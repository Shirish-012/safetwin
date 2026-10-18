// safetwin ui: the page's behaviour. Every name from a file is put in the page with textContent, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") { if (v) node.className = v; }
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

function size(bytes) {
  const units = ["bytes", "KB", "MB", "GB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${i ? bytes.toFixed(1) : bytes} ${units[i]}`;
}

const n = (x) => Number(x).toLocaleString("en-US");

async function api(method, path, body, raw) {
  const options = { method, headers: { "X-Safetwin": "1" }, credentials: "same-origin" };
  if (raw !== undefined) options.body = raw;
  else if (body !== undefined) {
    options.body = JSON.stringify(body);
    options.headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) throw new Error(data.error || data.detail || `the server answered ${response.status}`);
  return data;
}

function banner(message, kind = "error") {
  const b = $("banner");
  if (!message) { b.hidden = true; return; }
  b.className = kind === "error" ? "banner" : "banner info";
  b.textContent = message;
  b.hidden = false;
  b.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function busy(button, label) {
  const old = button.textContent;
  button.disabled = true;
  button.replaceChildren(el("span", { class: "spinner" }), ` ${label}`);
  return () => { button.textContent = old; button.disabled = false; };
}

// --- tabs ------------------------------------------------------------------------------------------------

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tab")) t.setAttribute("aria-selected", String(t === tab));
    for (const name of ["mask", "unmask", "history", "key"]) $(`tab-${name}`).hidden = name !== tab.dataset.tab;
    banner(null);
    if (tab.dataset.tab === "history") loadHistory();
  });
}

// --- a job: files in, on the server ------------------------------------------------------------------------

// A PUT with upload progress (fetch can't report it): resolves with the JSON answer.
function upload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", path);
    xhr.setRequestHeader("X-Safetwin", "1");
    xhr.upload.addEventListener("progress", (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); });
    xhr.addEventListener("load", () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new Error(data.error || data.detail || `the server answered ${xhr.status}`));
    });
    xhr.addEventListener("error", () => reject(new Error("the upload stopped")));
    xhr.send(file);
  });
}

class Job {
  constructor(listId, onChange) {
    this.id = null;
    this.files = new Map(); // name -> { bytes, sent: 0..1, done }
    this.list = $(listId);
    this.onChange = onChange;
  }

  async ensure() {
    if (!this.id) this.id = (await api("POST", "/api/jobs")).id;
    return this.id;
  }

  async add(fileList) {
    banner(null);
    for (const file of fileList) {
      if (!/\.(csv|parquet|xlsx)$/i.test(file.name) && file.name.toLowerCase() !== "report.json") {
        banner(`${file.name} is not a CSV, Parquet or Excel (.xlsx) file`);
        continue;
      }
      const id = await this.ensure();
      const entry = { bytes: file.size, sent: 0, done: false };
      this.files.set(file.name, entry);
      this.render();
      try {
        await upload(`/api/jobs/${id}/files/${encodeURIComponent(file.name)}`, file, (sent) => {
          entry.sent = sent;
          this.render();
        });
        entry.done = true;
      } catch (err) {
        this.files.delete(file.name);
        banner(`${file.name}: ${err.message}`);
      }
      this.render();
    }
    this.onChange();
  }

  async remove(name) {
    await api("DELETE", `/api/jobs/${this.id}/files/${encodeURIComponent(name)}`);
    this.files.delete(name);
    this.render();
    this.onChange();
  }

  async clear() {
    if (this.id) await api("DELETE", `/api/jobs/${this.id}`).catch(() => {});
    this.id = null;
    this.files.clear();
    this.render();
    this.onChange();
  }

  get ready() { return this.files.size > 0 && [...this.files.values()].every((f) => f.done); }

  render() {
    this.list.replaceChildren(...[...this.files].map(([name, f]) => el("li", {},
      el("span", { class: "name", text: name }),
      f.done
        ? el("span", {},
          el("span", { class: "muted", text: size(f.bytes) }),
          el("button", { class: "link", title: `Remove ${name}`, "aria-label": `Remove ${name}`, text: "✕",
            onclick: () => this.remove(name).catch((e) => banner(e.message)) }))
        : el("span", { class: "row tight" },
          el("progress", { max: "1", value: String(f.sent), "aria-label": `Uploading ${name}` }),
          el("span", { class: "muted", text: `${Math.round(f.sent * 100)}% of ${size(f.bytes)}` })))));
  }
}

function dropZone(zoneId, inputId, job) {
  const zone = $(zoneId);
  $(inputId).addEventListener("change", (e) => { job.add([...e.target.files]); e.target.value = ""; });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    job.add([...e.dataTransfer.files]);
  });
}

// --- mask ------------------------------------------------------------------------------------------------

let plan = null;
const choices = {}; // table -> "reversible" | "one-way"
const cipherOf = {}; // table -> how a reversible file encrypts: "auto" | "siv" | "gcm"
const picked = {}; // table -> column -> option id

const maskJob = new Job("mask-files", () => {
  $("scan-btn").disabled = !maskJob.ready;
  plan = null;
  $("plan-step").hidden = true;
  $("result-step").hidden = true;
});
dropZone("mask-drop", "mask-input", maskJob);

$("scan-btn").addEventListener("click", async () => {
  const done = busy($("scan-btn"), "Scanning…");
  banner(null);
  try {
    plan = await api("POST", `/api/jobs/${maskJob.id}/scan`);
    for (const k of Object.keys(choices)) delete choices[k];
    for (const k of Object.keys(picked)) delete picked[k];
    for (const t of plan.tables) picked[t.name] = Object.fromEntries(t.columns.map((c) => [c.name, c.default]));
    $("preview").hidden = true;
    renderPlan();
    $("plan-step").hidden = false;
    $("result-step").hidden = true;
    $("plan-step").scrollIntoView({ behavior: "smooth" });
  } catch (err) { banner(err.message); }
  done();
});

// What will happen to every column, as the server will do it: a reversible file's columns take its reversible
// methods (encrypted in one of three ways, kept, emptied or removed), a one-way file's the one-way ones. A
// linked column that is encrypted but joins a one-way column takes that column's method (`scan.make_reversible`),
// so the files still join and the one-way file holds nothing reversible. Linked columns must both be masked or
// both be kept: `conflicts` lists the links that aren't.
function optionsFor(t, c) { return choices[t.name] === "reversible" ? c.rev_options : c.options; }

function defaultsFor(t) {
  const rev = choices[t.name] === "reversible";
  return Object.fromEntries(t.columns.map((c) => [c.name, rev ? c.rev_default : c.default]));
}

function outcomes() {
  const out = {};
  for (const t of plan.tables) {
    out[t.name] = {};
    for (const c of t.columns) {
      const id = picked[t.name][c.name];
      const label = (optionsFor(t, c).find((o) => o.id === id) || { label: id }).label;
      const removing = id === "drop" || id === "null";
      if (id === "keep") out[t.name][c.name] = { kind: "keep", label };
      else if (choices[t.name] === "one-way" || (choices[t.name] && removing)) out[t.name][c.name] = { kind: "one", label };
      else if (choices[t.name] === "reversible") out[t.name][c.name] = { kind: "rev", label };
      else out[t.name][c.name] = { kind: "open", label: removing ? label : `one-way: ${label} · reversible: encrypted` };
    }
  }
  const sides = plan.relationships.map((r) => r.split("->").map((s) => {
    const side = s.trim();
    const dot = side.indexOf(".");
    return [side.slice(0, dot), side.slice(dot + 1)];
  }));
  const conflicts = [];
  for (const [[ta, ca], [tb, cb]] of sides) {
    const a = out[ta]?.[ca], b = out[tb]?.[cb];
    if (a && b && (a.kind === "keep") !== (b.kind === "keep")) {
      conflicts.push(`${ta}.${ca} and ${tb}.${cb}`);
      a.conflict = b.conflict = true;
    }
  }
  for (let changed = !conflicts.length; changed;) {
    changed = false;
    for (const [[ta, ca], [tb, cb]] of sides) {
      for (const [[t1, c1], [t2, c2]] of [[[ta, ca], [tb, cb]], [[tb, cb], [ta, ca]]]) {
        const mine = out[t1]?.[c1], theirs = out[t2]?.[c2];
        if (mine && theirs && mine.kind === "rev" && theirs.kind === "one") {
          out[t1][c1] = { kind: theirs.kind, label: theirs.label, linked: `${t2}.${c2}` };
          changed = true;
        }
      }
    }
  }
  return { out, conflicts };
}

function whatHappens(o) {
  if (o.kind === "open") return el("span", { class: "muted", text: o.label });
  const cls = { keep: "pill", rev: "pill rev", one: "pill one" }[o.kind];
  const suffix = { keep: "", rev: " · reversible", one: " · one-way" }[o.kind];
  const pill = el("span", { class: cls, text: o.label + suffix });
  if (o.conflict) {
    return el("span", {}, pill, el("br"), el("span", { class: "conflict", text: "linked: mask both sides or keep both" }));
  }
  if (!o.linked) return pill;
  return el("span", {}, pill, el("br"), el("span", { class: "muted", text: `linked to ${o.linked}, which is one-way` }));
}

// One choice for a whole reversible file, so no one has to set every column: "auto" (phone and card numbers
// keep their format with FF1, the rest is standard), "siv" (standard everywhere) or "gcm" (random wherever a
// column doesn't link files). Kept columns stay kept; any column can still be changed on its own.
function encryptWith(t) {
  const pick = el("select", { "aria-label": `Encrypt ${t.file} with` },
    el("option", { value: "auto", text: "Recommended: phone and card numbers keep their format" }),
    el("option", { value: "siv", text: "Standard everywhere (AES-SIV)" }),
    el("option", { value: "gcm", text: "Random where possible: hides repeats (AES-GCM)" }));
  pick.value = cipherOf[t.name] || "auto";
  pick.addEventListener("change", () => {
    cipherOf[t.name] = pick.value;
    picked[t.name] = Object.fromEntries(t.columns.map((c) => {
      const has = (id) => c.rev_options.some((o) => o.id === id);
      if (c.rev_default === "keep" || pick.value === "auto") return [c.name, c.rev_default];
      if (pick.value === "gcm" && has("gcm")) return [c.name, "gcm"];
      return [c.name, has("siv") ? "siv" : c.rev_default];
    }));
    $("preview").hidden = true;
    renderPlan();
  });
  return el("div", { class: "encrypt-with" }, el("span", { class: "muted", text: "Encrypt with" }), pick);
}

function renderPlan() {
  const { out: will, conflicts } = outcomes();
  const cards = plan.tables.map((t) => {
    const mode = el("div", { class: "mode", role: "radiogroup", "aria-label": `How to mask ${t.file}` },
      ...[["reversible", "Reversible", "people with the access key can read it back", "on-rev"],
          ["one-way", "One-way", "no one can read it back", "on-one"]].map(([value, title, hint, on]) => {
        const input = el("input", { type: "radio", name: `mode-${t.name}`, value });
        input.checked = choices[t.name] === value;
        input.addEventListener("change", () => {
          choices[t.name] = value;
          cipherOf[t.name] = "auto";
          picked[t.name] = defaultsFor(t);  // each kind of file has its own methods
          $("preview").hidden = true;
          renderPlan();
        });
        return el("label", { class: choices[t.name] === value ? on : "" }, input,
          el("span", {}, el("b", { text: title }), el("br"), el("span", { class: "muted", text: hint })));
      }));
    const rows = t.columns.map((c) => {
      const pick = el("select", { "aria-label": `Method for ${c.name}` },
        ...optionsFor(t, c).map((o) => el("option", { value: o.id, text: o.suggested ? `${o.label} (suggested)` : o.label })));
      pick.value = picked[t.name][c.name];
      pick.addEventListener("change", () => { picked[t.name][c.name] = pick.value; $("preview").hidden = true; renderPlan(); });
      return el("tr", { class: picked[t.name][c.name] === "keep" ? "dim" : "" },
        el("td", {}, el("b", { text: c.name }), el("br"), el("span", { class: "muted", text: c.type })),
        el("td", {}, pick, el("div", { class: "narrow-only" }, whatHappens(will[t.name][c.name]))),
        el("td", { class: "wide-only" }, whatHappens(will[t.name][c.name])),
        el("td", { class: "muted why", text: c.reasons.join("; ") }));
    });
    const table = el("table", {},
      el("thead", {}, el("tr", {}, ...["Column", "Method", "What happens", "Why"]
        .map((h) => el("th", { text: h, class: { Why: "why", "What happens": "wide-only" }[h] })))),
      el("tbody", {}, ...rows));
    return el("div", { class: "table-card" },
      el("div", { class: "table-head" },
        el("div", {}, el("div", { class: "title", text: t.file }),
          el("div", { class: "muted", text: `${n(t.rows)} rows · ${t.columns.length} columns` })),
        mode),
      choices[t.name] === "reversible" ? encryptWith(t) : null,
      el("div", { class: "scroll" }, table));
  });
  const notes = plan.relationships.length
    ? el("p", { class: "muted", text: `Linked columns: ${plan.relationships.join(", ")}. A link between a reversible ` +
        "and a one-way file stays one-way on both sides, so the files still join." })
    : null;
  $("plan").replaceChildren(...cards, notes ?? "");
  const all = plan.tables.every((t) => choices[t.name]);
  $("mask-btn").disabled = $("preview-btn").disabled = !all || conflicts.length > 0;
  $("mask-hint").textContent = conflicts.length
    ? `Linked columns ${conflicts.join(", ")}: mask both sides or keep both.`
    : all ? "" : "Choose reversible or one-way for every file.";
}

function body() {
  return { choices, picked, format: $("out-format").value || null };
}

$("preview-btn").addEventListener("click", async () => {
  const done = busy($("preview-btn"), "Previewing…");
  banner(null);
  try {
    const r = await api("POST", `/api/jobs/${maskJob.id}/preview`, body());
    const parts = [el("p", { class: "muted", text: `The first ${r.rows} rows of each file, as they will be masked. ` +
      "Removed columns aren't shown." })];
    for (const t of r.tables) {
      parts.push(el("h3", { text: t.name }), el("div", { class: "scroll" }, el("table", { class: "sample" },
        el("thead", {}, el("tr", {}, ...t.columns.map((c) => el("th", { text: c })))),
        el("tbody", {}, ...t.rows.map((row) => el("tr", {}, ...row.map((v) =>
          v === null ? el("td", { class: "null", text: "empty" }) : el("td", { text: v }))))))));
    }
    $("preview").replaceChildren(...parts);
    $("preview").hidden = false;
    $("preview").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (err) { banner(err.message); }
  done();
});

// The progress bar: a row of pills, filled up to the share done, the last one lit.
const SEGMENTS = 28;
function setBar(share) {
  const bar = $("mask-bar");
  if (bar.children.length !== SEGMENTS) bar.replaceChildren(...Array.from({ length: SEGMENTS }, () => el("i")));
  const lit = Math.round(Math.max(0, Math.min(1, share)) * SEGMENTS);
  [...bar.children].forEach((pill, i) => {
    pill.className = i < lit - 1 ? "on" : i === lit - 1 ? "now" : "";
  });
  bar.setAttribute("aria-valuenow", String(Math.round(share * 100)));
}

function showProgress(p) {
  if (!p || p.phase === "idle" || p.phase === "done") return;
  const share = p.total ? p.rows / p.total : 0;
  setBar(p.phase === "checking" ? 1 : share);
  $("mask-progress-text").textContent = p.phase === "starting" ? "Reading the files…"
    : p.phase === "checking" ? "Checking the masked files and writing the report…"
      : `${n(p.rows)} of ${n(p.total)} rows masked (${Math.round(share * 100)}%)`;
}

$("mask-btn").addEventListener("click", async () => {
  const done = busy($("mask-btn"), "Masking…");
  $("preview-btn").disabled = true;
  banner(null);
  setBar(0);
  $("mask-progress-text").textContent = "Starting…";
  $("mask-progress").hidden = false;
  const id = maskJob.id;
  const timer = setInterval(() => api("GET", `/api/jobs/${id}/progress`).then(showProgress).catch(() => {}), 500);
  try {
    renderResult(await api("POST", `/api/jobs/${id}/mask`, body()));
  } catch (err) { banner(err.message); }
  clearInterval(timer);
  $("mask-progress").hidden = true;
  done();
  $("preview-btn").disabled = $("mask-btn").disabled;
});

function stat(value, label, tone = "") {
  return el("div", { class: `stat ${tone}` }, el("b", { text: value }), el("span", { text: label }));
}

function renderResult(r) {
  const tables = Object.entries(r.tables);
  const rowsIn = tables.reduce((a, [, t]) => a + t.rows_in, 0);
  const rowsOut = tables.reduce((a, [, t]) => a + t.rows_out, 0);
  const classes = Object.values(r.classes).flatMap((c) => Object.values(c));
  const enc = classes.filter((c) => c === "encrypted").length;
  const oneWay = classes.filter((c) => c !== "encrypted" && c !== "kept").length;
  const parts = [
    el("p", {}, el("span", { class: r.ok ? "pill ok" : "pill bad", text: r.ok ? "done" : "failed" }), " ",
      r.ok ? "Your masked files are ready." : (r.error || "A check failed, so no masked files were kept.")),
    el("div", { class: "stats" },
      stat(`${n(rowsIn)} → ${n(rowsOut)}`, "rows in → out"),
      stat(n(enc), "columns encrypted (reversible)"),
      stat(n(oneWay), "columns masked one-way"),
      stat(n(r.orphans), "broken links between files", r.orphans ? "bad" : "good"),
      stat(n(r.findings), "personal data left (residual scan)", r.findings ? "bad" : "good")),
  ];
  if (r.warnings.length) {
    parts.push(el("div", { class: "note warn" }, el("b", { text: "Warnings" }),
      el("ul", {}, ...r.warnings.map((w) => el("li", { text: w })))));
  }
  $("result").replaceChildren(...parts);
  lastResult = r;
  $("save-panel").hidden = true;
  $("save-btn").hidden = !r.ok;
  $("download-masked").hidden = !r.ok;
  $("download-masked").href = `/api/jobs/${maskJob.id}/download/masked.zip`;
  $("open-report").href = `/api/jobs/${maskJob.id}/report`;
  $("report-frame").src = `/api/jobs/${maskJob.id}/report?t=${Date.now()}`;
  $("result-step").hidden = false;
  $("result-step").scrollIntoView({ behavior: "smooth" });
}

$("restart-btn").addEventListener("click", () => maskJob.clear().then(() => { $("report-frame").src = "about:blank"; }));

// --- save to a folder: a synced cloud folder (Google Drive, Dropbox, OneDrive, iCloud) or any other ---------

let lastResult = null;

$("save-btn").addEventListener("click", async () => {
  const panel = $("save-panel");
  panel.hidden = !panel.hidden;
  if (panel.hidden) return;
  $("save-note").textContent = "";
  const encrypted = lastResult && Object.values(lastResult.classes).some((c) => Object.values(c).includes("encrypted"));
  const parts = [];
  if (encrypted) {
    parts.push(el("div", { class: "note warn", text: "These files have reversible columns: anyone with the access key " +
      "can read them. Save them only where the people who see the folder may see the real values." }));
  }
  try {
    const { folders } = await api("GET", "/api/folders");
    if (folders.length) {
      parts.push(el("div", { class: "folders" }, ...folders.map((f) => el("button", {
        type: "button", class: "folder", title: f.path,
        onclick: () => { $("save-path").value = f.path; $("save-path").focus(); },
      }, el("b", { text: f.name }), el("span", { class: "muted", text: f.path })))));
      $("save-path").value = folders[0].path;
    } else {
      const drive = el("a", { href: "https://drive.google.com/drive/my-drive", target: "_blank", rel: "noopener noreferrer", text: "drive.google.com" });
      const app = el("a", { href: "https://www.google.com/drive/download/", target: "_blank", rel: "noopener noreferrer", text: "Google Drive for desktop" });
      parts.push(el("div", { class: "note" }, el("b", { text: "No synced cloud folder was found on this computer. " }),
        "Download the zip above and drag it into ", drive, " (or Dropbox, OneDrive, iCloud on the web). Or install ",
        app, ", then save here straight into it."));
    }
  } catch (err) { banner(err.message); }
  $("save-folders").replaceChildren(...parts);
});

$("save-go").addEventListener("click", async () => {
  const done = busy($("save-go"), "Saving…");
  try {
    const r = await api("POST", `/api/jobs/${maskJob.id}/save`, { folder: $("save-path").value });
    $("save-note").textContent = `Saved as ${r.saved}. The sync app uploads it from there.`;
  } catch (err) { $("save-note").textContent = ""; banner(err.message); }
  done();
});

// --- unmask ----------------------------------------------------------------------------------------------

const unmaskJob = new Job("unmask-files", () => {
  updateUnmask();
  $("unmask-result-step").hidden = true;
});
dropZone("unmask-drop", "unmask-input", unmaskJob);

function keySource() { return document.querySelector("input[name=keysrc]:checked").value; }

function updateUnmask() {
  const given = keySource() === "given";
  $("given-key").hidden = !given;
  const keyOk = !given || /^[0-9a-fA-F]{64}$/.test($("access-input").value.trim());
  $("unmask-btn").disabled = !(unmaskJob.ready && keyOk);
}
for (const radio of document.querySelectorAll("input[name=keysrc]")) radio.addEventListener("change", updateUnmask);
$("access-input").addEventListener("input", updateUnmask);
$("access-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (file) $("access-input").value = (await file.text()).trim().slice(0, 200);
  e.target.value = "";
  updateUnmask();
});

// What unmask found for each column: the value's prefix tells AES-SIV (st1.) from AES-GCM (sg1.), and the
// report.json names the FF1 columns. Nothing to choose by hand.
const CIPHERS = {
  "aes-siv": { short: "standard (AES-SIV)", long: "AES-256-SIV: equal values stay equal" },
  "aes-gcm": { short: "random (AES-GCM)", long: "AES-256-GCM: a fresh nonce per value" },
  "ff1": { short: "kept its format (FF1)", long: "FF1 format-preserving encryption (NIST SP 800-38G)" },
};

$("unmask-btn").addEventListener("click", async () => {
  const done = busy($("unmask-btn"), "Unmasking…");
  banner(null);
  try {
    const body = keySource() === "given" ? { access_key: $("access-input").value.trim() } : {};
    const r = await api("POST", `/api/jobs/${unmaskJob.id}/unmask`, body);
    const rows = r.tables.map((t) => el("tr", {},
      el("td", {}, el("b", { text: t.name })),
      el("td", { text: n(t.rows) }),
      el("td", {}, t.decrypted.length
        ? el("div", { class: "found" }, ...t.decrypted.map((d) => el("span", { class: "pill rev", title: CIPHERS[d.algorithm].long,
          text: `${d.column} · ${CIPHERS[d.algorithm].short}` })))
        : el("span", { class: "pill", text: "none" })),
      el("td", { class: "muted", text: t.copied.length ? `${t.copied.length} as they were (kept, or one-way)` : "—" })));
    const none = r.tables.every((t) => !t.decrypted.length);
    $("unmask-result").replaceChildren(
      none ? el("div", { class: "note warn", text: "No encrypted column was found, so nothing was read back. If the files " +
        "were masked to keep their format, add the report.json from the same zip. Files masked one-way can't " +
        "be read back." }) : "",
      el("div", { class: "scroll" }, el("table", {},
        el("thead", {}, el("tr", {}, ...["File", "Rows", "Columns read back", "Other columns"].map((h) => el("th", { text: h })))),
        el("tbody", {}, ...rows))),
      el("p", { class: "muted", text: `Access key fingerprint ${r.fingerprint}` }));
    $("download-readable").href = `/api/jobs/${unmaskJob.id}/download/readable.zip`;
    $("unmask-result-step").hidden = false;
  } catch (err) { banner(err.message); }
  done();
});

$("unmask-restart").addEventListener("click", () => unmaskJob.clear());

// --- history ---------------------------------------------------------------------------------------------

function when(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

async function loadHistory() {
  try {
    const { runs } = await api("GET", "/api/history");
    if (!runs.length) {
      $("history").replaceChildren(el("p", { class: "muted", text: "No runs yet. Reports appear here after you mask files." }));
      return;
    }
    const rows = runs.map((r) => {
      const tables = Object.values(r.tables);
      const rows = tables.reduce((a, t) => a + (t.rows_out || 0), 0);
      const modes = Object.entries(r.choices).map(([t, c]) => `${t}: ${c}`).join(", ");
      return el("tr", {},
        el("td", { text: when(r.when) }),
        el("td", {}, ...r.files.flatMap((f, i) => [i ? el("br") : null, el("span", { class: "name", text: f })])),
        el("td", { text: n(rows) }),
        el("td", { class: "muted why", text: modes }),
        el("td", {}, el("span", { class: r.ok ? "pill ok" : "pill bad", text: r.ok ? "done" : "failed" })),
        el("td", {},
          el("a", { class: "button small", href: `/api/history/${r.id}/report`, target: "_blank", rel: "noopener", text: "Report" }),
          " ",
          el("button", { class: "link", text: "Delete", "aria-label": `Delete the run of ${when(r.when)}`,
            onclick: () => api("DELETE", `/api/history/${r.id}`).then(loadHistory).catch((e) => banner(e.message)) })));
    });
    $("history").replaceChildren(el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ...["When", "Files", "Rows", "Mode", "Status", ""]
        .map((h) => el("th", { text: h, class: h === "Mode" ? "why" : null })))),
      el("tbody", {}, ...rows))));
  } catch (err) { banner(err.message); }
}

// --- start -----------------------------------------------------------------------------------------------

// --- keys: the masking key in use, and how to change it --------------------------------------------------

function showKey(k) {
  $("key-label").textContent = k.label;
  $("key-fp").textContent = k.fingerprint;
  $("access-fp").textContent = k.access_fingerprint;
  $("mask-key-label").textContent = k.label;
  $("mask-key-fp").textContent = k.fingerprint;
  $("mine-fp").textContent = `(${k.label}: access key ${k.access_fingerprint})`;
  for (const radio of document.querySelectorAll("input[name=keymode]")) radio.checked = radio.value === k.source;
  showKeyPanel(k.source);
}

function showKeyPanel(mode) {
  for (const panel of document.querySelectorAll(".keypanel")) panel.hidden = panel.dataset.mode !== mode;
  for (const label of document.querySelectorAll(".keymodes label")) {
    label.classList.toggle("on-rev", label.querySelector("input").value === mode);
  }
}

for (const radio of document.querySelectorAll("input[name=keymode]")) {
  radio.addEventListener("change", () => { showKeyPanel(radio.value); $("new-key").hidden = true; });
}

$("change-key").addEventListener("click", () => document.querySelector(".tab[data-tab=key]").click());

$("own-key-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (file) $("own-key").value = (await file.text()).trim().slice(0, 200);
  e.target.value = "";
});

for (const button of document.querySelectorAll("[data-use]")) {
  button.addEventListener("click", async () => {
    const mode = button.dataset.use;
    let value;
    if (mode === "hex") value = $("own-key").value.trim();
    if (mode === "passphrase") {
      if ($("phrase").value !== $("phrase2").value) { banner("The two passphrases are not the same."); return; }
      value = $("phrase").value;
    }
    const done = busy(button, mode === "passphrase" ? "Making the key…" : "One moment…");
    banner(null);
    try {
      const k = await api("POST", "/api/key", { mode, value });
      showKey(k);
      if (mode === "generate") {
        $("new-key-hex").textContent = k.key;
        $("new-key").hidden = false;
      }
      if (mode === "passphrase") { $("phrase").value = ""; $("phrase2").value = ""; }
      if (mode === "hex") $("own-key").value = "";
      banner(`Now masking and unmasking with ${k.label} (fingerprint ${k.fingerprint}).`, "info");
    } catch (err) { banner(err.message); }
    done();
  });
}

$("new-key-save").addEventListener("click", () => {
  const blob = new Blob([`${$("new-key-hex").textContent}\n`], { type: "text/plain" });
  const link = el("a", { href: URL.createObjectURL(blob), download: "safetwin-masking-key.txt" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});

// --- start -----------------------------------------------------------------------------------------------

async function start() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (token) {
    history.replaceState(null, "", "/");
    try { await api("POST", "/api/login", { token }); } catch (err) { banner(err.message); return; }
  }
  try {
    const s = await api("GET", "/api/state");
    $("key-file").textContent = s.key_file;
    showKey(s.key);
  } catch (err) {
    banner(`${err.message}. Run  safetwin ui  in the terminal and use the address it prints.`);
  }
}
start();
