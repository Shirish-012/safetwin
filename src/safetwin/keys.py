"""Masking keys: references, derivation and fingerprints (docs/security.md).

A key is 32 random bytes. A policy never holds it, only a reference to where it is:

- `env://NAME`: the environment variable NAME holds 64 hexadecimal characters;
- `file://PATH`: a regular file (`~` is expanded) owned by the user, with no permission bits for the group or
  others, that holds 64 hexadecimal characters and an optional newline;
- `keychain://...`: refused in M1 ("not supported yet").

Every use of the key gets its own subkey, `HKDF-SHA-256(key, salt=None, info="safetwin/v1/<method>/<domain>")`
(RFC 5869, implemented here with the standard library: pyca `cryptography` is not a dependency yet). Reports
and run history show only the fingerprint, `HMAC-SHA-256(key, "safetwin/v1/fingerprint")` cut to 8 bytes.

Nothing in this module ever puts the key, a subkey or the value of an environment variable into a message,
a repr or a file other than the key file that `new_key_file` writes. This module imports no data library.
"""

import hashlib
import hmac
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Final

KEY_BYTES: Final = 32
_HASH_LEN: Final = 32  # SHA-256
_HEX_KEY = re.compile(r"[0-9a-fA-F]{64}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FINGERPRINT_INFO: Final = b"safetwin/v1/fingerprint"
REFERENCE_SCHEMES: Final = ("env://", "file://", "keychain://")
PASSPHRASE_MIN: Final = 12  # characters
PASSPHRASE_SALT: Final = b"safetwin/v1/passphrase"
SCRYPT: Final = {"n": 2**17, "r": 8, "p": 1, "maxmem": 256 * 1024 * 1024}  # 128 MiB, about 0.3 s a guess


class KeyRefError(Exception):
    """A key reference that can't be used. The message names the reference, never the key or a value."""


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int = _HASH_LEN) -> bytes:
    """HKDF with SHA-256 (RFC 5869): extract with `salt` (HashLen zero bytes if None), then expand to
    `length` bytes with `info`."""
    if not 0 < length <= 255 * _HASH_LEN:
        raise ValueError("HKDF-SHA-256 can make 1 to 8160 bytes")
    prk = hmac.digest(salt if salt else bytes(_HASH_LEN), ikm, "sha256")
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.digest(prk, block + info + bytes([counter]), "sha256")
        okm += block
        counter += 1
    return okm[:length]


def subkey_info(method: str, domain: str) -> bytes:
    """The HKDF `info` of a subkey: `safetwin/v1/<method>/<domain>`."""
    return f"safetwin/v1/{method}/{domain}".encode()


class MasterKey:
    """A masking key in memory. Its repr shows the fingerprint only."""

    __slots__ = ("_raw", "fingerprint")

    def __init__(self, raw: bytes) -> None:
        if len(raw) != KEY_BYTES:
            raise KeyRefError("a key is 32 bytes (64 hexadecimal characters)")
        self._raw = raw
        self.fingerprint = fingerprint(raw)

    def subkey(self, method: str, domain: str) -> bytes:
        """The 32-byte subkey of one use of the key."""
        return hkdf_sha256(self._raw, None, subkey_info(method, domain))

    def access_key(self) -> bytes:
        """The access key (`portable.access_key`): it decrypts what `encrypt` masked, nothing more."""
        return self.subkey("access", "v1")

    def hex_for_key_file(self) -> str:
        """The key as hex: only for writing a new key file or `key new --print`."""
        return self._raw.hex()

    def as_access_key(self) -> bytes:
        """The 32 bytes themselves, when the reference holds an access key (`safetwin unmask --key`)."""
        return self._raw

    def __repr__(self) -> str:
        return f"MasterKey(fingerprint={self.fingerprint})"

    __str__ = __repr__


def fingerprint(raw: bytes) -> str:
    """`HMAC-SHA-256(key, "safetwin/v1/fingerprint")`, first 8 bytes, as 16 hex characters."""
    return hmac.digest(raw, FINGERPRINT_INFO, "sha256")[:8].hex()


def is_reference(value: str) -> bool:
    """Whether `value` has the shape of a key reference (it may still fail to resolve)."""
    return value.startswith(REFERENCE_SCHEMES) and len(value) > value.index("://") + 3


def _parse_hex(text: str, where: str) -> bytes:
    stripped = text.strip()
    if not _HEX_KEY.fullmatch(stripped):
        raise KeyRefError(f"{where} does not hold a key: it must be 64 hexadecimal characters (32 bytes)")
    return bytes.fromhex(stripped)


def resolve_key(reference: str, environ: Mapping[str, str] | None = None) -> MasterKey:
    """The key that `reference` points at. Raises `KeyRefError` with a message that is safe to show."""
    env = os.environ if environ is None else environ
    if reference.startswith("env://"):
        name = reference.removeprefix("env://")
        if not _ENV_NAME.fullmatch(name):
            raise KeyRefError("an env:// key reference names an environment variable: env://NAME")
        value = env.get(name)
        if value is None or value == "":
            raise KeyRefError(f"the environment variable {name} (key: env://{name}) is not set")
        return MasterKey(_parse_hex(value, f"the environment variable {name}"))
    if reference.startswith("file://"):
        return MasterKey(_read_key_file(Path(reference.removeprefix("file://")).expanduser()))
    if reference.startswith("keychain://"):
        raise KeyRefError("keychain:// keys are not supported yet: use env:// or file://")
    raise KeyRefError(
        "the key must be a reference: env://NAME, file://PATH or keychain://NAME, never the key"
    )


def resolve_secret(reference: str, what: str, environ: Mapping[str, str] | None = None) -> str:
    """The text that `reference` (`env://NAME` or `file://PATH`, with the key file's checks) points at, such
    as a database URL. `what` names it in messages, which never hold the text."""
    env = os.environ if environ is None else environ
    if reference.startswith("env://"):
        name = reference.removeprefix("env://")
        if not _ENV_NAME.fullmatch(name):
            raise KeyRefError(f"an env:// reference to the {what} names an environment variable: env://NAME")
        value = env.get(name, "").strip()
        if not value:
            raise KeyRefError(f"the environment variable {name} (the {what}: env://{name}) is not set")
        return value
    if reference.startswith("file://"):
        path = Path(reference.removeprefix("file://")).expanduser()
        text = _read_private_file(path, f"{what} file", 8192).decode("utf-8", errors="replace").strip()
        if not text:
            raise KeyRefError(f"the {what} file {path} is empty")
        return text
    raise KeyRefError(f"the {what} must be a reference, env://NAME or file://PATH, never the value itself")


def _read_private_file(path: Path, what: str, limit: int) -> bytes:
    """The first `limit` bytes of a regular file of this user that no one else can read or change."""
    if str(path) == "":
        raise KeyRefError(f"a file:// reference to the {what} needs a path: file://PATH")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as err:
        if err.errno is not None and os.path.islink(path):
            raise KeyRefError(f"the {what} {path} is a symbolic link: refer to the file itself") from None
        reason = os.strerror(err.errno) if err.errno else type(err).__name__
        raise KeyRefError(f"cannot open the {what} {path}: {reason}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise KeyRefError(f"the {what} {path} is not a regular file")
        if info.st_uid != os.getuid():
            raise KeyRefError(f"the {what} {path} belongs to another user")
        if info.st_mode & 0o077:
            raise KeyRefError(
                f"the {what} {path} can be read or changed by others "
                f"(mode {stat.S_IMODE(info.st_mode):04o}): run chmod 600 {path}"
            )
        return os.read(fd, limit)
    finally:
        os.close(fd)


def _read_key_file(path: Path) -> bytes:
    """The key in a key file, after the checks of the module docs."""
    if str(path) == "":
        raise KeyRefError("a file:// key reference needs a path: file://PATH")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as err:
        if err.errno is not None and os.path.islink(path):
            raise KeyRefError(f"the key file {path} is a symbolic link: refer to the file itself") from None
        reason = os.strerror(err.errno) if err.errno else type(err).__name__
        raise KeyRefError(f"cannot open the key file {path}: {reason}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise KeyRefError(f"the key file {path} is not a regular file")
        if info.st_uid != os.getuid():
            raise KeyRefError(f"the key file {path} belongs to another user")
        if info.st_mode & 0o077:
            raise KeyRefError(
                f"the key file {path} can be read or changed by others "
                f"(mode {stat.S_IMODE(info.st_mode):04o}): run chmod 600 {path}"
            )
        data = os.read(fd, 200)
    finally:
        os.close(fd)
    text = data.decode("ascii", errors="replace")
    body = text[:-1] if text.endswith("\n") else text
    if not _HEX_KEY.fullmatch(body):
        raise KeyRefError(
            f"the key file {path} does not hold a key: 64 hexadecimal characters and an optional newline"
        )
    return bytes.fromhex(body)


def new_key() -> MasterKey:
    """A new random key from the operating system's CSPRNG."""
    return MasterKey(secrets.token_bytes(KEY_BYTES))


def key_from_passphrase(passphrase: str) -> MasterKey:
    """The key of a passphrase: scrypt (N=2^17, r=8, p=1) of its UTF-8 bytes (NFKC-normalized) with the fixed
    salt `safetwin/v1/passphrase`, 32 bytes. The same passphrase gives the same key on every computer, so it
    can be typed again instead of copying a key file.

    The salt is fixed on purpose (so the key comes back), which means a guess costs an attacker the same for
    every safetwin user; scrypt makes each guess take about 0.3 s and 128 MiB. A random key file is stronger:
    use a long passphrase (several words). Raises `KeyRefError` (safe to show) below `PASSPHRASE_MIN`
    characters."""
    text = unicodedata.normalize("NFKC", passphrase)
    if len(text) < PASSPHRASE_MIN:
        raise KeyRefError(f"a passphrase has at least {PASSPHRASE_MIN} characters: several words are best")
    raw = hashlib.scrypt(text.encode("utf-8"), salt=PASSPHRASE_SALT, dklen=KEY_BYTES, **SCRYPT)
    return MasterKey(raw)


def new_key_file(path: Path) -> MasterKey:
    """Write a new key to `path` (mode 0600, created with O_EXCL: an existing file is never replaced).

    Missing parent folders are created with mode 0700. Raises `KeyRefError` (safe to show) if it can't.
    """
    key = new_key()
    write_key_file(path, key.hex_for_key_file())
    return key


def write_key_file(path: Path, hex_key: str) -> None:
    """Write 64 hexadecimal characters to the new file `path`, as `new_key_file` does (mode 0600, never
    replacing a file, missing folders 0700). Raises `KeyRefError` (safe to show) if it can't."""
    path = path.expanduser()
    try:
        missing = [p for p in (path.parent, *path.parent.parents) if not p.exists()]
        for folder in reversed(missing):  # each missing folder 0700, not only the last
            folder.mkdir(mode=0o700, exist_ok=True)
            os.chmod(folder, 0o700)  # whatever the umask was
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise KeyRefError(f"{path} exists already: a key file is never replaced") from None
    except OSError as err:
        reason = os.strerror(err.errno) if err.errno else type(err).__name__
        raise KeyRefError(f"cannot create the key file {path}: {reason}") from None
    try:
        os.fchmod(fd, 0o600)  # whatever the umask was
        os.write(fd, (hex_key + "\n").encode("ascii"))
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    os.close(fd)
