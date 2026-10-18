"""The messages between the control plane and a stage worker.

Each message is one JSON object on one line (UTF-8, ended by a newline): the control plane writes jobs to the
worker's stdin, and the worker writes what happens to its stdout. Both sides check every message with the
pydantic models below, which allow no extra field. Every message carries the version of the protocol, `v`
(`PROTOCOL_VERSION`); a message of another version is refused, like any message that does not fit.

No data ever crosses the pipe: only jobs (the pipeline text, the folders of its sockets, ids and limits),
progress (counts, bytes, memory), results (paths, sizes, SHA-256 and row counts) and safe errors. An error is
its class name, and a message only for the classes whose messages the engine writes itself and never quote
data (`SAFE_MESSAGE_CLASSES`); the control plane drops the message of any other class.

The life of a worker:

    worker:  ready
    control: plan          worker: plan_done | failed       (any number of times)
    control: stage         worker: progress* then stage_done | failed, and the worker ends
    control: (stdin closed)                                  the worker ends

A worker runs one stage at most and then ends, so a stage never finds the temporary files or the memory of
another one. SIGINT cancels what it is doing (it ends with status 130). Standard library and pydantic only.
"""

from datetime import datetime
from typing import Annotated, Final, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter

PROTOCOL_VERSION: Final = 1

DataPath = Literal["fused", "batch", "hybrid"]

# The errors whose message the engine writes itself, naming nodes, paths, settings and limits but never a
# value of the data (an OSError's is the reason of the system and the file: the worker builds it so).
SAFE_MESSAGE_CLASSES: Final = frozenset(
    {
        "ConfigError",
        "Unsupported",
        "SpillError",
        "OutOfMemory",
        "MemoryLimitReached",
        "PipelineInvalid",
        "OSError",
        "FileExistsError",
        "FileNotFoundError",
        "PermissionError",
        "IsADirectoryError",
        "NotADirectoryError",
    }
)
MAX_ERROR_MESSAGE: Final = 2000


class ProtocolError(Exception):
    """A message that does not fit the protocol. The message says so, without repeating what was sent."""


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    v: Literal[1] = PROTOCOL_VERSION


Count = Annotated[int, Field(ge=0)]


class FileOut(_Message):
    """A committed file: its path, size and SHA-256."""

    path: str
    bytes: Count
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


# --- the control plane to the worker ------------------------------------------------------------------------


class _Job(_Message):
    job_id: str
    pipeline_yaml: str
    sockets: dict[str, str]  # alias or socket URI -> absolute folder
    run_id: str
    started_at: AwareDatetime  # the start of the run: every stage must fill the placeholders with it
    path: DataPath | None = None  # run every stage this way
    memory_limit_bytes: Annotated[int, Field(ge=1)]  # the share of the stage


class PlanJob(_Job):
    """Validate the pipeline and plan every stage of the run. Nothing is written."""

    type: Literal["plan"] = "plan"


class StageJob(_Job):
    """Run one stage. `committed` holds what the sinks of the earlier stages wrote, by node id."""

    type: Literal["stage"] = "stage"
    stage_index: Count
    committed: dict[str, list[FileOut]] = Field(default_factory=dict)


Job = Annotated[PlanJob | StageJob, Field(discriminator="type")]


# --- the worker to the control plane ------------------------------------------------------------------------


class Ready(_Message):
    """The worker has imported its libraries and waits for a job."""

    type: Literal["ready"] = "ready"
    pid: int
    import_s: float


class SinkOut(_Message):
    """Where the sink of a stage writes: what the control plane needs to clean up after a failed stage."""

    file: str
    dataset_dir: str
    relative: str


class PlannedStageOut(_Message):
    index: Count
    node_ids: list[str]
    operators: list[str]
    path: DataPath
    input_from: str | None
    sink: SinkOut


class PlanDone(_Message):
    type: Literal["plan_done"] = "plan_done"
    job_id: str
    pipeline: str  # metadata.name
    stages: list[PlannedStageOut]


class Progress(_Message):
    """How far a stage has got (at most four a second)."""

    type: Literal["progress"] = "progress"
    job_id: str
    stage: Count
    path: DataPath
    rows_per_node: dict[str, Count]
    bytes_written: Count
    memory_bytes: Count | None
    elapsed_s: float


class StageDone(_Message):
    """The stage is done: what it committed, and its manifest (with its size and SHA-256, for the history)."""

    type: Literal["stage_done"] = "stage_done"
    job_id: str
    rows_per_node: dict[str, Count]
    files: list[FileOut]
    duration_s: float
    path: DataPath
    manifest: str
    manifest_bytes: Count | None = None
    manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None


class Failed(_Message):
    """The job failed. `message` is set only for an error class in `SAFE_MESSAGE_CLASSES`."""

    type: Literal["failed"] = "failed"
    job_id: str
    error_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")]
    message: Annotated[str, Field(max_length=MAX_ERROR_MESSAGE)] | None = None


WorkerMessage = Annotated[Ready | PlanDone | Progress | StageDone | Failed, Field(discriminator="type")]

_JOB: Final[TypeAdapter[PlanJob | StageJob]] = TypeAdapter(Job)
_WORKER_MESSAGE: Final[TypeAdapter[Ready | PlanDone | Progress | StageDone | Failed]] = TypeAdapter(
    WorkerMessage
)


def encode(message: _Message) -> bytes:
    """One message as a line of JSON."""
    return message.model_dump_json().encode("utf-8") + b"\n"


def decode_job(line: bytes) -> PlanJob | StageJob:
    """A job from the control plane. Raises `ProtocolError`."""
    try:
        return _JOB.validate_json(line)
    except ValueError:  # pydantic's message repeats the input
        raise ProtocolError("a job that does not fit the protocol") from None


def decode_worker_message(line: bytes) -> Ready | PlanDone | Progress | StageDone | Failed:
    """A message from a worker. Raises `ProtocolError`. The message of an error class that is not safe is
    dropped here, whatever the worker sent."""
    try:
        message = _WORKER_MESSAGE.validate_json(line)
    except ValueError:
        raise ProtocolError("a message from a worker that does not fit the protocol") from None
    if isinstance(message, Failed) and message.message is not None and not safe_class(message.error_class):
        return message.model_copy(update={"message": None})
    return message


def safe_class(error_class: str) -> bool:
    """Whether the engine's message for an error of this class may be shown."""
    return error_class in SAFE_MESSAGE_CLASSES


def utc_iso(moment: datetime) -> str:
    """`moment` as `2026-10-02T09:30:00.123Z`."""
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
