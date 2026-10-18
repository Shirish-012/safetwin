"""The executor (docs/internals.md): runs pipelines in stage workers, one process per running stage.

Nothing is imported here. The modules, all light enough for the control plane except ``worker``:

- ``settings``: the limits (concurrent workers, the warm worker, the grace period of a cancel), in one place.
- ``protocol``: the messages between the control plane and a stage worker (versioned, JSON, one per line).
- ``tmp``: the private temporary folder of each worker, and the cleanup of the ones a crash left behind.
- ``process``: a stage worker as the control plane sees it (the child process, its pipes and its folder).
- ``store``: the state of the runs, behind a small interface (``RunStore``; ``MemoryRunStore`` in memory).
- ``history``: ``DbRunStore``, the engine's ``RunStore``: the history of the runs in the metadata database.
- ``executor``: ``Executor``, the queue of runs, the workers that run their stages and their events.
- ``worker``: the stage worker itself (``python -m safetwin.executor.worker``). It is the only module here
  that loads Polars, PyArrow and DuckDB, and only the worker process imports it.
"""
