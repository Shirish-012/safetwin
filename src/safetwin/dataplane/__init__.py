"""The data plane: what runs a stage of a pipeline (docs/internals.md).

Nothing is imported here: the libraries that do the work (Polars, PyArrow, DuckDB) are heavy, and only a stage
worker or the `safetwin run-local` command needs them. Import the module you need, such as
``safetwin.dataplane.run`` (`run_pipeline_local`), ``safetwin.dataplane.writer`` (`CommitWriter`),
``safetwin.dataplane.spill`` (`open_duckdb`, where DuckDB spills) or ``safetwin.dataplane.manifest``.
"""
