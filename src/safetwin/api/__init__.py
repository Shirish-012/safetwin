"""The engine's local control API (docs/internals.md): a FastAPI app on 127.0.0.1, its connection file and
the engine process.

Nothing is imported here, so that the `safetwin` command can read the connection file and call the engine
(``connection`` and ``client``, standard library only) without loading FastAPI. The modules:

- ``settings``: the limits and the allowed app origins, in one place.
- ``connection``: the connection file (``$SAFETWIN_HOME/engine.json``) and the lock that keeps one engine
  running.
- ``client``: a small HTTP client of the API (``http.client``), for the CLI and the single-instance check.
- ``events``: the envelope of the events on the WebSocket, and the hub that sends them to every client.
- ``app``: ``create_app``, the app with its security checks.
- ``server``: ``run_engine``, which binds the socket, writes the connection file and serves with uvicorn.
"""
