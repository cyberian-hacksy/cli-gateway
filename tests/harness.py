"""Test harness: run ASGI apps as real HTTP servers on loopback.

Streaming, backpressure and client disconnects only behave realistically over sockets,
so the bridge tests use real servers in background threads, not an in-process transport.
"""
import threading
import time

import uvicorn


class ServerThread:
    def __init__(self, app):
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error",
                                lifespan="on", timeout_graceful_shutdown=1)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self.url = None

    def __enter__(self):
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError("server did not start")
            time.sleep(0.01)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        self.url = "http://127.0.0.1:%d" % port
        return self

    def __exit__(self, *exc_info):
        self._server.should_exit = True
        self._thread.join(timeout=10)


def wait_until(predicate, timeout=5.0, interval=0.01):
    """Poll until predicate() is truthy; return the elapsed seconds or fail."""
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if predicate():
            return time.monotonic() - started
        time.sleep(interval)
    raise AssertionError("condition not met within %.1fs" % timeout)
