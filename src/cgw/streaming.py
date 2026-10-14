"""A streaming response that reacts to the client leaving and can abort without pretending.

A plain StreamingResponse only notices a vanished client when a write fails. During
upstream silence that could take a whole heartbeat interval, far longer than the
two-second cancellation target.
"""
import asyncio
import contextlib
import logging

from starlette.responses import StreamingResponse

log = logging.getLogger("cgw.stream")


class WatchedStreamingResponse(StreamingResponse):
    """Stops the stream when the client disconnects, and always calls `on_close`.

    If the body iterator raises one of `abort_on`, the response is left incomplete on
    purpose: the server then drops the connection, so the client sees a broken stream
    and never a clean end that did not happen.
    """

    def __init__(self, content, on_close=None, abort_on=(), **kwargs):
        super().__init__(content, **kwargs)
        self._on_close = on_close
        self._abort_on = tuple(abort_on)

    async def __call__(self, scope, receive, send):
        async def client_gone():
            while (await receive())["type"] != "http.disconnect":
                pass

        stream = asyncio.ensure_future(self.stream_response(send))
        watcher = asyncio.ensure_future(client_gone())
        try:
            await asyncio.wait({stream, watcher}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (stream, watcher):
                task.cancel()
            results = await asyncio.gather(stream, watcher, return_exceptions=True)
            with contextlib.suppress(Exception):
                await self.body_iterator.aclose()
            if self._on_close is not None:
                self._on_close()
        failure = results[0]
        if self._abort_on and isinstance(failure, self._abort_on):
            log.warning("stream aborted reason=%s", type(failure).__name__)
            return
        if isinstance(failure, Exception) and not isinstance(failure, OSError):
            raise failure


async def run_unless_client_leaves(receive, work):
    """Await `work`, but cancel it and return None if the client disconnects first."""
    async def client_gone():
        while (await receive())["type"] != "http.disconnect":
            pass

    task = asyncio.ensure_future(work)
    watcher = asyncio.ensure_future(client_gone())
    try:
        await asyncio.wait({task, watcher}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        watcher.cancel()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, watcher, return_exceptions=True)
    return None if task.cancelled() else task.result()
