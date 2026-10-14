"""HTTP server protocol for the gateway's public listener."""
from uvicorn.protocols.http.h11_impl import H11Protocol

HEAD_TIMEOUT_SECONDS = 10.0


class HeadTimeoutProtocol(H11Protocol):
    """Closes a connection that does not deliver a complete request head in time.

    The underlying server only times out idle connections after a response. Without this, a
    connection that sends nothing, or trickles a request head, is held forever and counts
    toward the connection cap, so idle anonymous connections could fill it and lock every
    client out. The deadline is never extended by trickled bytes, and it does not apply
    while a request is being served; request bodies have their own deadline in the bridge.
    """

    head_timeout = HEAD_TIMEOUT_SECONDS

    def connection_made(self, transport):
        self._head_timer = None
        super().connection_made(transport)
        self._arm_head_timer()

    def data_received(self, data):
        super().data_received(data)
        if self._request_in_progress():
            self._cancel_head_timer()
        else:
            # Bytes of a new request head after a kept-alive response. Arms the deadline if
            # it is not running; never pushes back one that is.
            self._arm_head_timer()

    def connection_lost(self, exc):
        self._cancel_head_timer()
        super().connection_lost(exc)

    def _request_in_progress(self):
        return self.cycle is not None and not self.cycle.response_complete

    def _arm_head_timer(self):
        if self._head_timer is None:
            self._head_timer = self.loop.call_later(self.head_timeout, self._head_timed_out)

    def _cancel_head_timer(self):
        if self._head_timer is not None:
            self._head_timer.cancel()
            self._head_timer = None

    def _head_timed_out(self):
        self._head_timer = None
        if not self._request_in_progress() and not self.transport.is_closing():
            self.transport.close()
