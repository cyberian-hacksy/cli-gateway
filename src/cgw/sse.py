"""SSE gate for the local bridge.

Upstream SSE bytes are released one complete event at a time, unchanged, and always one
event behind: the newest complete event is held until the next one completes, and the last
one until the encrypted stream has verified its final record.

Every event-stream format ends with the event that says it is done: `response.completed`
for Responses, `message_stop` for Anthropic messages, `[DONE]` for chat completions, the
chunk carrying `finishReason` for Gemini. So a tool never sees the end of a stream that a
truncated stream could not back up, and the gate needs no knowledge of any one format.
"""
import re

MAX_EVENT_BYTES = 8 * 1024 * 1024

_LINE_END = re.compile(rb"[\r\n]")


class SseError(Exception):
    """The upstream event stream cannot be released safely."""


class SseGate:
    def __init__(self, max_event_bytes=MAX_EVENT_BYTES):
        self._max_event_bytes = max_event_bytes
        self._pending = b""     # bytes of the event still being received
        self._line_start = 0    # offset in _pending where the unterminated line begins
        self._held = b""        # the newest complete event
        self._finished = False

    def feed(self, chunk):
        """Accept upstream bytes; return the bytes that are safe to release now."""
        if self._finished:
            raise SseError("stream already finished")
        released = b""
        for event in self._complete_events(self._pending + chunk, at_end=False):
            released += self._held
            self._held = event
        return released

    def finish(self):
        """Call once the encrypted stream has verified its final record. Returns everything held."""
        if self._finished:
            raise SseError("stream already finished")
        # No more bytes can arrive, so a trailing carriage return is a complete line ending.
        events = self._complete_events(self._pending, at_end=True)
        self._finished = True
        rest = self._held + b"".join(events) + self._pending
        self._held = self._pending = b""
        return rest

    def _complete_events(self, pending, at_end):
        """Split complete events off `pending`; keep the unfinished remainder for later."""
        events, event_start, position = [], 0, self._line_start
        while True:
            match = _LINE_END.search(pending, position)
            if match is None:
                break
            line_end = match.start()
            next_line = line_end + 1
            if pending[line_end] == 0x0D:  # carriage return: may be the first half of CRLF
                if next_line == len(pending):
                    if not at_end:
                        break
                elif pending[next_line] == 0x0A:
                    next_line += 1
            blank_line = line_end == position
            position = next_line
            if not blank_line:
                continue
            event = pending[event_start:next_line]
            if len(event) > self._max_event_bytes:
                raise SseError("event too large")
            events.append(event)
            event_start = next_line

        self._pending = pending[event_start:]
        self._line_start = position - event_start
        if len(self._pending) > self._max_event_bytes:
            raise SseError("event too large")
        return events
