"""SSE gate for the local bridge.

Upstream SSE bytes are released to Codex one complete event at a time, unchanged. The
terminal Responses event, and anything after it, is held until the encrypted stream has
verified its final record, so Codex never sees a completion that a truncated stream
could not back up.
"""
import json
import re

MAX_EVENT_BYTES = 8 * 1024 * 1024
TERMINAL_EVENTS = frozenset({"response.completed", "response.failed", "response.incomplete", "error"})

_LINE_END = re.compile(rb"[\r\n]")
_LINE_SPLIT = re.compile(rb"\r\n|\r|\n")
_TERMINAL_HINTS = tuple(name.encode("ascii") for name in TERMINAL_EVENTS)


class SseError(Exception):
    """The upstream event stream cannot be released safely."""


def _field_value(line, prefix):
    value = line[len(prefix):]
    return value[1:] if value.startswith(b" ") else value


def _is_terminal(event):
    """True if the event's name, or the `type` of its JSON data, is a terminal Responses event.

    Codex reads the type from the data, so the data decides even when the event name
    says otherwise.
    """
    if not any(hint in event for hint in _TERMINAL_HINTS):
        return False
    name, data_lines = None, []
    for line in _LINE_SPLIT.split(event):
        if line.startswith(b"event:"):
            name = _field_value(line, b"event:")
        elif line.startswith(b"data:"):
            data_lines.append(_field_value(line, b"data:"))
    if name is not None and name.decode("utf-8", "replace") in TERMINAL_EVENTS:
        return True
    try:
        data = json.loads(b"\n".join(data_lines))
    except ValueError:
        return False
    return isinstance(data, dict) and data.get("type") in TERMINAL_EVENTS


class SseGate:
    def __init__(self, max_event_bytes=MAX_EVENT_BYTES):
        self._max_event_bytes = max_event_bytes
        self._pending = b""     # bytes of the event still being received
        self._line_start = 0    # offset in _pending where the unterminated line begins
        self._held = b""        # the terminal event and everything after it
        self.terminal_seen = False
        self._finished = False

    def feed(self, chunk):
        """Accept upstream bytes; return the bytes that are safe to release now."""
        if self._finished:
            raise SseError("stream already finished")
        if self.terminal_seen:
            self._hold(chunk)
            return b""
        return self._scan(self._pending + chunk, at_end=False)

    def finish(self):
        """Call once the encrypted stream has verified its final record.

        Returns everything still held. Fails unless a terminal event was received.
        """
        if self._finished:
            raise SseError("stream already finished")
        # No more bytes can arrive, so a trailing carriage return is a complete line ending.
        released = b"" if self.terminal_seen else self._scan(self._pending, at_end=True)
        if not self.terminal_seen:
            raise SseError("stream ended without a terminal event")
        self._finished = True
        held, self._held = self._held, b""
        return released + held

    def _scan(self, pending, at_end):
        """Release complete events from `pending`; move a terminal event and its tail to the hold."""
        released_until, event_start, position = 0, 0, self._line_start
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
            if _is_terminal(event):
                self.terminal_seen = True
                self._hold(pending[event_start:])
                self._pending, self._line_start = b"", 0
                return pending[:released_until]
            released_until = event_start = next_line

        self._pending = pending[released_until:]
        self._line_start = position - released_until
        if len(self._pending) > self._max_event_bytes:
            raise SseError("event too large")
        return pending[:released_until]

    def _hold(self, data):
        self._held += data
        if len(self._held) > self._max_event_bytes:
            raise SseError("held tail too large")
