"""SSE gate: release events one behind, and the last one only once the stream has verified."""
import random

import pytest

from cgw import sse

CREATED = b'event: response.created\ndata: {"type":"response.created"}\n\n'
DELTA_1 = b'event: response.output_text.delta\ndata: {"delta":"Hel"}\n\n'
DELTA_2 = b'event: response.output_text.delta\ndata: {"delta":"lo \xe2\x9c\x93"}\n\n'
COMPLETED = b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"r1"}}\n\n'
STREAM = CREATED + DELTA_1 + DELTA_2 + COMPLETED

# How each format ends: the last event is the one that says the stream is done.
FORMATS = {
    "responses": [CREATED, DELTA_1, DELTA_2, COMPLETED],
    "anthropic": [
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"m1"}}\n\n',
        b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"hi"}}\n\n',
        b'event: ping\ndata: {"type":"ping"}\n\n',
        b'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}\n\n',
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'],
    "chat": [
        b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n',
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n',
        b"data: [DONE]\n\n"],
    "gemini": [
        b'data: {"candidates":[{"content":{"parts":[{"text":"h"}]}}]}\r\n\r\n',
        b'data: {"candidates":[{"content":{"parts":[{"text":"i"}]},"finishReason":"STOP"}]}\r\n\r\n'],
}


def feed_all(gate, data, sizes):
    """Feed `data` in pieces of the given sizes (cycled) and return everything released."""
    released, position, index = b"", 0, 0
    while position < len(data):
        size = sizes[index % len(sizes)]
        released += gate.feed(data[position:position + size])
        position += size
        index += 1
    return released


# --- one event behind -----------------------------------------------------------------

def test_a_complete_event_is_held_until_the_next_one_completes():
    gate = sse.SseGate()
    assert gate.feed(DELTA_1) == b""
    assert gate.feed(DELTA_2) == DELTA_1


def test_several_events_in_one_chunk_are_released_except_the_newest():
    assert sse.SseGate().feed(CREATED + DELTA_1 + DELTA_2) == CREATED + DELTA_1


def test_partial_event_releases_nothing_new():
    gate = sse.SseGate()
    gate.feed(DELTA_1)
    assert gate.feed(DELTA_2[:-1]) == b""
    assert gate.feed(DELTA_2[-1:]) == DELTA_1


def test_event_split_across_many_chunks_is_released_once_and_intact():
    gate = sse.SseGate()
    assert feed_all(gate, DELTA_1 + DELTA_2 + CREATED, sizes=[1]) == DELTA_1 + DELTA_2


def test_comment_only_keepalive_counts_as_an_event():
    gate = sse.SseGate()
    assert gate.feed(b": keepalive\n\n" + DELTA_1) == b": keepalive\n\n"


# --- finishing ------------------------------------------------------------------------

def test_finish_returns_the_held_last_event():
    gate = sse.SseGate()
    assert gate.feed(STREAM) == CREATED + DELTA_1 + DELTA_2
    assert gate.finish() == COMPLETED


def test_finish_also_returns_an_unterminated_tail():
    # The stream has verified, so whatever upstream sent is released exactly as sent.
    gate = sse.SseGate()
    gate.feed(DELTA_1 + b"data: no blank line")
    assert gate.finish() == DELTA_1 + b"data: no blank line"


def test_finish_on_an_empty_stream_returns_nothing():
    assert sse.SseGate().finish() == b""


def test_feed_after_finish_fails():
    gate = sse.SseGate()
    gate.feed(STREAM)
    gate.finish()
    with pytest.raises(sse.SseError):
        gate.feed(DELTA_1)


def test_finish_twice_fails():
    gate = sse.SseGate()
    gate.finish()
    with pytest.raises(sse.SseError):
        gate.finish()


@pytest.mark.parametrize("name", sorted(FORMATS))
def test_the_event_that_ends_each_format_is_held_until_finish(name):
    events = FORMATS[name]
    gate = sse.SseGate()
    assert gate.feed(b"".join(events)) == b"".join(events[:-1])
    assert gate.finish() == events[-1]


# --- line endings ---------------------------------------------------------------------

def test_crlf_line_endings_are_preserved_and_understood():
    stream = STREAM.replace(b"\n", b"\r\n")
    completed = COMPLETED.replace(b"\n", b"\r\n")
    gate = sse.SseGate()
    assert gate.feed(stream) == stream[:-len(completed)]
    assert gate.finish() == completed


def test_bare_carriage_returns_are_preserved_and_understood():
    # A carriage return at the very end might be the first half of CRLF, so the last event is
    # not known to be complete until finish, and the one before it stays held as the newest.
    stream = STREAM.replace(b"\n", b"\r")
    tail = (DELTA_2 + COMPLETED).replace(b"\n", b"\r")
    gate = sse.SseGate()
    assert gate.feed(stream) == stream[:-len(tail)]
    assert gate.finish() == tail


def test_crlf_split_between_chunks_does_not_end_an_event_early():
    event = b"event: response.output_text.delta\r\ndata: {}\r\n\r\n"
    gate = sse.SseGate()
    assert feed_all(gate, event + event, sizes=[1]) == event


def test_lone_carriage_return_at_chunk_end_waits_for_the_next_byte():
    gate = sse.SseGate()
    assert gate.feed(b"data: a\r\n\r") == b""
    assert gate.feed(b"\ndata: b\r\n\r\n") == b"data: a\r\n\r\n"
    assert gate.finish() == b"data: b\r\n\r\n"


# --- bounds ---------------------------------------------------------------------------

def test_event_larger_than_the_limit_fails():
    gate = sse.SseGate(max_event_bytes=1024)
    with pytest.raises(sse.SseError):
        gate.feed(b"data: " + b"a" * 2048)


def test_complete_event_larger_than_the_limit_fails():
    gate = sse.SseGate(max_event_bytes=1024)
    with pytest.raises(sse.SseError):
        gate.feed(b"data: " + b"a" * 2048 + b"\n\n")


def test_event_of_exactly_the_limit_is_accepted():
    event = b"data: " + b"a" * (1024 - 8) + b"\n\n"
    assert len(event) == 1024
    gate = sse.SseGate(max_event_bytes=1024)
    assert gate.feed(event + DELTA_1) == event


# --- properties: any chunking, any cut ------------------------------------------------

@pytest.mark.parametrize("seed", range(40))
def test_any_chunking_releases_everything_but_the_last_event_until_finish(seed):
    rng = random.Random(seed)
    newline = rng.choice([b"\n", b"\r\n", b"\r"])
    events = list(FORMATS[rng.choice(sorted(FORMATS))])
    events = [rng.choice(events[:-1]) for _ in range(rng.randint(0, 12))] + [events[-1]]
    events = [event.replace(b"\r\n", b"\n").replace(b"\n", newline) for event in events]
    stream = b"".join(events)

    gate = sse.SseGate()
    released = feed_all(gate, stream, sizes=[rng.randint(1, 40) for _ in range(8)])

    if newline == b"\r":
        # A final bare carriage return leaves the last event unconfirmed, so one more is held.
        assert released == b"".join(events[:-2])
    else:
        assert released == b"".join(events[:-1])
    assert released + gate.finish() == stream


@pytest.mark.parametrize("name", sorted(FORMATS))
def test_a_stream_cut_anywhere_never_releases_its_final_event(name):
    stream = b"".join(FORMATS[name])
    final = FORMATS[name][-1]
    for cut in range(len(stream) + 1):
        gate = sse.SseGate()
        released = gate.feed(stream[:cut])
        assert final not in released, cut
