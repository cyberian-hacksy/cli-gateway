"""SSE gate: release events as they complete, but hold the terminal event until told."""
import random

import pytest

from cgw import sse

CREATED = b'event: response.created\ndata: {"type":"response.created"}\n\n'
DELTA_1 = b'event: response.output_text.delta\ndata: {"delta":"Hel"}\n\n'
DELTA_2 = b'event: response.output_text.delta\ndata: {"delta":"lo \xe2\x9c\x93"}\n\n'
COMPLETED = b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"r1"}}\n\n'
STREAM = CREATED + DELTA_1 + DELTA_2 + COMPLETED


def feed_all(gate, data, sizes):
    """Feed `data` in pieces of the given sizes (cycled) and return everything released."""
    released, position, index = b"", 0, 0
    while position < len(data):
        size = sizes[index % len(sizes)]
        released += gate.feed(data[position:position + size])
        position += size
        index += 1
    return released


# --- release as events complete -------------------------------------------------------

def test_complete_event_is_released_immediately_and_unchanged():
    assert sse.SseGate().feed(DELTA_1) == DELTA_1


def test_several_events_in_one_chunk_are_all_released():
    assert sse.SseGate().feed(CREATED + DELTA_1 + DELTA_2) == CREATED + DELTA_1 + DELTA_2


def test_partial_event_is_held_until_its_blank_line_arrives():
    gate = sse.SseGate()
    assert gate.feed(DELTA_1[:-1]) == b""
    assert gate.feed(DELTA_1[-1:]) == DELTA_1


def test_event_split_across_many_chunks_is_released_once_and_intact():
    gate = sse.SseGate()
    assert feed_all(gate, DELTA_1 + DELTA_2, sizes=[1]) == DELTA_1 + DELTA_2


def test_comment_only_keepalive_is_released():
    assert sse.SseGate().feed(b": keepalive\n\n") == b": keepalive\n\n"


# --- the terminal event is held -------------------------------------------------------

def test_terminal_event_is_not_released_by_feed():
    gate = sse.SseGate()
    assert gate.feed(STREAM) == CREATED + DELTA_1 + DELTA_2
    assert gate.terminal_seen


def test_finish_returns_the_held_terminal_event():
    gate = sse.SseGate()
    gate.feed(STREAM)
    assert gate.finish() == COMPLETED


def test_bytes_after_the_terminal_event_are_held_too():
    gate = sse.SseGate()
    trailing = b'event: x.after\ndata: {}\n\n: bye\n\n'
    assert gate.feed(STREAM + trailing) == CREATED + DELTA_1 + DELTA_2
    assert gate.feed(b"data: late\n\n") == b""
    assert gate.finish() == COMPLETED + trailing + b"data: late\n\n"


@pytest.mark.parametrize("name", ["response.completed", "response.failed", "response.incomplete", "error"])
def test_every_terminal_event_name_is_held(name):
    terminal = b"event: " + name.encode() + b"\ndata: {}\n\n"
    gate = sse.SseGate()
    assert gate.feed(DELTA_1 + terminal) == DELTA_1
    assert gate.finish() == terminal


def test_terminal_event_named_only_in_its_data_is_held():
    terminal = b'data: {"type":"response.completed","response":{}}\n\n'
    gate = sse.SseGate()
    assert gate.feed(DELTA_1 + terminal) == DELTA_1
    assert gate.finish() == terminal


def test_terminal_type_in_multi_line_data_is_held():
    terminal = b'data: {"type":\ndata: "response.completed"}\n\n'
    gate = sse.SseGate()
    assert gate.feed(terminal) == b""
    assert gate.terminal_seen


def test_event_field_without_a_space_after_the_colon_is_recognised():
    terminal = b"event:response.completed\ndata:{}\n\n"
    gate = sse.SseGate()
    assert gate.feed(terminal) == b""
    assert gate.terminal_seen


def test_terminal_type_in_data_wins_over_an_innocuous_event_name():
    disguised = b'event: response.output_text.delta\ndata: {"type":"response.completed"}\n\n'
    gate = sse.SseGate()
    assert gate.feed(DELTA_1 + disguised) == DELTA_1
    assert gate.finish() == disguised


def test_terminal_type_nested_inside_a_string_is_released():
    nested = (b'event: response.output_text.delta\n'
              b'data: {"type":"response.output_text.delta","delta":"{\\"type\\":\\"response.completed\\"}"}\n\n')
    gate = sse.SseGate()
    assert gate.feed(nested) == nested
    assert not gate.terminal_seen


def test_delta_that_merely_mentions_the_terminal_name_is_released():
    sneaky = b'event: response.output_text.delta\ndata: {"delta":"event: response.completed"}\n\n'
    gate = sse.SseGate()
    assert gate.feed(sneaky) == sneaky
    assert not gate.terminal_seen


def test_non_json_data_without_an_event_name_is_released():
    plain = b"data: just text, not json\n\n"
    gate = sse.SseGate()
    assert gate.feed(plain) == plain
    assert not gate.terminal_seen


# --- finishing ------------------------------------------------------------------------

def test_finish_without_a_terminal_event_fails():
    gate = sse.SseGate()
    gate.feed(CREATED + DELTA_1)
    with pytest.raises(sse.SseError):
        gate.finish()


def test_finish_on_an_empty_stream_fails():
    with pytest.raises(sse.SseError):
        sse.SseGate().finish()


def test_finish_fails_when_the_terminal_event_never_completed():
    gate = sse.SseGate()
    gate.feed(DELTA_1 + COMPLETED[:-1])
    with pytest.raises(sse.SseError):
        gate.finish()


def test_feed_after_finish_fails():
    gate = sse.SseGate()
    gate.feed(STREAM)
    gate.finish()
    with pytest.raises(sse.SseError):
        gate.feed(DELTA_1)


# --- line endings ---------------------------------------------------------------------

@pytest.mark.parametrize("newline", [b"\r\n", b"\r"])
def test_other_line_endings_are_preserved_and_understood(newline):
    stream = STREAM.replace(b"\n", newline)
    completed = COMPLETED.replace(b"\n", newline)
    gate = sse.SseGate()
    released = gate.feed(stream)
    assert released == stream[:-len(completed)]
    assert gate.finish() == completed


def test_crlf_split_between_chunks_does_not_end_an_event_early():
    event = b"event: response.output_text.delta\r\ndata: {}\r\n\r\n"
    gate = sse.SseGate()
    assert feed_all(gate, event, sizes=[1]) == event


def test_lone_carriage_return_at_chunk_end_waits_for_the_next_byte():
    gate = sse.SseGate()
    assert gate.feed(b"data: a\r\n\r") == b""
    assert gate.feed(b"\ndata: b\r\n\r\n") == b"data: a\r\n\r\ndata: b\r\n\r\n"


# --- bounds ---------------------------------------------------------------------------

def test_event_larger_than_the_limit_fails():
    gate = sse.SseGate(max_event_bytes=1024)
    with pytest.raises(sse.SseError):
        gate.feed(b"data: " + b"a" * 2048)


def test_event_of_exactly_the_limit_is_released():
    event = b"data: " + b"a" * (1024 - 8) + b"\n\n"
    assert len(event) == 1024
    assert sse.SseGate(max_event_bytes=1024).feed(event) == event


def test_held_tail_larger_than_the_limit_fails():
    gate = sse.SseGate(max_event_bytes=1024)
    gate.feed(COMPLETED)
    with pytest.raises(sse.SseError):
        gate.feed(b"data: " + b"a" * 2048 + b"\n\n")


# --- property: any chunking gives the same answer --------------------------------------

@pytest.mark.parametrize("seed", range(40))
def test_any_chunking_releases_the_same_bytes_and_never_the_terminal_event(seed):
    rng = random.Random(seed)
    newline = rng.choice([b"\n", b"\r\n", b"\r"])
    body = b"".join(rng.choice([CREATED, DELTA_1, DELTA_2, b": ping\n\n"]) for _ in range(rng.randint(0, 12)))
    stream = (body + COMPLETED + rng.choice([b"", b": tail\n\n"])).replace(b"\n", newline)
    expected_released = body.replace(b"\n", newline)

    gate = sse.SseGate()
    released = feed_all(gate, stream, sizes=[rng.randint(1, 40) for _ in range(8)])

    assert released == expected_released
    assert b"response.completed" not in released
    assert released + gate.finish() == stream
