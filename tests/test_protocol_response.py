"""Response stream: sealing, opening, ordering, truncation and tampering."""
import json

import pytest

import wire_reference as ref
from cgw import protocol

PSK = bytes(range(32))
OTHER_PSK = bytes(range(1, 33))
HID = bytes(range(200, 232))
SHARED = bytes(range(64, 96))
IKM = PSK + SHARED
SESSION = protocol.Session(kid="poc-1", hid=HID, ikm=IKM)
KID = "poc-1"
RID = bytes(range(100, 132))
TS = 1_800_000_000
SSE = b'event: response.output_text.delta\ndata: {"delta":"h\xc3\xa9llo"}\n\n'
RESPONSE_HEADERS = {"content-type": "text/event-stream"}
META_JSON = json.dumps({"status": 200, "headers": RESPONSE_HEADERS}).encode()


def sealer():
    return protocol.ResponseSealer(SESSION, RID, TS)


def opener(session=SESSION, rid=RID, ts=TS):
    return protocol.ResponseOpener(session, rid, ts)


def forger(**overrides):
    """Reference writer for building streams the real sealer refuses to produce."""
    args = {"ikm": IKM, "kid": KID, "hid": HID, "rid": RID, "ts": TS}
    args.update(overrides)
    return ref.ResponseWriter(**args)


def opened_with_meta(writer):
    """An opener that has consumed the writer's header and a valid META record."""
    reader = opener()
    reader.open_header(writer.header_line())
    reader.open_record(writer.record(protocol.META, META_JSON))
    return reader


def good_stream():
    out = sealer()
    return [
        out.header_line(),
        out.meta(200, RESPONSE_HEADERS),
        out.data(SSE),
        out.heartbeat(),
        out.data(b"second chunk"),
        out.end(),
    ]


def open_all(lines, reader=None):
    reader = reader or opener()
    reader.open_header(lines[0])
    return reader, [reader.open_record(line) for line in lines[1:]]


# --- round trip -----------------------------------------------------------------------

def test_full_stream_round_trips_in_order():
    reader, records = open_all(good_stream())
    assert [record.type for record in records] == [
        protocol.META, protocol.DATA, protocol.HEARTBEAT, protocol.DATA, protocol.END]
    assert reader.finished


def test_data_payload_is_byte_exact():
    _, records = open_all(good_stream())
    assert records[1].payload == SSE
    assert records[3].payload == b"second chunk"


def test_meta_carries_upstream_status_and_headers():
    _, records = open_all(good_stream())
    assert records[0].value == {"status": 200, "headers": RESPONSE_HEADERS}


@pytest.mark.parametrize("status", [200, 400, 401, 429, 500, 503])
def test_upstream_error_status_is_preserved_in_meta(status):
    out = sealer()
    _, records = open_all([out.header_line(), out.meta(status, {}), out.data(b'{"error":"x"}'), out.end()])
    assert records[0].value["status"] == status


def test_binary_data_round_trips():
    out = sealer()
    blob = bytes(range(256)) * 8
    _, records = open_all([out.header_line(), out.meta(200, {}), out.data(blob), out.end()])
    assert records[1].payload == blob


def test_error_record_ends_the_stream():
    out = sealer()
    reader, records = open_all([out.header_line(), out.error({"code": "upstream_unreachable"})])
    assert records[0].type == protocol.ERROR
    assert records[0].value == {"code": "upstream_unreachable"}
    assert reader.finished


def test_error_record_may_follow_data():
    out = sealer()
    reader, records = open_all(
        [out.header_line(), out.meta(200, {}), out.data(b"partial"), out.error({"code": "upstream_reset"})])
    assert records[-1].type == protocol.ERROR and reader.finished


def test_heartbeat_may_precede_meta():
    out = sealer()
    _, records = open_all([out.header_line(), out.heartbeat(), out.meta(200, {}), out.end()])
    assert [record.type for record in records] == [protocol.HEARTBEAT, protocol.META, protocol.END]


def test_stream_is_not_finished_before_the_final_record():
    lines = good_stream()
    reader, _ = open_all(lines[:-1])
    assert not reader.finished


# --- wire format ----------------------------------------------------------------------

def test_lines_are_newline_terminated_json_with_the_specified_fields():
    lines = good_stream()
    assert all(line.endswith(b"\n") and line.count(b"\n") == 1 for line in lines)
    assert set(json.loads(lines[0])) == {"v", "header"} and json.loads(lines[0])["v"] == 2
    for sequence, line in enumerate(lines[1:]):
        entry = json.loads(line)
        assert set(entry) == {"seq", "data"} and entry["seq"] == sequence


def test_largest_data_record_fits_in_a_24_kib_line():
    out = sealer()
    out.meta(200, {})
    assert len(out.data(bytes(16 * 1024))) <= 24 * 1024


def test_stream_opens_with_the_independent_reference():
    records = ref.read_response(IKM, KID, HID, RID, TS, good_stream())
    assert [(record_type, tag) for record_type, _, tag in records] == [
        (1, ref.TAG_MESSAGE), (2, ref.TAG_MESSAGE), (3, ref.TAG_MESSAGE), (2, ref.TAG_MESSAGE), (4, ref.TAG_FINAL)]
    assert json.loads(records[0][1]) == {"status": 200, "headers": RESPONSE_HEADERS}
    assert records[1][1] == SSE and records[2][1] == b"" and records[4][1] == b""


def test_error_record_carries_the_final_tag():
    out = sealer()
    records = ref.read_response(IKM, KID, HID, RID, TS, [out.header_line(), out.error({"code": "x"})])
    assert records[0][0] == 5 and records[0][2] == ref.TAG_FINAL


def test_stream_built_by_the_independent_reference_opens():
    writer = forger()
    reader, records = open_all([
        writer.header_line(),
        writer.record(protocol.META, META_JSON),
        writer.record(protocol.DATA, SSE),
        writer.record(protocol.END, tag=ref.TAG_FINAL),
    ])
    assert records[1].payload == SSE and reader.finished


def test_response_text_is_not_visible_on_the_wire():
    canary = b"CANARY-51be02-unique-reply-text"
    out = sealer()
    lines = [out.header_line(), out.meta(200, {}), out.data(canary * 4), out.end()]
    assert all(canary not in line for line in lines)
    assert canary not in ref.unb64(json.loads(lines[2])["data"])


def test_chunks_splits_upstream_bytes_into_data_sized_pieces():
    blob = bytes(range(256)) * 200  # 51200 bytes
    pieces = list(protocol.chunks(blob))
    assert b"".join(pieces) == blob
    assert [len(piece) for piece in pieces] == [16384, 16384, 16384, 2048]
    assert list(protocol.chunks(b"")) == []


# --- authentication and context -------------------------------------------------------

@pytest.mark.parametrize("context", [
    {"session": protocol.Session(kid="poc-1", hid=HID, ikm=OTHER_PSK + SHARED)},
    {"session": protocol.Session(kid="poc-2", hid=HID, ikm=IKM)},
    {"session": protocol.Session(kid="poc-1", hid=bytes(32), ikm=IKM)},
    {"session": protocol.Session(kid="poc-1", hid=HID, ikm=PSK + bytes(32))},
    {"rid": bytes(32)}, {"ts": TS + 1}])
def test_stream_from_another_key_or_session_context_is_rejected(context):
    lines = good_stream()
    reader = opener(**context)
    reader.open_header(lines[0])
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(lines[1])


def test_response_sealed_with_the_request_key_is_rejected():
    writer = forger(info=ref.REQUEST_INFO)
    reader = opener()
    reader.open_header(writer.header_line())
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.META, META_JSON))


def test_flipped_bit_in_a_record_is_rejected():
    lines = good_stream()
    entry = json.loads(lines[2])
    raw = bytearray(ref.unb64(entry["data"]))
    raw[5] ^= 0x01
    entry["data"] = ref.b64(bytes(raw))
    reader, _ = open_all(lines[:2])
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(ref.dump(entry) + b"\n")


def test_flipped_bit_in_the_stream_header_is_rejected():
    lines = good_stream()
    raw = bytearray(ref.unb64(json.loads(lines[0])["header"]))
    raw[0] ^= 0x01
    reader = opener()
    reader.open_header(ref.dump({"v": 2, "header": ref.b64(bytes(raw))}) + b"\n")
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(lines[1])


# --- ordering, replay and truncation --------------------------------------------------

def test_reordered_records_are_rejected():
    lines = good_stream()
    reader, _ = open_all(lines[:2])
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(lines[3])


def test_duplicated_record_is_rejected():
    lines = good_stream()
    reader, _ = open_all(lines[:3])
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(lines[2])


def test_wire_sequence_that_disagrees_with_position_is_rejected():
    writer = forger()
    reader = opener()
    reader.open_header(writer.header_line())
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.META, META_JSON, wire_seq=1))


def test_record_after_the_final_record_is_rejected():
    writer = forger()
    reader = opened_with_meta(writer)
    reader.open_record(writer.record(protocol.END, tag=ref.TAG_FINAL))
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.DATA, b"late"))


def test_opener_stays_failed_after_a_rejected_record():
    lines = good_stream()
    reader, _ = open_all(lines[:2])
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(lines[3])
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(lines[2])
    assert not reader.finished


@pytest.mark.parametrize("record_type", [protocol.DATA, protocol.END])
def test_data_or_end_before_meta_is_rejected(record_type):
    writer = forger()
    reader = opener()
    reader.open_header(writer.header_line())
    payload = b"x" if record_type == protocol.DATA else b""
    tag = ref.TAG_FINAL if record_type == protocol.END else ref.TAG_MESSAGE
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(record_type, payload, tag=tag))


def test_second_meta_is_rejected():
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.META, META_JSON))


def test_end_without_the_final_tag_is_rejected():
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.END, tag=ref.TAG_MESSAGE))
    assert not reader.finished


@pytest.mark.parametrize("record_type,payload", [
    (protocol.DATA, b"x"), (protocol.HEARTBEAT, b""), (protocol.META, META_JSON)])
def test_non_terminal_record_with_the_final_tag_is_rejected(record_type, payload):
    writer = forger()
    reader = opener()
    reader.open_header(writer.header_line())
    if record_type != protocol.META:
        reader.open_record(writer.record(protocol.META, META_JSON))
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(record_type, payload, tag=ref.TAG_FINAL))
    assert not reader.finished


def test_record_before_the_stream_header_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        opener().open_record(good_stream()[1])


def test_second_stream_header_is_rejected():
    lines = good_stream()
    reader = opener()
    reader.open_header(lines[0])
    with pytest.raises(protocol.ProtocolError):
        reader.open_header(lines[0])


# --- record content rules -------------------------------------------------------------

@pytest.mark.parametrize("record_type", [0x00, 0x06, 0xFF])
def test_unknown_record_type_is_rejected(record_type):
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(record_type, b"x"))


def test_record_without_a_type_byte_is_rejected():
    writer = forger()
    reader = opened_with_meta(writer)
    data = ref.sodium.crypto_secretstream_xchacha20poly1305_push(
        writer.state, b"", ref.aad(KID, HID, RID, TS, 1, writer.sequence), ref.TAG_MESSAGE)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(ref.dump({"seq": writer.sequence, "data": ref.b64(data)}) + b"\n")


@pytest.mark.parametrize("record_type,tag", [
    (protocol.HEARTBEAT, ref.TAG_MESSAGE), (protocol.END, ref.TAG_FINAL)])
def test_heartbeat_or_end_with_a_payload_is_rejected(record_type, tag):
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(record_type, b"smuggled", tag=tag))


def test_empty_data_record_is_rejected():
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.DATA, b""))


def test_data_record_larger_than_16_kib_is_rejected():
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.DATA, bytes(16 * 1024 + 1)))


def test_line_longer_than_24_kib_is_rejected_before_decryption():
    writer = forger()
    reader = opened_with_meta(writer)
    with pytest.raises(protocol.ProtocolError, match="too long"):
        reader.open_record(b'{"seq":1,"data":"' + b"A" * (24 * 1024) + b'"}\n')


@pytest.mark.parametrize("meta", [
    b"not json", b"[]", b"{}",
    b'{"status":"200","headers":{}}', b'{"status":true,"headers":{}}',
    b'{"status":99,"headers":{}}', b'{"status":600,"headers":{}}',
    b'{"status":200,"headers":[]}', b'{"status":200,"headers":{"a":1}}',
    b'{"status":200,"headers":{},"extra":1}', b'{"status":200}',
])
def test_malformed_meta_is_rejected(meta):
    writer = forger()
    reader = opener()
    reader.open_header(writer.header_line())
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.META, meta))


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"pad":"' + b"a" * 1024 + b'"}'])
def test_malformed_or_oversized_error_payload_is_rejected(payload):
    writer = forger()
    reader = opener()
    reader.open_header(writer.header_line())
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(writer.record(protocol.ERROR, payload, tag=ref.TAG_FINAL))
    assert not reader.finished


# --- strict line parsing --------------------------------------------------------------

@pytest.mark.parametrize("line", [
    b"", b"not json\n", b"[]\n",
    b'{"v":1,"header":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}\n',
    b'{"v":2}\n',
    b'{"v":2,"header":"AAAA"}\n',
    b'{"v":2,"header":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":1}\n',
    b'{"v":2,"v":2,"header":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}\n',
    b'{"v":2,"header":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}\n{"seq":0}\n',
])
def test_malformed_stream_header_line_is_rejected(line):
    with pytest.raises(protocol.ProtocolError):
        opener().open_header(line)


@pytest.mark.parametrize("mutation", [
    {"seq": "1"}, {"seq": True}, {"seq": -1}, {"seq": 1.0}, {"seq": None},
    {"data": 5}, {"data": "not base64!"}, {"extra": 1},
])
def test_malformed_record_line_is_rejected(mutation):
    lines = good_stream()
    reader, _ = open_all(lines[:2])
    entry = json.loads(lines[2])
    entry.update(mutation)
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(ref.dump(entry) + b"\n")


@pytest.mark.parametrize("field", ["seq", "data"])
def test_record_line_missing_a_field_is_rejected(field):
    lines = good_stream()
    reader, _ = open_all(lines[:2])
    entry = json.loads(lines[2])
    del entry[field]
    with pytest.raises(protocol.ProtocolError):
        reader.open_record(ref.dump(entry) + b"\n")


# --- sealer refuses to produce an invalid stream --------------------------------------

def test_sealer_refuses_data_before_meta():
    with pytest.raises(protocol.ProtocolError):
        sealer().data(b"x")


def test_sealer_refuses_end_before_meta():
    with pytest.raises(protocol.ProtocolError):
        sealer().end()


def test_sealer_refuses_a_second_meta():
    out = sealer()
    out.meta(200, {})
    with pytest.raises(protocol.ProtocolError):
        out.meta(200, {})


@pytest.mark.parametrize("finish", ["end", "error"])
def test_sealer_refuses_anything_after_the_final_record(finish):
    out = sealer()
    out.meta(200, {})
    out.end() if finish == "end" else out.error({"code": "x"})
    for attempt in (lambda: out.data(b"x"), out.heartbeat, out.end, lambda: out.error({"code": "y"})):
        with pytest.raises(protocol.ProtocolError):
            attempt()


@pytest.mark.parametrize("chunk", [b"", bytes(16 * 1024 + 1)])
def test_sealer_refuses_empty_or_oversized_data(chunk):
    out = sealer()
    out.meta(200, {})
    with pytest.raises(protocol.ProtocolError):
        out.data(chunk)


def test_sealer_refuses_oversized_error_payload():
    with pytest.raises(protocol.ProtocolError):
        sealer().error({"pad": "a" * 1024})


# --- timestamp freshness --------------------------------------------------------------

@pytest.mark.parametrize("offset,fresh", [(0, True), (120, True), (-120, True), (121, False), (-121, False)])
def test_timestamp_is_fresh_within_120_seconds_either_way(offset, fresh):
    assert protocol.timestamp_is_fresh(TS + offset, now=TS) is fresh
