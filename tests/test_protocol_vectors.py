"""Frozen wire vectors.

`fixtures/protocol_v2.json` was produced once by the independent reference in
`wire_reference.py` (see `make_vectors.py`), not by cgw.protocol, with fixed X25519 keys on
both sides so the whole handshake is reproducible. If these tests fail after a dependency
upgrade or a refactor, the wire format changed.
"""
import json
from pathlib import Path

import pytest

from cgw import protocol

VECTORS = Path(__file__).parent / "fixtures" / "protocol_v2.json"


@pytest.fixture(scope="module")
def vectors():
    return json.loads(VECTORS.read_text())


def values(vectors):
    return (bytes.fromhex(vectors["psk_hex"]), vectors["kid"], bytes.fromhex(vectors["hid_hex"]),
            bytes.fromhex(vectors["rid_hex"]), vectors["ts"])


def session_of(vectors):
    psk, kid, hid, _, _ = values(vectors)
    return protocol.Session(kid=kid, hid=hid, ikm=psk + bytes.fromhex(vectors["handshake"]["shared_hex"]))


def test_frozen_client_hello_is_reproduced(vectors):
    psk, kid, hid, _, ts = values(vectors)
    handshake = protocol.ClientHandshake(psk, kid, ts, hid=hid, private=bytes.fromhex(vectors["client_private_hex"]))
    assert handshake.message() == vectors["handshake"]["hello"].encode()


def test_frozen_reply_completes_to_the_recorded_session(vectors):
    psk, kid, hid, _, ts = values(vectors)
    handshake = protocol.ClientHandshake(psk, kid, ts, hid=hid, private=bytes.fromhex(vectors["client_private_hex"]))
    assert handshake.complete(vectors["handshake"]["reply"].encode()) == session_of(vectors)


def test_frozen_client_hello_is_accepted_by_the_server(vectors):
    psk, kid, hid, _, ts = values(vectors)
    answered = protocol.answer_handshake(vectors["handshake"]["hello"].encode(), {kid: psk})
    assert (answered.session.kid, answered.session.hid, answered.ts) == (kid, hid, ts)


def test_frozen_admission_tags_are_reproduced(vectors):
    psk, kid, hid, rid, ts = values(vectors)
    hello = vectors["handshake"]["hello"].encode()
    assert protocol.seal_admission(psk, kid, hid, ts, len(hello)) == vectors["handshake"]["hello_admission"]
    expected = vectors["admission"]
    assert protocol.seal_admission(psk, kid, rid, ts, expected["content_length"]) == expected["value"]


def test_frozen_key_derivation_matches(vectors):
    session, rid = session_of(vectors), values(vectors)[3]
    assert protocol.derive_key(session, rid, protocol.REQUEST).hex() == vectors["request_key_hex"]
    assert protocol.derive_key(session, rid, protocol.RESPONSE).hex() == vectors["response_key_hex"]


def test_frozen_request_envelope_opens_to_the_recorded_plaintext(vectors):
    session = session_of(vectors)
    opened = protocol.open_request(vectors["request"]["envelope"].encode(),
                                   lambda kid, hid: session if (kid, hid) == (session.kid, session.hid) else None)
    assert (opened.rid, opened.ts) == (values(vectors)[3], vectors["ts"])
    assert opened.metadata == vectors["request"]["metadata"]
    assert opened.body == bytes.fromhex(vectors["request"]["body_hex"])


def test_frozen_response_stream_opens_to_the_recorded_records(vectors):
    _, _, _, rid, ts = values(vectors)
    reader = protocol.ResponseOpener(session_of(vectors), rid, ts)
    lines = [line.encode() for line in vectors["response"]["lines"]]
    reader.open_header(lines[0])
    records = [reader.open_record(line) for line in lines[1:]]
    assert [(record.type, record.payload.hex()) for record in records] == [
        (expected["type"], expected["payload_hex"]) for expected in vectors["response"]["records"]]
    assert reader.finished
