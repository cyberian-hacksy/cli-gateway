"""Frozen wire vectors.

`fixtures/protocol_v1.json` was produced once by the independent reference in
`wire_reference.py` (see `make_vectors.py`), not by cgw.protocol. If these tests fail
after a dependency upgrade or a refactor, the wire format changed.
"""
import json
from pathlib import Path

import pytest

from cgw import protocol

VECTORS = Path(__file__).parent / "fixtures" / "protocol_v1.json"


@pytest.fixture(scope="module")
def vectors():
    return json.loads(VECTORS.read_text())


def test_frozen_request_envelope_opens_to_the_recorded_plaintext(vectors):
    psk = bytes.fromhex(vectors["psk_hex"])
    opened = protocol.open_request(vectors["request"]["envelope"].encode(), {vectors["kid"]: psk})
    assert opened.rid == bytes.fromhex(vectors["rid_hex"])
    assert opened.ts == vectors["ts"]
    assert opened.metadata == vectors["request"]["metadata"]
    assert opened.body == bytes.fromhex(vectors["request"]["body_hex"])


def test_frozen_response_stream_opens_to_the_recorded_records(vectors):
    reader = protocol.ResponseOpener(
        bytes.fromhex(vectors["psk_hex"]), vectors["kid"], bytes.fromhex(vectors["rid_hex"]), vectors["ts"])
    lines = [line.encode() for line in vectors["response"]["lines"]]
    reader.open_header(lines[0])
    records = [reader.open_record(line) for line in lines[1:]]
    assert [(record.type, record.payload.hex()) for record in records] == [
        (expected["type"], expected["payload_hex"]) for expected in vectors["response"]["records"]]
    assert reader.finished


def test_frozen_key_derivation_matches(vectors):
    psk, rid = bytes.fromhex(vectors["psk_hex"]), bytes.fromhex(vectors["rid_hex"])
    assert protocol.derive_key(psk, rid, protocol.REQUEST).hex() == vectors["request_key_hex"]
    assert protocol.derive_key(psk, rid, protocol.RESPONSE).hex() == vectors["response_key_hex"]
