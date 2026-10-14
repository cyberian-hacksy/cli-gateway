"""Request envelope: sealing, opening, tampering, strict parsing and size limits."""
import json
import struct

import pytest

import wire_reference as ref
from cgw import protocol

PSK = bytes(range(32))
OTHER_PSK = bytes(range(1, 33))
KID = "poc-1"
RID = bytes(range(100, 132))
TS = 1_800_000_000
HID = bytes(range(200, 232))
SHARED = bytes(range(64, 96))
IKM = PSK + SHARED
SESSION = protocol.Session(kid=KID, hid=HID, ikm=IKM)
OTHER_SESSION = protocol.Session(kid=KID, hid=HID, ikm=OTHER_PSK + SHARED)


def finder(sessions):
    """What the remote bridge provides: the pending session for a (kid, handshake id), if any."""
    return lambda kid, hid: sessions.get(kid) if hid == HID else None


KEYS = finder({KID: SESSION})
METADATA = {"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
BODY = '{"model":"gpt-6-astra","input":"héllo wörld ✓ 日本語"}'.encode("utf-8")


def sealed(body=BODY, metadata=METADATA):
    return protocol.seal_request(SESSION, RID, TS, metadata, body)


def mutated(**changes):
    """A valid envelope with some outer fields replaced, serialised compactly."""
    envelope = json.loads(sealed())
    envelope.update(changes)
    return ref.dump(envelope)


# --- round trip -----------------------------------------------------------------------

@pytest.mark.parametrize("body", [BODY, b"", bytes(range(256)) * 16, b"\x00" * 1000])
def test_body_survives_round_trip_byte_for_byte(body):
    opened = protocol.open_request(sealed(body=body), KEYS)
    assert opened.body == body


def test_metadata_survives_round_trip():
    assert protocol.open_request(sealed(), KEYS).metadata == METADATA


def test_opened_request_reports_kid_rid_and_timestamp():
    opened = protocol.open_request(sealed(), KEYS)
    assert (opened.kid, opened.hid, opened.rid, opened.ts) == (KID, HID, RID, TS)
    assert opened.session == SESSION


def test_sealing_twice_gives_different_ciphertext():
    assert sealed() != sealed()


# --- wire format ----------------------------------------------------------------------

def test_envelope_is_json_with_exactly_the_specified_fields():
    envelope = json.loads(sealed())
    assert set(envelope) == {"v", "kid", "hid", "rid", "ts", "header", "data"}
    assert (envelope["v"], envelope["kid"], envelope["ts"]) == (2, KID, TS)
    assert ref.unb64(envelope["hid"]) == HID
    assert ref.unb64(envelope["rid"]) == RID
    assert len(ref.unb64(envelope["header"])) == 24


def test_binary_fields_are_base64url_without_padding():
    envelope = json.loads(sealed())
    for field in ("rid", "header", "data"):
        assert "=" not in envelope[field] and "+" not in envelope[field] and "/" not in envelope[field]


def test_envelope_opens_with_the_independent_reference_as_one_final_record():
    plaintext, tag = ref.open_request(IKM, sealed())
    metadata_bytes = plaintext[4:4 + struct.unpack(">I", plaintext[:4])[0]]
    assert tag == ref.TAG_FINAL
    assert json.loads(metadata_bytes) == METADATA
    assert plaintext[4 + len(metadata_bytes):] == BODY


def test_envelope_built_by_the_independent_reference_opens():
    metadata_bytes = json.dumps(METADATA).encode()
    envelope = ref.seal_request(IKM, KID, HID, RID, TS, ref.request_plaintext(metadata_bytes, BODY))
    opened = protocol.open_request(ref.dump(envelope), KEYS)
    assert (opened.metadata, opened.body) == (METADATA, BODY)


def test_prompt_text_is_not_visible_in_the_envelope():
    canary = b"CANARY-7f3a9c-unique-prompt-text"
    envelope_bytes = sealed(body=canary * 4)
    assert canary not in envelope_bytes
    assert canary not in ref.unb64(json.loads(envelope_bytes)["data"])


# --- authentication and tampering -----------------------------------------------------

def test_wrong_key_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(sealed(), finder({KID: OTHER_SESSION}))


def test_unknown_kid_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(sealed(), finder({"someone-else": SESSION}))


def test_unknown_or_expired_handshake_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(sealed(), lambda kid, hid: None)


def test_substituted_handshake_id_is_rejected_even_when_it_maps_to_the_same_session():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(hid=ref.b64(bytes(32))), lambda kid, hid: SESSION)


@pytest.mark.parametrize("length", [31, 33])
def test_handshake_id_of_wrong_length_is_rejected(length):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(hid=ref.b64(bytes(length))), lambda kid, hid: SESSION)


def test_finding_the_session_does_not_consume_it():
    # The bridge discards a session only after its envelope has authenticated, so a forged
    # envelope naming a pending handshake cannot spoil it for the real request.
    seen = []
    protocol.open_request(sealed(), lambda kid, hid: seen.append((kid, hid)) or SESSION)
    assert seen == [(KID, HID)]


def test_substituted_kid_is_rejected_even_when_it_maps_to_the_same_key():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(kid="poc-2"), finder({KID: SESSION, "poc-2": SESSION}))


def test_changed_timestamp_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(ts=TS + 1), KEYS)


def test_changed_request_id_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(rid=ref.b64(bytes(32))), KEYS)


@pytest.mark.parametrize("field", ["header", "data"])
@pytest.mark.parametrize("position", [0, -1])
def test_flipped_bit_in_header_or_ciphertext_is_rejected(field, position):
    raw = bytearray(ref.unb64(json.loads(sealed())[field]))
    raw[position] ^= 0x01
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(**{field: ref.b64(bytes(raw))}), KEYS)


def test_truncated_ciphertext_is_rejected():
    raw = ref.unb64(json.loads(sealed())["data"])
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(data=ref.b64(raw[:-1])), KEYS)


def test_request_that_is_not_a_final_record_is_rejected():
    plaintext = ref.request_plaintext(json.dumps(METADATA).encode(), BODY)
    envelope = ref.seal_request(IKM, KID, HID, RID, TS, plaintext, tag=ref.TAG_MESSAGE)
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(ref.dump(envelope), KEYS)


# --- strict outer parsing -------------------------------------------------------------

def test_duplicate_json_keys_are_rejected():
    text = sealed().decode()
    duplicated = text[:-1] + ',"v":2}'
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(duplicated.encode(), KEYS)


def test_unknown_field_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(url="https://example.com"), KEYS)


@pytest.mark.parametrize("field", ["v", "kid", "hid", "rid", "ts", "header", "data"])
def test_missing_field_is_rejected(field):
    envelope = json.loads(sealed())
    del envelope[field]
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(ref.dump(envelope), KEYS)


@pytest.mark.parametrize("version", [0, 1, 3, "2", 2.0, True, None])
def test_unsupported_or_mistyped_version_is_rejected(version):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(v=version), KEYS)


@pytest.mark.parametrize("ts", ["1800000000", 1.8e9, True, None, -1, 2**64])
def test_mistyped_or_out_of_range_timestamp_is_rejected(ts):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(ts=ts), KEYS)


@pytest.mark.parametrize("kid", ["", "a" * 65, "has space", 5, None])
def test_invalid_kid_is_rejected(kid):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(kid=kid), finder({KID: SESSION, "": SESSION, "a" * 65: SESSION, "has space": SESSION}))


@pytest.mark.parametrize("field", ["rid", "header", "data"])
def test_padded_base64_is_rejected(field):
    value = json.loads(sealed())[field]
    padded = value + "=" * (-len(value) % 4 or 4)
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(**{field: padded}), KEYS)


@pytest.mark.parametrize("bad", ["not base64!", "abc+/def", "ab cd", "é", 5, None])
def test_invalid_base64_is_rejected(bad):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(data=bad), KEYS)


def test_non_canonical_base64_is_rejected():
    # 43 characters encode 32 bytes; the last character carries two unused bits that must be zero.
    canonical = ref.b64(RID)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    non_canonical = canonical[:-1] + alphabet[alphabet.index(canonical[-1]) | 1]
    assert non_canonical != canonical and ref.unb64(non_canonical) == RID
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(rid=non_canonical), KEYS)


@pytest.mark.parametrize("length", [31, 33])
def test_request_id_of_wrong_length_is_rejected(length):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(rid=ref.b64(bytes(length))), KEYS)


@pytest.mark.parametrize("length", [23, 25])
def test_stream_header_of_wrong_length_is_rejected(length):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(mutated(header=ref.b64(bytes(length))), KEYS)


@pytest.mark.parametrize("raw", [b"", b"[]", b"null", b'"text"', b"{", b"\xff\xfe", b'{"v":2} trailing'])
def test_envelope_that_is_not_a_single_json_object_is_rejected(raw):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(raw, KEYS)


# --- size limits ----------------------------------------------------------------------

def test_metadata_larger_than_8_kib_is_refused_when_sealing():
    with pytest.raises(protocol.ProtocolError):
        sealed(metadata={"headers": {"x": "a" * 8192}})


def test_body_larger_than_8_mib_is_refused_when_sealing():
    with pytest.raises(protocol.ProtocolError):
        sealed(body=bytes(8 * 1024 * 1024 + 1))


def test_body_of_exactly_8_mib_round_trips():
    body = bytes(8 * 1024 * 1024)
    assert protocol.open_request(sealed(body=body), KEYS).body == body


def test_outer_request_larger_than_12_mib_is_rejected_before_parsing():
    with pytest.raises(protocol.ProtocolError, match="too large"):
        protocol.open_request(b" " * (12 * 1024 * 1024 + 1), KEYS)


def test_authenticated_metadata_larger_than_8_kib_is_rejected():
    plaintext = ref.request_plaintext(json.dumps({"pad": "a" * 8192}).encode(), BODY)
    envelope = ref.seal_request(IKM, KID, HID, RID, TS, plaintext)
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(ref.dump(envelope), KEYS)


def test_authenticated_body_larger_than_8_mib_is_rejected():
    plaintext = ref.request_plaintext(b"{}", bytes(8 * 1024 * 1024 + 1))
    envelope = ref.seal_request(IKM, KID, HID, RID, TS, plaintext)
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(ref.dump(envelope), KEYS)


@pytest.mark.parametrize("plaintext", [
    b"",                                    # no length prefix
    b"\x00\x00",                            # short length prefix
    struct.pack(">I", 50) + b"{}",          # declared length runs past the end
    struct.pack(">I", 2) + b"[]",           # metadata is not an object
    struct.pack(">I", 3) + b"{x}",          # metadata is not JSON
    struct.pack(">I", 2) + b"\xff\xfe",     # metadata is not UTF-8
])
def test_malformed_authenticated_plaintext_is_rejected(plaintext):
    envelope = ref.seal_request(IKM, KID, HID, RID, TS, plaintext)
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(ref.dump(envelope), KEYS)
