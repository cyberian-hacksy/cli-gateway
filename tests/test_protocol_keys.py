"""Key derivation and authenticated context, checked against the specification directly."""
import hashlib
import hmac
import struct

import pytest

from cgw import protocol

PSK = bytes(range(32))
SHARED = bytes(range(64, 96))
KID = "poc-1"
HID = bytes(range(200, 232))
RID = bytes(range(100, 132))
TS = 1_800_000_000
SESSION = protocol.Session(kid=KID, hid=HID, ikm=PSK + SHARED)


def rfc5869_hkdf_sha256(ikm, salt, info, length=32):
    """Independent HKDF-SHA256 (RFC 5869), so the test does not trust the library call."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def test_request_key_derives_from_the_psk_and_the_x25519_secret_together():
    expected = rfc5869_hkdf_sha256(PSK + SHARED, RID, b"cli-gateway/v3/request")
    assert protocol.derive_key(SESSION, RID, protocol.REQUEST) == expected


def test_response_key_uses_its_own_info_string():
    expected = rfc5869_hkdf_sha256(PSK + SHARED, RID, b"cli-gateway/v3/response")
    assert protocol.derive_key(SESSION, RID, protocol.RESPONSE) == expected


def test_request_and_response_keys_differ():
    assert protocol.derive_key(SESSION, RID, protocol.REQUEST) != protocol.derive_key(SESSION, RID, protocol.RESPONSE)


def test_keys_differ_per_request_id():
    assert protocol.derive_key(SESSION, RID, protocol.REQUEST) != protocol.derive_key(SESSION, bytes(32), protocol.REQUEST)


def test_the_psk_alone_does_not_determine_the_keys():
    # The point of the key exchange: two sessions with the same PSK share no keys.
    other = protocol.Session(kid=KID, hid=HID, ikm=PSK + bytes(range(1, 33)))
    assert protocol.derive_key(SESSION, RID, protocol.REQUEST) != protocol.derive_key(other, RID, protocol.REQUEST)


@pytest.mark.parametrize("bad_rid", [b"", bytes(31), bytes(33)])
def test_derive_key_rejects_rid_that_is_not_32_bytes(bad_rid):
    with pytest.raises(protocol.ProtocolError):
        protocol.derive_key(SESSION, bad_rid, protocol.REQUEST)


def test_derive_key_rejects_unknown_direction():
    with pytest.raises(protocol.ProtocolError):
        protocol.derive_key(SESSION, RID, 2)


@pytest.mark.parametrize("ikm", [b"", bytes(32), bytes(63), bytes(65)])
def test_session_requires_64_bytes_of_key_material(ikm):
    with pytest.raises(protocol.ProtocolError):
        protocol.Session(kid=KID, hid=HID, ikm=ikm)


@pytest.mark.parametrize("hid", [b"", bytes(31), bytes(33)])
def test_session_requires_a_32_byte_handshake_id(hid):
    with pytest.raises(protocol.ProtocolError):
        protocol.Session(kid=KID, hid=hid, ikm=PSK + SHARED)


def test_session_does_not_show_its_key_material():
    assert PSK.hex() not in repr(SESSION) and repr(PSK) not in repr(SESSION) and "ikm" not in repr(SESSION)


def test_aad_layout_matches_the_specification():
    aad = protocol.build_aad(HID, RID, TS, protocol.RESPONSE, 7)
    assert aad == (
        b"CGP3"
        + HID
        + RID
        + struct.pack(">Q", TS)
        + b"\x01"
        + struct.pack(">Q", 7)
    )


def test_aad_request_direction_is_a_zero_byte():
    aad = protocol.build_aad(HID, RID, TS, protocol.REQUEST, 0)
    assert aad == b"CGP3" + HID + RID + struct.pack(">Q", TS) + b"\x00" + bytes(8)


@pytest.mark.parametrize("bad_kid", ["", "a" * 65, "has space", "dot.ted", "ünï", "slash/"])
def test_session_rejects_invalid_internal_label(bad_kid):
    with pytest.raises(protocol.ProtocolError):
        protocol.Session(bad_kid, HID, PSK + SHARED)


@pytest.mark.parametrize("bad_ts", [-1, 2**64])
def test_aad_rejects_timestamp_outside_u64(bad_ts):
    with pytest.raises(protocol.ProtocolError):
        protocol.build_aad(HID, RID, bad_ts, protocol.REQUEST, 0)


@pytest.mark.parametrize("hid", [b"", bytes(31), bytes(33)])
def test_aad_rejects_handshake_id_of_wrong_length(hid):
    with pytest.raises(protocol.ProtocolError):
        protocol.build_aad(hid, RID, TS, protocol.REQUEST, 0)
