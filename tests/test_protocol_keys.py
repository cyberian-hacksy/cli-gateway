"""Key derivation and authenticated context, checked against the specification directly."""
import hashlib
import hmac
import struct

import pytest

from cgw import protocol

PSK = bytes(range(32))
RID = bytes(range(100, 132))
TS = 1_800_000_000


def rfc5869_hkdf_sha256(ikm, salt, info, length=32):
    """Independent HKDF-SHA256 (RFC 5869), so the test does not trust the library call."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def test_request_key_is_hkdf_sha256_of_psk_salted_by_rid():
    expected = rfc5869_hkdf_sha256(PSK, RID, b"codex-gateway-poc/v1/request")
    assert protocol.derive_key(PSK, RID, protocol.REQUEST) == expected


def test_response_key_uses_its_own_info_string():
    expected = rfc5869_hkdf_sha256(PSK, RID, b"codex-gateway-poc/v1/response")
    assert protocol.derive_key(PSK, RID, protocol.RESPONSE) == expected


def test_request_and_response_keys_differ():
    assert protocol.derive_key(PSK, RID, protocol.REQUEST) != protocol.derive_key(PSK, RID, protocol.RESPONSE)


def test_keys_differ_per_request_id():
    other_rid = bytes(32)
    assert protocol.derive_key(PSK, RID, protocol.REQUEST) != protocol.derive_key(PSK, other_rid, protocol.REQUEST)


@pytest.mark.parametrize("bad_psk", [b"", bytes(31), bytes(33)])
def test_derive_key_rejects_psk_that_is_not_32_bytes(bad_psk):
    with pytest.raises(protocol.ProtocolError):
        protocol.derive_key(bad_psk, RID, protocol.REQUEST)


@pytest.mark.parametrize("bad_rid", [b"", bytes(31), bytes(33)])
def test_derive_key_rejects_rid_that_is_not_32_bytes(bad_rid):
    with pytest.raises(protocol.ProtocolError):
        protocol.derive_key(PSK, bad_rid, protocol.REQUEST)


def test_derive_key_rejects_unknown_direction():
    with pytest.raises(protocol.ProtocolError):
        protocol.derive_key(PSK, RID, 2)


def test_aad_layout_matches_the_specification():
    aad = protocol.build_aad("poc-1", RID, TS, protocol.RESPONSE, 7)
    assert aad == (
        b"CGP1"
        + b"\x00\x05" + b"poc-1"
        + RID
        + struct.pack(">Q", TS)
        + b"\x01"
        + struct.pack(">Q", 7)
    )


def test_aad_request_direction_is_a_zero_byte():
    aad = protocol.build_aad("k", RID, TS, protocol.REQUEST, 0)
    assert aad == b"CGP1" + b"\x00\x01k" + RID + struct.pack(">Q", TS) + b"\x00" + bytes(8)


@pytest.mark.parametrize("bad_kid", ["", "a" * 65, "has space", "dot.ted", "ünï", "slash/"])
def test_aad_rejects_kid_outside_the_allowed_alphabet_or_length(bad_kid):
    with pytest.raises(protocol.ProtocolError):
        protocol.build_aad(bad_kid, RID, TS, protocol.REQUEST, 0)


def test_aad_accepts_kid_of_maximum_length_and_full_alphabet():
    kid = ("Az09_-" * 11)[:64]
    assert protocol.build_aad(kid, RID, TS, protocol.REQUEST, 0)[4:6] == b"\x00\x40"


@pytest.mark.parametrize("bad_ts", [-1, 2**64])
def test_aad_rejects_timestamp_outside_u64(bad_ts):
    with pytest.raises(protocol.ProtocolError):
        protocol.build_aad("poc-1", RID, bad_ts, protocol.REQUEST, 0)
