"""Admission tag: proof of holding the key, checked before the gateway commits any resources."""
import pytest

import wire_reference as ref
from cgw import protocol

PSK = bytes(range(32))
OTHER_PSK = bytes(range(1, 33))
KID = "poc-1"
RID = bytes(range(100, 132))
TS = 1_800_000_000
LENGTH = 4321
KEYS = {KID: protocol.derive_admission_key(PSK)}


def tag(psk=PSK, rid=RID, ts=TS, length=LENGTH):
    return protocol.seal_admission(protocol.derive_admission_key(psk), rid, ts, length)


def parts(**changes):
    """A valid tag with some of its four dot-separated parts replaced."""
    names = ["version", "ts", "rid", "mac"]
    values = dict(zip(names, tag().split(".")))
    values.update(changes)
    return ".".join(values[name] for name in names)


def test_tag_matches_the_independent_reference_exactly():
    assert tag() == ref.admission(PSK, KID, RID, TS, LENGTH)


def test_valid_tag_opens_to_its_session_identity():
    admitted = protocol.open_admission(tag(), KEYS, LENGTH)
    assert (admitted.kid, admitted.rid, admitted.ts) == (KID, RID, TS)


def test_tag_built_by_the_reference_opens():
    assert protocol.open_admission(ref.admission(PSK, KID, RID, TS, LENGTH), KEYS, LENGTH).rid == RID


def test_tag_reveals_no_key_material():
    value = tag()
    assert ref.b64(PSK) not in value and PSK.hex() not in value


def test_tag_is_deterministic_for_one_request_and_differs_between_requests():
    assert tag() == tag()
    assert tag() != tag(rid=bytes(32)) and tag() != tag(ts=TS + 1) and tag() != tag(length=LENGTH + 1)


def test_wrong_key_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(tag(), {KID: protocol.derive_admission_key(OTHER_PSK)}, LENGTH)


def test_identity_is_the_label_of_the_matching_key():
    assert protocol.open_admission(tag(), {"renamed": protocol.derive_admission_key(PSK)}, LENGTH).kid == "renamed"


def test_tag_for_another_content_length_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(tag(), KEYS, LENGTH + 1)


def test_duplicate_matching_keys_are_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(tag(), {"one": KEYS[KID], "two": KEYS[KID]}, LENGTH)


def test_changed_timestamp_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(parts(ts=str(TS + 1)), KEYS, LENGTH)


def test_changed_request_id_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(parts(rid=ref.b64(bytes(32))), KEYS, LENGTH)


def test_flipped_bit_in_the_mac_is_rejected():
    mac = bytearray(ref.unb64(tag().split(".")[3]))
    mac[0] ^= 0x01
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(parts(mac=ref.b64(bytes(mac))), KEYS, LENGTH)


MALFORMED = {
    "none": lambda: None, "number": lambda: 5, "empty": lambda: "", "version only": lambda: "1",
    "two parts": lambda: "1.poc-1", "extra part": lambda: tag() + ".extra", "other version": lambda: "1" + tag()[1:],
    "leading dot": lambda: "." + tag(), "trailing padding": lambda: tag() + "=", "too long": lambda: "x" * 600,
}


@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_malformed_tag_is_rejected(case):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(MALFORMED[case](), KEYS, LENGTH)


@pytest.mark.parametrize("changes", [
    {"ts": "0" + str(TS)}, {"ts": "+" + str(TS)}, {"ts": "1e9"}, {"ts": "-1"}, {"ts": ""}, {"ts": str(2**64)},
    {"rid": ref.b64(bytes(31))}, {"rid": ref.b64(bytes(33))}, {"rid": "not base64!"},
    {"mac": ref.b64(bytes(31))}, {"mac": ref.b64(bytes(33))}, {"mac": ""},
], ids=lambda changes: "%s=%r" % next(iter(changes.items())))
def test_tag_with_a_malformed_part_is_rejected(changes):
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(parts(**changes), KEYS, LENGTH)


def test_padded_base64_in_the_tag_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(parts(rid=ref.b64(RID) + "="), KEYS, LENGTH)


@pytest.mark.parametrize("arguments", [
    {"psk": bytes(31)}, {"rid": bytes(31)}, {"ts": -1}, {"length": -1}, {"length": 2**64},
])
def test_sealing_refuses_invalid_inputs(arguments):
    with pytest.raises(protocol.ProtocolError):
        tag(**arguments)


def test_admission_key_is_separate_from_the_request_and_response_keys():
    # A tag must never be usable as, or derived from, the keys that encrypt traffic.
    mac = ref.unb64(tag().split(".")[3])
    session = protocol.Session(kid=KID, hid=RID, ikm=PSK + bytes(32))
    assert mac not in (protocol.derive_key(session, RID, protocol.REQUEST), protocol.derive_key(session, RID, protocol.RESPONSE))
    forged_with_request_key = ref.admission(PSK, KID, RID, TS, LENGTH).rsplit(".", 1)[0] + "." + ref.b64(
        __import__("hmac").new(protocol.derive_key(session, RID, protocol.REQUEST), b"CGA2", "sha256").digest())
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(forged_with_request_key, KEYS, LENGTH)
