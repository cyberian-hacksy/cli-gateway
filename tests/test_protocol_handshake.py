"""X25519 handshake: a fresh shared secret per request, authenticated by the pre-shared key."""
import json

import pytest

import wire_reference as ref
from cgw import protocol

PSK = bytes(range(32))
OTHER_PSK = bytes(range(1, 33))
KID = "poc-1"
HID = bytes(range(200, 232))
TS = 1_800_000_000
CLIENT_PRIVATE = bytes(range(40, 72))
SERVER_PRIVATE = bytes(range(80, 112))
KEYS = {KID: PSK}


def client(private=CLIENT_PRIVATE, psk=PSK, kid=KID, hid=HID, ts=TS):
    return protocol.ClientHandshake(psk, kid, ts, hid=hid, private=private)


def reference_hello(**changes):
    hello = ref.client_hello(PSK, KID, HID, TS, CLIENT_PRIVATE)
    hello.update(changes)
    return ref.dump(hello)


def reference_reply(epk=None, psk=PSK, **changes):
    epk = epk or ref.x25519_public(CLIENT_PRIVATE)
    reply = ref.server_hello(psk, KID, HID, TS, epk, SERVER_PRIVATE)
    reply.update(changes)
    return ref.dump(reply)


def expected_ikm(psk=PSK):
    return psk + ref.x25519(CLIENT_PRIVATE, ref.x25519_public(SERVER_PRIVATE))


# --- the client's message -------------------------------------------------------------

def test_client_message_matches_the_independent_reference_exactly():
    assert client().message() == reference_hello()


def test_client_message_has_exactly_the_specified_fields():
    message = json.loads(client().message())
    assert set(message) == {"v", "hid", "ts", "epk", "mac"}
    assert (message["v"], message["ts"]) == (3, TS)
    assert ref.unb64(message["hid"]) == HID and len(ref.unb64(message["epk"])) == 32


def test_each_handshake_uses_a_fresh_key_pair_and_id():
    first, second = protocol.ClientHandshake(PSK, KID, TS), protocol.ClientHandshake(PSK, KID, TS)
    one, two = json.loads(first.message()), json.loads(second.message())
    assert one["epk"] != two["epk"] and one["hid"] != two["hid"]
    assert len(first.hid) == len(second.hid) == 32


# --- the server's answer --------------------------------------------------------------

def test_server_accepts_the_reference_message_and_reaches_the_same_secret():
    answered = protocol.answer_handshake(reference_hello(), KID, PSK)
    reply = json.loads(answered.reply)
    shared = ref.x25519(CLIENT_PRIVATE, ref.unb64(reply["spk"]))
    assert answered.session.ikm == PSK + shared
    assert (answered.session.kid, answered.session.hid, answered.ts) == (KID, HID, TS)


def test_server_reply_is_authenticated_over_both_public_keys():
    answered = protocol.answer_handshake(reference_hello(), KID, PSK)
    reply = json.loads(answered.reply)
    assert set(reply) == {"v", "spk", "mac"} and reply["v"] == 3
    expected = ref.handshake_mac(PSK, KID, HID, TS, ref.x25519_public(CLIENT_PRIVATE), ref.unb64(reply["spk"]),
                                 role=b"CGH3-S")
    assert ref.unb64(reply["mac"]) == expected


def test_server_uses_a_fresh_key_pair_each_time():
    first = json.loads(protocol.answer_handshake(reference_hello(), KID, PSK).reply)["spk"]
    second = json.loads(protocol.answer_handshake(reference_hello(), KID, PSK).reply)["spk"]
    assert first != second


def test_wrong_key_is_rejected_by_the_server():
    with pytest.raises(protocol.ProtocolError):
        protocol.answer_handshake(reference_hello(), KID, OTHER_PSK)


def test_server_uses_the_admitted_internal_label():
    answered = protocol.answer_handshake(reference_hello(), "another-label", PSK)
    assert answered.session.kid == "another-label"


@pytest.mark.parametrize("field,value", [
    ("epk", ref.b64(ref.x25519_public(bytes(range(7, 39))))),
    ("ts", TS + 1),
    ("hid", ref.b64(bytes(32))),
    ("kid", "poc-2"),
])
def test_tampered_client_message_is_rejected(field, value):
    with pytest.raises(protocol.ProtocolError):
        protocol.answer_handshake(reference_hello(**{field: value}), KID, PSK)


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"not json",
    lambda: reference_hello(v=1), lambda: reference_hello(v="2"), lambda: reference_hello(extra=1),
    lambda: reference_hello(epk=ref.b64(bytes(31))), lambda: reference_hello(hid=ref.b64(bytes(31))),
    lambda: reference_hello(mac=ref.b64(bytes(31))), lambda: reference_hello(ts=-1), lambda: reference_hello(ts=True),
    lambda: reference_hello(kid="bad kid"), lambda: reference_hello(epk=ref.b64(ref.x25519_public(CLIENT_PRIVATE)) + "="),
    lambda: reference_hello()[:-1] + b',"v":3}',
], ids=lambda raw: "callable" if callable(raw) else repr(raw))
def test_malformed_client_message_is_rejected(raw):
    with pytest.raises(protocol.ProtocolError):
        protocol.answer_handshake(raw() if callable(raw) else raw, KID, PSK)


def test_low_order_client_key_is_rejected():
    # An all-zero public key forces an all-zero shared secret; it must never be accepted,
    # even with a valid MAC from someone holding the PSK.
    zero = bytes(32)
    hello = ref.client_hello(PSK, KID, HID, TS, CLIENT_PRIVATE)
    hello["epk"] = ref.b64(zero)
    hello["mac"] = ref.b64(ref.handshake_mac(PSK, KID, HID, TS, zero, role=b"CGH3-C"))
    with pytest.raises(protocol.ProtocolError):
        protocol.answer_handshake(ref.dump(hello), KID, PSK)


# --- the client completing ------------------------------------------------------------

def test_client_completes_with_the_reference_reply():
    session = client().complete(reference_reply())
    assert session.ikm == expected_ikm()
    assert (session.kid, session.hid) == (KID, HID)


def test_both_ends_reach_the_same_session():
    handshake = protocol.ClientHandshake(PSK, KID, TS)
    answered = protocol.answer_handshake(handshake.message(), KID, PSK)
    assert handshake.complete(answered.reply) == answered.session


def test_reply_from_a_server_without_the_psk_is_rejected():
    # Someone in the middle substituting their own key pair cannot produce the MAC.
    with pytest.raises(protocol.ProtocolError):
        client().complete(reference_reply(psk=OTHER_PSK))


def test_reply_for_another_client_key_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        client().complete(reference_reply(epk=ref.x25519_public(bytes(range(7, 39)))))


def test_reply_with_a_substituted_server_key_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        client().complete(reference_reply(spk=ref.b64(ref.x25519_public(bytes(range(9, 41))))))


def test_low_order_server_key_is_rejected():
    zero = bytes(32)
    reply = {"v": 3, "spk": ref.b64(zero),
             "mac": ref.b64(ref.handshake_mac(PSK, KID, HID, TS, ref.x25519_public(CLIENT_PRIVATE), zero,
                                              role=b"CGH3-S"))}
    with pytest.raises(protocol.ProtocolError):
        client().complete(ref.dump(reply))


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"not json",
    lambda: reference_reply(v=1), lambda: reference_reply(extra=1), lambda: reference_reply(spk=ref.b64(bytes(31))),
    lambda: reference_reply(mac=ref.b64(bytes(31))), lambda: reference_reply()[:-1] + b',"v":3}',
], ids=lambda raw: "callable" if callable(raw) else repr(raw))
def test_malformed_reply_is_rejected(raw):
    with pytest.raises(protocol.ProtocolError):
        client().complete(raw() if callable(raw) else raw)


def test_a_handshake_completes_only_once_and_then_holds_no_private_key():
    handshake = client()
    handshake.complete(reference_reply())
    with pytest.raises(protocol.ProtocolError):
        handshake.complete(reference_reply())


def test_a_failed_completion_also_discards_the_private_key():
    handshake = client()
    with pytest.raises(protocol.ProtocolError):
        handshake.complete(reference_reply(psk=OTHER_PSK))
    with pytest.raises(protocol.ProtocolError):
        handshake.complete(reference_reply())


@pytest.mark.parametrize("arguments", [
    {"psk": bytes(31)}, {"kid": "bad kid"}, {"hid": bytes(31)}, {"ts": -1}, {"private": bytes(31)},
])
def test_client_handshake_refuses_invalid_inputs(arguments):
    with pytest.raises(protocol.ProtocolError):
        client(**arguments)
