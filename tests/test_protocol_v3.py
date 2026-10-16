"""v3 wire privacy properties and authenticated malformed encodings."""
import hashlib
import hmac
import json

import pytest
from nacl import bindings as sodium

from cgw import protocol
import wire_reference as ref

PSK = bytes(range(32))
HID, RID, TS = bytes(range(32, 64)), bytes(range(64, 96)), 1800000000
SESSION = protocol.Session("machine-label", HID, PSK + bytes(range(96, 128)))


def test_names_do_not_affect_handshake_or_keys():
    first = protocol.ClientHandshake(PSK, "short", TS, hid=HID, private=bytes(range(32)))
    second = protocol.ClientHandshake(PSK, "admin_a-much-longer-machine-name", TS, hid=HID, private=bytes(range(32)))
    assert first.message() == second.message()
    assert set(json.loads(first.message())) == {"v", "hid", "ts", "epk", "mac"}
    assert json.loads(first.message())["v"] == 3


@pytest.mark.parametrize("match", [0, 31, 63, None])
def test_admission_checks_every_key(monkeypatch, match):
    keys = {"machine-%d" % i: protocol.derive_admission_key(bytes([i + 1]) * 32) for i in range(64)}
    key = keys["machine-%d" % match] if match is not None else protocol.derive_admission_key(b"z" * 32)
    value = protocol.seal_admission(key, RID, TS, 1234)
    assert len(value.split(".")) == 4 and value.startswith("2.")
    new, compare = hmac.new, hmac.compare_digest
    calls = {"hmac": 0, "compare": 0}
    def counted_new(*args, **kwargs):
        calls["hmac"] += 1
        return new(*args, **kwargs)
    def counted_compare(*args):
        calls["compare"] += 1
        return compare(*args)
    monkeypatch.setattr(hmac, "new", counted_new)
    monkeypatch.setattr(hmac, "compare_digest", counted_compare)
    if match is None:
        with pytest.raises(protocol.ProtocolError):
            protocol.open_admission(value, keys, 1234)
    else:
        assert protocol.open_admission(value, keys, 1234).kid == "machine-%d" % match
    assert calls == {"hmac": 64, "compare": 64}


@pytest.mark.parametrize("match", [31, None])
def test_prepared_admission_keys_check_every_key_without_rekeying(monkeypatch, match):
    raw = {"machine-%d" % i: protocol.derive_admission_key(bytes([i + 1]) * 32) for i in range(64)}
    prepared = protocol.AdmissionKeys(raw)
    key = raw["machine-31"] if match is not None else protocol.derive_admission_key(b"z" * 32)
    value = protocol.seal_admission(key, RID, TS, 1234)
    new, compare = hmac.new, hmac.compare_digest
    calls = {"hmac": 0, "compare": 0}
    def counted_new(*args, **kwargs):
        calls["hmac"] += 1
        return new(*args, **kwargs)
    def counted_compare(*args):
        calls["compare"] += 1
        return compare(*args)
    monkeypatch.setattr(hmac, "new", counted_new)
    monkeypatch.setattr(hmac, "compare_digest", counted_compare)
    if match is None:
        with pytest.raises(protocol.ProtocolError):
            protocol.open_admission(value, prepared, 1234)
    else:
        assert protocol.open_admission(value, prepared, 1234).kid == "machine-31"
    assert calls == {"hmac": 0, "compare": 64}


def test_admission_derivation_and_input_are_exact():
    key = protocol.derive_admission_key(PSK)
    assert key == ref.hkdf(PSK, b"", b"cli-gateway/v3/admission")
    message = b"CGA2" + RID + TS.to_bytes(8, "big") + (1234).to_bytes(8, "big")
    tag = protocol.seal_admission(key, RID, TS, 1234)
    assert tag == "2.%d.%s.%s" % (TS, ref.b64(RID), ref.b64(hmac.new(key, message, hashlib.sha256).digest()))
    with pytest.raises(protocol.ProtocolError):
        protocol.open_admission(tag, {"one": key, "two": key}, 1234)


def test_request_owner_must_match_admission():
    envelope = protocol.seal_request(SESSION, RID, TS, {"method": "GET"}, b"body")
    assert set(json.loads(envelope)) == {"v", "hid", "rid", "ts", "header", "data"}
    for admitted in (protocol.Admission("someone-else", RID, TS),
                     protocol.Admission(SESSION.kid, bytes(32), TS),
                     protocol.Admission(SESSION.kid, RID, TS + 1)):
        with pytest.raises(protocol.ProtocolError):
            protocol.open_request(envelope, lambda hid: SESSION, admitted=admitted)


def test_small_record_types_have_equal_ciphertext_sizes():
    writer = protocol.ResponseSealer(SESSION, RID, TS)
    lines = [writer.heartbeat(), writer.meta(200, {}), writer.data(b"a" * 510), writer.end()]
    other = protocol.ResponseSealer(SESSION, RID, TS)
    lines.append(other.error({"code": "upstream_failed"}))
    assert [len(ref.unb64(json.loads(line)["data"])) for line in lines] == [529] * 5
    maximum = protocol.ResponseSealer(SESSION, RID, TS)
    maximum.meta(200, {})
    line = maximum.data(b"x" * 16384)
    assert len(ref.unb64(json.loads(line)["data"])) == 16913
    assert len(line) < 24 * 1024


@pytest.mark.parametrize("raw", [b"\x03", b"\x03" + b"\0" * 511,
                              b"\x03\x80" + b"\0" * 1022, b"\x03\x80" + b"\0" * 509 + b"\x01"])
def test_authenticated_bad_response_padding_permanently_fails(raw):
    writer = ref.ResponseWriter(SESSION.ikm, SESSION.kid, HID, RID, TS)
    opener = protocol.ResponseOpener(SESSION, RID, TS)
    opener.open_header(writer.header_line())
    data = sodium.crypto_secretstream_xchacha20poly1305_push(
        writer.state, raw, ref.aad(SESSION.kid, HID, RID, TS, 1, 0), ref.TAG_MESSAGE)
    line = ref.dump({"seq": 0, "data": ref.b64(data)})
    with pytest.raises(protocol.ProtocolError):
        opener.open_record(line)
    with pytest.raises(protocol.ProtocolError, match="already failed"):
        opener.open_record(writer.record(protocol.HEARTBEAT))


def test_largest_request_fits_outer_limit():
    metadata = {"x": "a" * (8192 - 8)}
    envelope = protocol.seal_request(SESSION, RID, TS, metadata, b"b" * (8 * 1024 * 1024))
    assert len(envelope) < 12 * 1024 * 1024
    assert len(ref.unb64(json.loads(envelope)["data"])) == 8650752 + 17


@pytest.mark.parametrize("encoding", ["missing", "extra", "short", "tail"])
def test_authenticated_bad_request_padding_is_rejected(encoding):
    raw = ref.request_plaintext(b"{}", b"body")
    padded = ref.pad(raw, 4096)
    bad = {"missing": raw, "extra": padded + bytes(256), "short": padded[:-1],
           "tail": padded[:-1] + b"\x01"}[encoding]
    envelope = ref.dump(ref.seal_request(SESSION.ikm, SESSION.kid, HID, RID, TS, bad, padded=True))
    with pytest.raises(protocol.ProtocolError):
        protocol.open_request(envelope, lambda hid: SESSION, admitted=protocol.Admission(SESSION.kid, RID, TS))
