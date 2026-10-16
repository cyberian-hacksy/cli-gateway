"""Independent construction of the wire format, written from the specification.

Deliberately shares no code with cgw.protocol: it uses raw libsodium bindings (including
its X25519), hmac and struct, while the implementation uses the cryptography library for
X25519 and HKDF. Tests use it to check that the implementation speaks the specified
format, and to forge inputs the implementation itself refuses to produce.
"""
import base64
import hashlib
import hmac
import json
import math
import struct

from nacl import bindings as sodium

TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
REQUEST_INFO = b"cli-gateway/v3/request"
RESPONSE_INFO = b"cli-gateway/v3/response"
HANDSHAKE_INFO = b"cli-gateway/v3/handshake"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hkdf(ikm, salt, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def dump(envelope):
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def padme(length):
    if length <= 8:
        return length
    exponent = math.floor(math.log2(length))
    significant = math.floor(math.log2(exponent)) + 1
    step = 2 ** (exponent - significant)
    return math.ceil(length / step) * step


def pad(data, size):
    return data + b"\x80" + b"\0" * (size - len(data) - 1)


def unpad(data):
    index = len(data) - 1
    while index >= 0 and data[index] == 0:
        index -= 1
    assert index >= 0 and data[index] == 128
    return data[:index]


# --- handshake ------------------------------------------------------------------------

def x25519_public(private):
    return sodium.crypto_scalarmult_base(private)


def x25519(private, public):
    return sodium.crypto_scalarmult(private, public)


def handshake_mac(psk, kid, hid, ts, *parts, role):
    key = hkdf(psk, hid, HANDSHAKE_INFO)
    return hmac.new(key, role + hid + struct.pack(">Q", ts) + b"".join(parts), hashlib.sha256).digest()


def client_hello(psk, kid, hid, ts, private):
    """The client's handshake message as a dict, so tests can mutate it before serialising."""
    epk = x25519_public(private)
    return {"v": 3, "hid": b64(hid), "ts": ts, "epk": b64(epk),
            "mac": b64(handshake_mac(psk, kid, hid, ts, epk, role=b"CGH3-C"))}


def server_hello(psk, kid, hid, ts, epk, private):
    spk = x25519_public(private)
    return {"v": 3, "spk": b64(spk), "mac": b64(handshake_mac(psk, kid, hid, ts, epk, spk, role=b"CGH3-S"))}


def session_ikm(psk, shared):
    """Input keying material for one request: the pre-shared key followed by the X25519 secret."""
    return psk + shared


# --- admission tag (no client identifier) -----------------------------------------

def admission(psk, kid, rid, ts, content_length):
    """The admission header value, built from the specification alone."""
    key = hkdf(psk, b"", b"cli-gateway/v3/admission")
    message = b"CGA2" + rid + struct.pack(">Q", ts) + struct.pack(">Q", content_length)
    return "2.%d.%s.%s" % (ts, b64(rid), b64(hmac.new(key, message, hashlib.sha256).digest()))


# --- records --------------------------------------------------------------------------

def aad(kid, hid, rid, ts, direction, sequence):
    return (b"CGP3" + hid + rid + struct.pack(">Q", ts) + bytes([direction])
            + struct.pack(">Q", sequence))


def request_plaintext(metadata_bytes, body):
    return struct.pack(">I", len(metadata_bytes)) + metadata_bytes + body


def seal_request(ikm, kid, hid, rid, ts, plaintext, tag=TAG_FINAL, *, padded=False):
    """Returns the envelope as a dict so tests can mutate it before serialising."""
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, hkdf(ikm, rid, REQUEST_INFO))
    if not padded:
        plaintext = pad(plaintext, padme(max(len(plaintext) + 1, 4096)))
    data = sodium.crypto_secretstream_xchacha20poly1305_push(state, plaintext, aad(kid, hid, rid, ts, 0, 0), tag)
    return {"v": 3, "hid": b64(hid), "rid": b64(rid), "ts": ts,
            "header": b64(header), "data": b64(data)}


def open_request(ikm, envelope_bytes):
    """Returns (plaintext, tag) or raises if authentication fails."""
    envelope = json.loads(envelope_bytes)
    hid, rid = unb64(envelope["hid"]), unb64(envelope["rid"])
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(
        state, unb64(envelope["header"]), hkdf(ikm, rid, REQUEST_INFO))
    plaintext, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(
        state, unb64(envelope["data"]), aad(None, hid, rid, envelope["ts"], 0, 0))
    return unpad(plaintext), tag


class ResponseWriter:
    """Reference sender for the response stream."""

    def __init__(self, ikm, kid, hid, rid, ts, info=RESPONSE_INFO):
        self.kid, self.hid, self.rid, self.ts = kid, hid, rid, ts
        self.state = sodium.crypto_secretstream_xchacha20poly1305_state()
        self.header = sodium.crypto_secretstream_xchacha20poly1305_init_push(self.state, hkdf(ikm, rid, info))
        self.sequence = 0

    def header_line(self):
        return dump({"v": 3, "header": b64(self.header)}) + b"\n"

    def record(self, record_type, payload=b"", tag=TAG_MESSAGE, wire_seq=None):
        data = sodium.crypto_secretstream_xchacha20poly1305_push(
            self.state, pad(bytes([record_type]) + payload, 512 * math.ceil((len(payload) + 2) / 512)),
            aad(self.kid, self.hid, self.rid, self.ts, 1, self.sequence), tag)
        line = dump({"seq": self.sequence if wire_seq is None else wire_seq, "data": b64(data)}) + b"\n"
        self.sequence += 1
        return line


def read_response(ikm, kid, hid, rid, ts, lines):
    """Reference receiver. Returns [(record_type, payload, tag)] or raises on bad authentication."""
    header = unb64(json.loads(lines[0])["header"])
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, hkdf(ikm, rid, RESPONSE_INFO))
    records = []
    for sequence, line in enumerate(lines[1:]):
        entry = json.loads(line)
        assert entry["seq"] == sequence
        plaintext, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(
            state, unb64(entry["data"]), aad(kid, hid, rid, ts, 1, sequence))
        plaintext = unpad(plaintext)
        records.append((plaintext[0], plaintext[1:], tag))
    return records
