"""Independent construction of the wire format, written from the specification.

Deliberately shares no code with cgw.protocol: it uses raw libsodium bindings, hmac and
struct. Tests use it to check that the implementation speaks the specified format, and
to forge inputs the implementation itself refuses to produce.
"""
import base64
import hashlib
import hmac
import json
import struct

from nacl import bindings as sodium

TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
REQUEST_INFO = b"codex-gateway-poc/v1/request"
RESPONSE_INFO = b"codex-gateway-poc/v1/response"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hkdf(psk, rid, info):
    prk = hmac.new(rid, psk, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def aad(kid, rid, ts, direction, sequence):
    return (b"CGP1" + struct.pack(">H", len(kid)) + kid.encode("ascii") + rid
            + struct.pack(">Q", ts) + bytes([direction]) + struct.pack(">Q", sequence))


def admission(psk, kid, rid, ts, content_length):
    """The admission header value, built from the specification alone."""
    prk = hmac.new(rid, psk, hashlib.sha256).digest()
    key = hmac.new(prk, b"codex-gateway-poc/v1/admission" + b"\x01", hashlib.sha256).digest()
    message = (b"CGA1" + struct.pack(">H", len(kid)) + kid.encode("ascii") + rid
               + struct.pack(">Q", ts) + struct.pack(">Q", content_length))
    return "1.%s.%d.%s.%s" % (kid, ts, b64(rid), b64(hmac.new(key, message, hashlib.sha256).digest()))


def request_plaintext(metadata_bytes, body):
    return struct.pack(">I", len(metadata_bytes)) + metadata_bytes + body


def seal_request(psk, kid, rid, ts, plaintext, tag=TAG_FINAL):
    """Returns the envelope as a dict so tests can mutate it before serialising."""
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, hkdf(psk, rid, REQUEST_INFO))
    data = sodium.crypto_secretstream_xchacha20poly1305_push(state, plaintext, aad(kid, rid, ts, 0, 0), tag)
    return {"v": 1, "kid": kid, "rid": b64(rid), "ts": ts, "header": b64(header), "data": b64(data)}


def dump(envelope):
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def open_request(psk, envelope_bytes):
    """Returns (plaintext, tag) or raises if authentication fails."""
    envelope = json.loads(envelope_bytes)
    rid = unb64(envelope["rid"])
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(
        state, unb64(envelope["header"]), hkdf(psk, rid, REQUEST_INFO))
    return sodium.crypto_secretstream_xchacha20poly1305_pull(
        state, unb64(envelope["data"]), aad(envelope["kid"], rid, envelope["ts"], 0, 0))


class ResponseWriter:
    """Reference sender for the response stream."""

    def __init__(self, psk, kid, rid, ts, info=RESPONSE_INFO):
        self.kid, self.rid, self.ts = kid, rid, ts
        self.state = sodium.crypto_secretstream_xchacha20poly1305_state()
        self.header = sodium.crypto_secretstream_xchacha20poly1305_init_push(self.state, hkdf(psk, rid, info))
        self.sequence = 0

    def header_line(self):
        return dump({"v": 1, "header": b64(self.header)}) + b"\n"

    def record(self, record_type, payload=b"", tag=TAG_MESSAGE, wire_seq=None):
        data = sodium.crypto_secretstream_xchacha20poly1305_push(
            self.state, bytes([record_type]) + payload,
            aad(self.kid, self.rid, self.ts, 1, self.sequence), tag)
        line = dump({"seq": self.sequence if wire_seq is None else wire_seq, "data": b64(data)}) + b"\n"
        self.sequence += 1
        return line


def read_response(psk, kid, rid, ts, lines):
    """Reference receiver. Returns [(record_type, payload, tag)] or raises on bad authentication."""
    header = unb64(json.loads(lines[0])["header"])
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, hkdf(psk, rid, RESPONSE_INFO))
    records = []
    for sequence, line in enumerate(lines[1:]):
        entry = json.loads(line)
        assert entry["seq"] == sequence
        plaintext, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(
            state, unb64(entry["data"]), aad(kid, rid, ts, 1, sequence))
        records.append((plaintext[0], plaintext[1:], tag))
    return records
