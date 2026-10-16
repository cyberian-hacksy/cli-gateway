"""Wire protocol for the encrypted gateway: handshake, envelope, AAD, key derivation, framing.

Pure functions and small state objects: bytes in, bytes out, no network and no disk.
Both bridges import this module so the two ends cannot drift apart.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as sodium
from nacl import exceptions as sodium_errors

VERSION = 3
MAX_KEYS = 64
REQUEST = 0
RESPONSE = 1

# Response record types: the first byte of every decrypted response record.
META = 0x01
DATA = 0x02
HEARTBEAT = 0x03
END = 0x04
ERROR = 0x05

PSK_BYTES = 32
RID_BYTES = 32
HID_BYTES = 32
KEY_BYTES = 32
X25519_BYTES = 32
IKM_BYTES = PSK_BYTES + X25519_BYTES

MAX_METADATA_BYTES = 8 * 1024
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_OUTER_REQUEST_BYTES = 12 * 1024 * 1024
MAX_HANDSHAKE_BYTES = 1024
MAX_DATA_BYTES = 16 * 1024
MAX_RESPONSE_LINE_BYTES = 24 * 1024
MAX_ERROR_BYTES = 1024
TIMESTAMP_WINDOW_SECONDS = 120

_STREAM_HEADER_BYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
_RECORD_OVERHEAD_BYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
_TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
_TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL

_REQUEST_FIELDS = frozenset({"v", "hid", "rid", "ts", "header", "data"})
_HELLO_FIELDS = frozenset({"v", "hid", "ts", "epk", "mac"})
_REPLY_FIELDS = frozenset({"v", "spk", "mac"})
_HEADER_LINE_FIELDS = frozenset({"v", "header"})
_RECORD_LINE_FIELDS = frozenset({"seq", "data"})
_META_FIELDS = frozenset({"status", "headers"})
_FINAL_TYPES = frozenset({END, ERROR})
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]*")
_AAD_MAGIC = b"CGP3"
_HANDSHAKE_INFO = b"cli-gateway/v3/handshake"
_HELLO_ROLE = b"CGH3-C"
_REPLY_ROLE = b"CGH3-S"
_ADMISSION_MAGIC = b"CGA2"
_ADMISSION_INFO = b"cli-gateway/v3/admission"
_ADMISSION_VERSION = "2"
_ADMISSION_MAX_CHARS = 256
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,19}")
_KEY_INFO = {
    REQUEST: b"cli-gateway/v3/request",
    RESPONSE: b"cli-gateway/v3/response",
}
_KID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
_U64_MAX = 2**64 - 1


class ProtocolError(Exception):
    """Any violation of the wire protocol. The message is a short reason, never payload data."""


def padme_size(length):
    """Padmé rounding, using integer exponents so large boundaries are exact."""
    if type(length) is not int or length < 1:
        raise ProtocolError("invalid padding length")
    if length <= 8:
        return length
    exponent = length.bit_length() - 1
    step = 1 << (exponent - exponent.bit_length())
    return (length + step - 1) // step * step


def request_padded_size(unpadded_length):
    return padme_size(max(unpadded_length + 1, 4096))


def response_padded_size(unpadded_length):
    return (unpadded_length // 512 + 1) * 512


def _pad(data, size):
    return data + b"\x80" + bytes(size - len(data) - 1)


def _unpadded_length(data, size_for):
    """Where the padding begins, found without copying the plaintext.

    The last non-zero byte must be the 0x80 marker, and the padded length must be
    exactly what the rule gives for what precedes it.
    """
    marker = data.rfind(b"\x80")
    if marker < 0 or data.count(0, marker + 1) != len(data) - marker - 1:
        raise ProtocolError("invalid padding")
    if len(data) != size_for(marker):
        raise ProtocolError("non-canonical padding")
    return marker


def _unpad(data, size_for):
    return data[:_unpadded_length(data, size_for)]


def pad_request(data):
    return _pad(data, request_padded_size(len(data)))


def unpad_request(data):
    return _unpad(data, request_padded_size)


def pad_response(data):
    return _pad(data, response_padded_size(len(data)))


def unpad_response(data):
    return _unpad(data, response_padded_size)


def _is_u64(value):
    return type(value) is int and 0 <= value <= _U64_MAX


def _validate_kid(kid):
    if not isinstance(kid, str) or not _KID_PATTERN.fullmatch(kid):
        raise ProtocolError("invalid kid")


@dataclass(frozen=True, repr=False)
class Session:
    """Key material for exactly one request: the PSK followed by a fresh X25519 secret.

    Both ends drop it once the exchange is over. Without the X25519 secret, which neither
    end keeps, the PSK alone cannot recover the traffic keys: that is the forward secrecy.
    """
    kid: str
    hid: bytes
    ikm: bytes

    def __post_init__(self):
        _validate_kid(self.kid)
        if not isinstance(self.hid, bytes) or len(self.hid) != HID_BYTES:
            raise ProtocolError("handshake id must be 32 bytes")
        if not isinstance(self.ikm, bytes) or len(self.ikm) != IKM_BYTES:
            raise ProtocolError("session key material must be 64 bytes")

    def __repr__(self):
        return "Session(kid=%r, hid=%s)" % (self.kid, self.hid.hex()[:12])


def derive_key(session, rid, direction):
    """Per-request, per-direction key: HKDF-SHA256 over the PSK and X25519 secret, salted by the rid."""
    if len(rid) != RID_BYTES:
        raise ProtocolError("rid must be 32 bytes")
    if direction not in _KEY_INFO:
        raise ProtocolError("unknown direction")
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=rid, info=_KEY_INFO[direction]).derive(session.ikm)


def build_aad(hid, rid, ts, direction, sequence):
    """Additional authenticated data bound to every record, in the exact specified order."""
    if len(hid) != HID_BYTES:
        raise ProtocolError("handshake id must be 32 bytes")
    if len(rid) != RID_BYTES:
        raise ProtocolError("rid must be 32 bytes")
    if direction not in _KEY_INFO:
        raise ProtocolError("unknown direction")
    if not _is_u64(ts) or not _is_u64(sequence):
        raise ProtocolError("value outside u64")
    return b"".join((_AAD_MAGIC, hid, rid, struct.pack(">Q", ts), bytes([direction]),
                     struct.pack(">Q", sequence)))


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    """Canonical base64url without padding; anything else is rejected."""
    if not isinstance(text, str) or not _BASE64URL_PATTERN.fullmatch(text):
        raise ProtocolError("invalid base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ProtocolError("invalid base64url") from None
    if _b64encode(raw) != text:
        raise ProtocolError("non-canonical base64url")
    return raw


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate json key")
        result[key] = value
    return result


def _parse_json_object(raw):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ProtocolError("invalid json") from None
    if type(value) is not dict:
        raise ProtocolError("json value is not an object")
    return value


def _dump_json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _require_version(fields):
    if type(fields["v"]) is not int or fields["v"] != VERSION:
        raise ProtocolError("unsupported version")


def _start_pull(header, key):
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    try:
        sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
    except (sodium_errors.CryptoError, ValueError, TypeError):
        raise ProtocolError("authentication failed") from None
    return state


def _open_record(state, data, aad):
    try:
        return sodium.crypto_secretstream_xchacha20poly1305_pull(state, data, aad)
    except (sodium_errors.CryptoError, ValueError, TypeError):
        raise ProtocolError("authentication failed") from None


ADMISSION_HEADER = "cgw-admission"


@dataclass(frozen=True)
class Admission:
    kid: str
    rid: bytes
    ts: int


def derive_admission_key(psk):
    if not isinstance(psk, bytes) or len(psk) != PSK_BYTES:
        raise ProtocolError("psk must be 32 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=b"", info=_ADMISSION_INFO).derive(psk)


def _admission_message(rid, ts, content_length):
    return _ADMISSION_MAGIC + rid + struct.pack(">QQ", ts, content_length)


class AdmissionKeys:
    """Admission keys, each keyed into its HMAC once, so checking a tag hashes only its message."""

    def __init__(self, keys):
        self._macs = {kid: hmac.new(key, digestmod=hashlib.sha256) for kid, key in keys.items()}

    def matching(self, message, mac):
        """Every key under which `mac` verifies. All are checked: none is skipped after a match."""
        matches = []
        for kid, keyed in self._macs.items():
            expected = keyed.copy()
            expected.update(message)
            if hmac.compare_digest(mac, expected.digest()):
                matches.append(kid)
        return matches


def seal_admission(admission_key, rid, ts, content_length):
    """Prove possession of a key without transmitting a client identifier."""
    if not isinstance(admission_key, bytes) or len(admission_key) != KEY_BYTES:
        raise ProtocolError("admission key must be 32 bytes")
    if len(rid) != RID_BYTES or not _is_u64(ts):
        raise ProtocolError("invalid admission identity")
    if not _is_u64(content_length):
        raise ProtocolError("invalid content length")
    mac = hmac.new(admission_key, _admission_message(rid, ts, content_length), hashlib.sha256).digest()
    return "%s.%d.%s.%s" % (_ADMISSION_VERSION, ts, _b64encode(rid), _b64encode(mac))


def open_admission(value, keys, content_length):
    """Check an admission header against the declared body length. Cheap: no body is involved.

    `keys` is an AdmissionKeys, or a mapping of client name to admission key.
    """
    if not isinstance(value, str) or len(value) > _ADMISSION_MAX_CHARS:
        raise ProtocolError("invalid admission")
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != _ADMISSION_VERSION:
        raise ProtocolError("invalid admission")
    _, ts_text, rid_text, mac_text = parts
    if not _DECIMAL.fullmatch(ts_text):
        raise ProtocolError("invalid admission")
    ts = int(ts_text)
    rid, mac = _b64decode(rid_text), _b64decode(mac_text)
    if not _is_u64(ts) or len(rid) != RID_BYTES or len(mac) != 32 or not _is_u64(content_length):
        raise ProtocolError("invalid admission")
    if not isinstance(keys, AdmissionKeys):
        keys = AdmissionKeys(keys)
    matches = keys.matching(_admission_message(rid, ts, content_length), mac)
    if len(matches) != 1:
        raise ProtocolError("authentication failed")
    return Admission(kid=matches[0], rid=rid, ts=ts)


def _handshake_mac(psk, hid, ts, role, *keys):
    key = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=hid, info=_HANDSHAKE_INFO).derive(psk)
    message = role + hid + struct.pack(">Q", ts) + b"".join(keys)
    return hmac.new(key, message, hashlib.sha256).digest()


def _x25519(private, public_bytes):
    try:
        return private.exchange(X25519PublicKey.from_public_bytes(public_bytes))
    except ValueError:  # a low-order point gives an all-zero secret, which is refused
        raise ProtocolError("invalid key exchange") from None


class ClientHandshake:
    """The local bridge's side of one key exchange. Usable once; its private key is then gone."""

    def __init__(self, psk, kid, ts, hid=None, private=None):
        _validate_kid(kid)
        if not isinstance(psk, bytes) or len(psk) != PSK_BYTES:
            raise ProtocolError("psk must be 32 bytes")
        if not _is_u64(ts):
            raise ProtocolError("invalid timestamp")
        hid = os.urandom(HID_BYTES) if hid is None else hid
        if not isinstance(hid, bytes) or len(hid) != HID_BYTES:
            raise ProtocolError("handshake id must be 32 bytes")
        if private is not None and (not isinstance(private, bytes) or len(private) != X25519_BYTES):
            raise ProtocolError("private key must be 32 bytes")
        self._psk, self.kid, self.ts, self.hid = psk, kid, ts, hid
        self._private = X25519PrivateKey.generate() if private is None else X25519PrivateKey.from_private_bytes(private)
        self._epk = self._private.public_key().public_bytes_raw()

    def message(self):
        mac = _handshake_mac(self._psk, self.hid, self.ts, _HELLO_ROLE, self._epk)
        return _dump_json({"v": VERSION, "hid": _b64encode(self.hid), "ts": self.ts,
                           "epk": _b64encode(self._epk), "mac": _b64encode(mac)})

    def complete(self, reply):
        """Verify the gateway's answer and return the session. The private key is dropped either way."""
        private, self._private = self._private, None
        if private is None:
            raise ProtocolError("handshake already completed")
        fields = _parse_json_object(reply)
        if set(fields) != _REPLY_FIELDS:
            raise ProtocolError("unexpected handshake fields")
        _require_version(fields)
        spk, mac = _b64decode(fields["spk"]), _b64decode(fields["mac"])
        if len(spk) != X25519_BYTES or len(mac) != 32:
            raise ProtocolError("invalid field length")
        expected = _handshake_mac(self._psk, self.hid, self.ts, _REPLY_ROLE, self._epk, spk)
        if not hmac.compare_digest(mac, expected):
            raise ProtocolError("authentication failed")
        return Session(kid=self.kid, hid=self.hid, ikm=self._psk + _x25519(private, spk))


@dataclass(frozen=True)
class AnsweredHandshake:
    session: Session
    ts: int
    reply: bytes


def answer_handshake(message, kid, psk):
    """The gateway's side: verify the client's message, answer with a fresh key of its own.

    The caller supplies the admitted client and its PSK. The private key exists only here.
    """
    fields = _parse_json_object(message)
    if set(fields) != _HELLO_FIELDS:
        raise ProtocolError("unexpected handshake fields")
    _require_version(fields)
    ts = fields["ts"]
    _validate_kid(kid)
    if not _is_u64(ts):
        raise ProtocolError("invalid timestamp")
    hid, epk, mac = _b64decode(fields["hid"]), _b64decode(fields["epk"]), _b64decode(fields["mac"])
    if len(hid) != HID_BYTES or len(epk) != X25519_BYTES or len(mac) != 32:
        raise ProtocolError("invalid field length")
    if not isinstance(psk, bytes) or len(psk) != PSK_BYTES:
        raise ProtocolError("psk must be 32 bytes")
    if not hmac.compare_digest(mac, _handshake_mac(psk, hid, ts, _HELLO_ROLE, epk)):
        raise ProtocolError("authentication failed")
    private = X25519PrivateKey.generate()
    shared = _x25519(private, epk)
    spk = private.public_key().public_bytes_raw()
    reply_mac = _handshake_mac(psk, hid, ts, _REPLY_ROLE, epk, spk)
    reply = _dump_json({"v": VERSION, "spk": _b64encode(spk), "mac": _b64encode(reply_mac)})
    return AnsweredHandshake(session=Session(kid=kid, hid=hid, ikm=psk + shared), ts=ts, reply=reply)


@dataclass(frozen=True)
class OpenedRequest:
    kid: str
    hid: bytes
    rid: bytes
    ts: int
    metadata: dict
    body: bytes
    session: Session


def seal_request(session, rid, ts, metadata, body):
    """Encrypt one request as a single final record and return the outer envelope bytes."""
    metadata_bytes = _dump_json(metadata)
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise ProtocolError("metadata too large")
    if len(body) > MAX_BODY_BYTES:
        raise ProtocolError("body too large")
    aad = build_aad(session.hid, rid, ts, REQUEST, 0)
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, derive_key(session, rid, REQUEST))
    plaintext = pad_request(struct.pack(">I", len(metadata_bytes)) + metadata_bytes + body)
    data = sodium.crypto_secretstream_xchacha20poly1305_push(state, plaintext, aad, _TAG_FINAL)
    return _dump_json({
        "v": VERSION,
        "hid": _b64encode(session.hid),
        "rid": _b64encode(rid),
        "ts": ts,
        "header": _b64encode(header),
        "data": _b64encode(data),
    })


def open_request(envelope, find_session, *, admitted):
    """Parse, authenticate and decrypt a request envelope.

    `find_session(hid)` returns the pending session of that handshake, or None. It must
    not consume the session: the caller discards it only once this call has succeeded, so a
    forged envelope naming someone else's handshake cannot spoil it. Nothing from the
    envelope is trusted until the single final record authenticates.
    """
    if len(envelope) > MAX_OUTER_REQUEST_BYTES:
        raise ProtocolError("request too large")
    fields = _parse_json_object(envelope)
    if set(fields) != _REQUEST_FIELDS:
        raise ProtocolError("unexpected envelope fields")
    _require_version(fields)
    ts = fields["ts"]
    kid = admitted.kid
    if not _is_u64(ts):
        raise ProtocolError("invalid timestamp")
    hid = _b64decode(fields["hid"])
    rid = _b64decode(fields["rid"])
    header = _b64decode(fields["header"])
    data = _b64decode(fields["data"])
    if (len(hid) != HID_BYTES or len(rid) != RID_BYTES or len(header) != _STREAM_HEADER_BYTES
            or len(data) < _RECORD_OVERHEAD_BYTES):
        raise ProtocolError("invalid field length")

    session = find_session(hid)
    if (session is None or (session.kid, session.hid) != (kid, hid)
            or (rid, ts) != (admitted.rid, admitted.ts)):
        raise ProtocolError("authentication failed")
    state = _start_pull(header, derive_key(session, rid, REQUEST))
    plaintext, tag = _open_record(state, data, build_aad(hid, rid, ts, REQUEST, 0))
    if tag != _TAG_FINAL:
        raise ProtocolError("request is not a final record")

    # A view, so the body is copied once, not once per step.
    plaintext = memoryview(plaintext)[:_unpadded_length(plaintext, request_padded_size)]
    if len(plaintext) < 4:
        raise ProtocolError("malformed request plaintext")
    metadata_length = struct.unpack_from(">I", plaintext)[0]
    if metadata_length > MAX_METADATA_BYTES:
        raise ProtocolError("metadata too large")
    if 4 + metadata_length > len(plaintext):
        raise ProtocolError("malformed request plaintext")
    metadata = _parse_json_object(bytes(plaintext[4:4 + metadata_length]))
    body = bytes(plaintext[4 + metadata_length:])
    if len(body) > MAX_BODY_BYTES:
        raise ProtocolError("body too large")
    return OpenedRequest(kid=kid, hid=hid, rid=rid, ts=ts, metadata=metadata, body=body, session=session)


@dataclass(frozen=True)
class Record:
    """One verified response record. `value` holds the parsed JSON of META and ERROR."""
    type: int
    payload: bytes
    value: dict | None = None


def chunks(data, size=MAX_DATA_BYTES):
    """Split upstream bytes into pieces that each fit one DATA record."""
    for start in range(0, len(data), size):
        yield data[start:start + size]


def timestamp_is_fresh(ts, now, window=TIMESTAMP_WINDOW_SECONDS):
    return abs(now - ts) <= window


def _validate_meta(value):
    if set(value) != _META_FIELDS:
        raise ProtocolError("unexpected meta fields")
    status, headers = value["status"], value["headers"]
    if type(status) is not int or not 100 <= status <= 599:
        raise ProtocolError("invalid upstream status")
    if type(headers) is not dict or not all(
            isinstance(name, str) and isinstance(text, str) for name, text in headers.items()):
        raise ProtocolError("invalid upstream headers")


class ResponseSealer:
    """Remote side: turns upstream output into encrypted NDJSON lines, in a valid order only."""

    def __init__(self, session, rid, ts):
        build_aad(session.hid, rid, ts, RESPONSE, 0)  # validates the context up front
        self._context = (session.hid, rid, ts)
        self._state = sodium.crypto_secretstream_xchacha20poly1305_state()
        self._header = sodium.crypto_secretstream_xchacha20poly1305_init_push(
            self._state, derive_key(session, rid, RESPONSE))
        self._sequence = 0
        self._meta_sent = False
        self._finished = False

    def header_line(self):
        return _dump_json({"v": VERSION, "header": _b64encode(self._header)}) + b"\n"

    def meta(self, status, headers):
        if self._meta_sent:
            raise ProtocolError("meta already sent")
        value = {"status": status, "headers": dict(headers)}
        _validate_meta(value)
        payload = _dump_json(value)
        if len(payload) > MAX_METADATA_BYTES:
            raise ProtocolError("meta too large")
        line = self._push(META, payload, _TAG_MESSAGE)
        self._meta_sent = True
        return line

    def data(self, chunk):
        if not self._meta_sent:
            raise ProtocolError("data before meta")
        if not 1 <= len(chunk) <= MAX_DATA_BYTES:
            raise ProtocolError("invalid data size")
        return self._push(DATA, chunk, _TAG_MESSAGE)

    def heartbeat(self):
        return self._push(HEARTBEAT, b"", _TAG_MESSAGE)

    def end(self):
        if not self._meta_sent:
            raise ProtocolError("end before meta")
        return self._push(END, b"", _TAG_FINAL)

    def error(self, value):
        if type(value) is not dict:
            raise ProtocolError("invalid error payload")
        payload = _dump_json(value)
        if len(payload) > MAX_ERROR_BYTES:
            raise ProtocolError("invalid error payload")
        return self._push(ERROR, payload, _TAG_FINAL)

    def _push(self, record_type, payload, tag):
        if self._finished:
            raise ProtocolError("stream already finished")
        hid, rid, ts = self._context
        data = sodium.crypto_secretstream_xchacha20poly1305_push(
            self._state, pad_response(bytes([record_type]) + payload),
            build_aad(hid, rid, ts, RESPONSE, self._sequence), tag)
        line = _dump_json({"seq": self._sequence, "data": _b64encode(data)}) + b"\n"
        self._sequence += 1
        self._finished = tag == _TAG_FINAL
        return line


_AWAIT_HEADER, _AWAIT_META, _IN_BODY, _FINISHED, _FAILED = range(5)
_ALLOWED_TYPES = {
    _AWAIT_META: frozenset({HEARTBEAT, META, ERROR}),
    _IN_BODY: frozenset({DATA, HEARTBEAT, END, ERROR}),
}


class ResponseOpener:
    """Local side: verifies NDJSON lines strictly in order and releases only verified records.

    Any rejected line leaves the opener failed for good. A stream is complete only when
    `finished` is true; end of input before that is truncation.
    """

    def __init__(self, session, rid, ts):
        build_aad(session.hid, rid, ts, RESPONSE, 0)  # validates the context up front
        self._context = (session.hid, rid, ts)
        self._key = derive_key(session, rid, RESPONSE)
        self._state = None
        self._sequence = 0
        self._phase = _AWAIT_HEADER

    @property
    def finished(self):
        return self._phase == _FINISHED

    def open_header(self, line):
        self._guarded(self._open_header, line)

    def open_record(self, line):
        return self._guarded(self._open_record, line)

    def _guarded(self, step, line):
        if self._phase == _FAILED:
            raise ProtocolError("stream already failed")
        try:
            return step(line)
        except ProtocolError:
            self._phase = _FAILED
            raise

    @staticmethod
    def _parse_line(line, expected_fields):
        if len(line) > MAX_RESPONSE_LINE_BYTES:
            raise ProtocolError("line too long")
        fields = _parse_json_object(line[:-1] if line.endswith(b"\n") else line)
        if set(fields) != expected_fields:
            raise ProtocolError("unexpected line fields")
        return fields

    def _open_header(self, line):
        if self._phase != _AWAIT_HEADER:
            raise ProtocolError("unexpected stream header")
        fields = self._parse_line(line, _HEADER_LINE_FIELDS)
        _require_version(fields)
        header = _b64decode(fields["header"])
        if len(header) != _STREAM_HEADER_BYTES:
            raise ProtocolError("invalid field length")
        self._state = _start_pull(header, self._key)
        self._phase = _AWAIT_META

    def _open_record(self, line):
        if self._phase == _AWAIT_HEADER:
            raise ProtocolError("record before stream header")
        if self._phase == _FINISHED:
            raise ProtocolError("record after final record")
        fields = self._parse_line(line, _RECORD_LINE_FIELDS)
        if not _is_u64(fields["seq"]) or fields["seq"] != self._sequence:
            raise ProtocolError("unexpected sequence")
        data = _b64decode(fields["data"])
        if len(data) < _RECORD_OVERHEAD_BYTES:
            raise ProtocolError("invalid field length")
        hid, rid, ts = self._context
        plaintext, tag = _open_record(self._state, data, build_aad(hid, rid, ts, RESPONSE, self._sequence))

        plaintext = unpad_response(plaintext)
        if not plaintext:
            raise ProtocolError("record without a type")
        record_type, payload = plaintext[0], plaintext[1:]
        if record_type not in _ALLOWED_TYPES[self._phase]:
            raise ProtocolError("record type not allowed here")
        if tag != (_TAG_FINAL if record_type in _FINAL_TYPES else _TAG_MESSAGE):
            raise ProtocolError("unexpected record tag")

        value = None
        if record_type == META:
            if len(payload) > MAX_METADATA_BYTES:
                raise ProtocolError("meta too large")
            value = _parse_json_object(payload)
            _validate_meta(value)
        elif record_type == DATA:
            if not 1 <= len(payload) <= MAX_DATA_BYTES:
                raise ProtocolError("invalid data size")
        elif record_type == ERROR:
            if len(payload) > MAX_ERROR_BYTES:
                raise ProtocolError("error payload too large")
            value = _parse_json_object(payload)
        elif payload:
            raise ProtocolError("unexpected payload")

        self._sequence += 1
        if record_type == META:
            self._phase = _IN_BODY
        elif record_type in _FINAL_TYPES:
            self._phase = _FINISHED
        return Record(type=record_type, payload=payload, value=value)
