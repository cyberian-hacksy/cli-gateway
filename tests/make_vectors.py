"""Regenerate tests/fixtures/protocol_v2.json from the independent reference.

    uv run python tests/make_vectors.py

Only run this when the wire format is changed on purpose. Every key below is a public
test value, never a real one.
"""
import json
from pathlib import Path

import wire_reference as ref

PSK = bytes(range(32))
KID = "poc-1"
HID = bytes(range(200, 232))
RID = bytes(range(100, 132))
TS = 1_800_000_000
CLIENT_PRIVATE = bytes(range(40, 72))
SERVER_PRIVATE = bytes(range(80, 112))
METADATA = {"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
BODY = '{"model":"gpt-6-astra","stream":true,"input":"héllo ✓"}'.encode("utf-8")
META = json.dumps({"status": 200, "headers": {"content-type": "text/event-stream"}}).encode()
SSE = b'event: response.completed\ndata: {"type":"response.completed"}\n\n'


def main():
    hello = ref.dump(ref.client_hello(PSK, KID, HID, TS, CLIENT_PRIVATE))
    reply = ref.dump(ref.server_hello(PSK, KID, HID, TS, ref.x25519_public(CLIENT_PRIVATE), SERVER_PRIVATE))
    shared = ref.x25519(CLIENT_PRIVATE, ref.x25519_public(SERVER_PRIVATE))
    ikm = ref.session_ikm(PSK, shared)

    metadata_bytes = json.dumps(METADATA, separators=(",", ":")).encode()
    envelope = ref.dump(ref.seal_request(ikm, KID, HID, RID, TS, ref.request_plaintext(metadata_bytes, BODY)))
    writer = ref.ResponseWriter(ikm, KID, HID, RID, TS)
    records = [(1, META, ref.TAG_MESSAGE), (3, b"", ref.TAG_MESSAGE), (2, SSE, ref.TAG_MESSAGE),
               (4, b"", ref.TAG_FINAL)]
    lines = [writer.header_line()] + [writer.record(kind, payload, tag) for kind, payload, tag in records]
    vectors = {
        "comment": "Produced by tests/make_vectors.py from the independent reference. Test keys only.",
        "psk_hex": PSK.hex(),
        "kid": KID,
        "hid_hex": HID.hex(),
        "rid_hex": RID.hex(),
        "ts": TS,
        "client_private_hex": CLIENT_PRIVATE.hex(),
        "server_private_hex": SERVER_PRIVATE.hex(),
        "handshake": {
            "hello": hello.decode(),
            "hello_admission": ref.admission(PSK, KID, HID, TS, len(hello)),
            "reply": reply.decode(),
            "shared_hex": shared.hex(),
        },
        "request_key_hex": ref.hkdf(ikm, RID, ref.REQUEST_INFO).hex(),
        "response_key_hex": ref.hkdf(ikm, RID, ref.RESPONSE_INFO).hex(),
        "admission": {"content_length": len(envelope), "value": ref.admission(PSK, KID, RID, TS, len(envelope))},
        "request": {"envelope": envelope.decode(), "metadata": METADATA, "body_hex": BODY.hex()},
        "response": {
            "lines": [line.decode() for line in lines],
            "records": [{"type": kind, "payload_hex": payload.hex()} for kind, payload, _ in records],
        },
    }
    target = Path(__file__).parent / "fixtures" / "protocol_v2.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(vectors, indent=2) + "\n")
    print("wrote", target)


if __name__ == "__main__":
    main()
