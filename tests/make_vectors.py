"""Regenerate tests/fixtures/protocol_v1.json from the independent reference.

    uv run python tests/make_vectors.py

Only run this when the wire format is changed on purpose. The key below is a public test
value, never a real PSK.
"""
import json
from pathlib import Path

import wire_reference as ref

PSK = bytes(range(32))
KID = "poc-1"
RID = bytes(range(100, 132))
TS = 1_800_000_000
METADATA = {"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
BODY = '{"model":"gpt-6-astra","stream":true,"input":"héllo ✓"}'.encode("utf-8")
META = json.dumps({"status": 200, "headers": {"content-type": "text/event-stream"}}).encode()
SSE = b'event: response.completed\ndata: {"type":"response.completed"}\n\n'


def main():
    metadata_bytes = json.dumps(METADATA, separators=(",", ":")).encode()
    envelope = ref.seal_request(PSK, KID, RID, TS, ref.request_plaintext(metadata_bytes, BODY))
    writer = ref.ResponseWriter(PSK, KID, RID, TS)
    records = [(1, META, ref.TAG_MESSAGE), (3, b"", ref.TAG_MESSAGE), (2, SSE, ref.TAG_MESSAGE),
               (4, b"", ref.TAG_FINAL)]
    lines = [writer.header_line()] + [writer.record(kind, payload, tag) for kind, payload, tag in records]
    vectors = {
        "comment": "Produced by tests/make_vectors.py from the independent reference. Test key only.",
        "psk_hex": PSK.hex(),
        "kid": KID,
        "rid_hex": RID.hex(),
        "ts": TS,
        "request_key_hex": ref.hkdf(PSK, RID, ref.REQUEST_INFO).hex(),
        "response_key_hex": ref.hkdf(PSK, RID, ref.RESPONSE_INFO).hex(),
        "admission": {
            "content_length": len(ref.dump(envelope)),
            "value": ref.admission(PSK, KID, RID, TS, len(ref.dump(envelope))),
        },
        "request": {
            "envelope": ref.dump(envelope).decode(),
            "metadata": METADATA,
            "body_hex": BODY.hex(),
        },
        "response": {
            "lines": [line.decode() for line in lines],
            "records": [{"type": kind, "payload_hex": payload.hex()} for kind, payload, _ in records],
        },
    }
    target = Path(__file__).parent / "fixtures" / "protocol_v1.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(vectors, indent=2) + "\n")
    print("wrote", target)


if __name__ == "__main__":
    main()
