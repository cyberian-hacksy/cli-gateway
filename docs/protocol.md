# Wire protocol, version 1

This is the protocol spoken between the local bridge and the remote bridge. It keeps
request and response bodies confidential and tamper-evident on a network that can read
and modify HTTPS traffic.

It is a proof-of-concept design assembled from established primitives. It has not been
independently audited.

The implementation is `src/cgw/protocol.py`. An independent construction written from
this description lives in `tests/wire_reference.py`, and frozen vectors produced by that
reference are in `tests/fixtures/protocol_v1.json`.

## Shared state

| Value | Definition |
|---|---|
| PSK | 32 cryptographically random bytes, shared by the two bridges. Never derived from a password |
| `kid` | Public key identifier: 1 to 64 characters of `A-Z a-z 0-9 _ -` |

## Per request

| Value | Definition |
|---|---|
| `rid` | 32 fresh random bytes. Never reused, including for a retry |
| `ts` | Unsigned Unix time in seconds when the request was sealed |

## Primitives

- **Key derivation:** HKDF-SHA256 (RFC 5869) with IKM = PSK, salt = `rid`, output 32
  bytes, and one of two `info` strings:
  - request key: `codex-gateway-poc/v1/request`
  - response key: `codex-gateway-poc/v1/response`
- **Encryption:** libsodium `crypto_secretstream_xchacha20poly1305`. Each direction has
  its own key, its own 24-byte stream header and its own state.
- **Binary fields on the wire:** base64url without padding, in canonical form. Padded
  or non-canonical encodings are rejected.

## Additional authenticated data

Every record in both directions is bound to its session and position by this AAD, in
this exact byte order:

```
"CGP1" || u16be(len(kid)) || kid || rid[32] || u64be(ts) || direction[1] || u64be(sequence)
```

`direction` is `0x00` for the request and `0x01` for the response. The request's
sequence is 0. Response sequences start at 0 and increase by one per record. The
receiver builds the AAD from the session it expects, never from the record.

## Request

```
POST /poc/v1/exchange
Content-Type: application/json

{"v":1,"kid":"...","rid":"<base64url>","ts":<seconds>,"header":"<base64url>","data":"<base64url>"}
```

The object has exactly these six fields. Duplicate keys, unknown fields, wrong types
(`true` is not `1`) and any version other than `1` are rejected.

`data` is a single secretstream record carrying the FINAL tag. Its plaintext is:

```
u32be(len(metadata)) || metadata || body
```

`metadata` is a UTF-8 JSON object with exactly three fields:

```json
{"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
```

There is no field for a destination. The remote bridge forwards only these routes, to
one fixed upstream:

| Method | Path |
|---|---|
| `GET` | `/v1/models` |
| `POST` | `/v1/responses` |

The path carries no query string. Header names must be valid HTTP tokens and values may
not contain NUL, CR or LF. Both bridges apply the same allowlist of header names
(`src/cgw/policy.py`); `Authorization`, cookies and everything else are dropped, and
the remote bridge injects its own credential for the upstream.

### How the remote bridge processes a request

In this order, stopping at the first failure:

1. Refuse a request with an `Origin` header (browsers are not clients).
2. Enforce the outer size limit, from `Content-Length` if declared and while reading.
3. Parse the envelope strictly and authenticate the record under the claimed `kid`.
   An unknown `kid` and a wrong key give the same answer.
4. Validate the metadata against the route and header rules.
5. Require `ts` to be within 120 seconds of server time, in either direction.
6. Record `(kid, rid)` in the replay ledger and commit. A duplicate stops here.
7. Take one of two in-flight slots.
8. Forward to the upstream and stream the response back.

Nothing is sent upstream before step 8. A request ID stays consumed whatever happens
afterwards, including an upstream failure or a refusal at step 7.

### Failures before the response stream

These are plain, unencrypted JSON bodies of the form `{"error":"<code>"}`:

| Status | Code | Cause |
|---|---|---|
| 400 | `rejected` | Malformed, unauthenticated or disallowed request. Deliberately unspecific |
| 400 | `stale_timestamp` | `ts` outside the 120-second window |
| 403 | `forbidden` | `Origin` header present |
| 409 | `replayed` | `(kid, rid)` already recorded |
| 413 | `too_large` | Outer request over the size limit |
| 429 | `busy` | Both in-flight slots taken |
| 503 | `unavailable` | Replay ledger missing, corrupt or full |

The local bridge never shows the network's own text to its user. It maps an outer
failure to one of these codes if it recognises it, and to `bad_gateway_response`
otherwise.

## Response

```
HTTP/1.1 200
Content-Type: application/x-ndjson
Cache-Control: no-store

{"v":1,"header":"<base64url>"}
{"seq":0,"data":"<base64url>"}
{"seq":1,"data":"<base64url>"}
...
```

The first line carries the response stream header. Each following line is one
secretstream record. Lines have exactly the fields shown and are at most 24 KiB.

The plaintext of a record is one type byte followed by its payload:

| Type | Byte | Tag | Payload |
|---|---|---|---|
| `META` | `0x01` | MESSAGE | JSON object with exactly `status` (100 to 599) and `headers` (string to string). At most 8 KiB |
| `DATA` | `0x02` | MESSAGE | Upstream bytes, unchanged. 1 byte to 16 KiB |
| `HEARTBEAT` | `0x03` | MESSAGE | Empty. Sent every 15 seconds of upstream silence |
| `END` | `0x04` | FINAL | Empty. Upstream finished cleanly |
| `ERROR` | `0x05` | FINAL | JSON object `{"code": "..."}`, at most 1 KiB |

Records must arrive in this order:

```
HEARTBEAT*  ( ERROR  |  META (DATA | HEARTBEAT)*  (END | ERROR) )
```

`ERROR` codes are `upstream_unreachable`, `upstream_timeout` and `upstream_failed`.
The upstream's own HTTP errors are not `ERROR` records: a 4xx or 5xx travels as `META`
with that status, followed by its body in `DATA` records and `END`.

### How the local bridge verifies a response

- Records are verified strictly in order. The `seq` on the wire must equal the
  receiver's own count, and the same number is in the AAD.
- The tag must match the type: FINAL for `END` and `ERROR`, MESSAGE for the rest.
- After one rejected line the stream is dead. No later record is accepted.
- The stream is complete only when a FINAL record has verified. The connection ending
  before that is truncation, whatever was received.

### What reaches the client

- **A successful event stream** (status 200, `text/event-stream`) is released one
  complete SSE event at a time, byte for byte. The terminal event and anything after it
  are held until `END` verifies. An event is terminal if its `event:` name or the
  `type` in its JSON `data` is `response.completed`, `response.failed`,
  `response.incomplete` or `error`. A stream that ends without a terminal event is not
  reported as a success.
- **Anything else** is buffered, up to 32 MiB, and delivered whole after `END`
  verifies, or not at all.
- **A failure before the first byte** becomes an HTTP 502 with a `gateway_error` code.
- **A failure after bytes were sent** drops the client connection without a clean end.
  Output already delivered cannot be taken back, but no completion is ever invented.

## Limits

| Limit | Value |
|---|---|
| Request metadata | 8 KiB |
| Request body | 8 MiB |
| Outer request | 12 MiB |
| `DATA` payload | 16 KiB |
| Response line | 24 KiB |
| One SSE event, and the held tail | 8 MiB |
| Buffered (non-stream) response | 32 MiB |
| Timestamp tolerance | 120 seconds |
| Requests in flight | 2 |
| Upstream connect / idle / overall | 15 s / 180 s / 600 s |
| Replay ledger | 100,000 request IDs per key |

## What the protocol provides, and what it does not

Provided, against a party that can read, change, replay, reorder, delay and drop all
traffic between the bridges, including through a locally trusted inspection certificate:

- Confidentiality of method, path, forwarded headers, request body, upstream status,
  response headers and response body.
- Integrity and ordering of every record, and detection of truncation.
- At-most-once delivery of a request to the upstream, across restarts.

Not provided:

- **Forward secrecy.** Keys are derived from a static PSK. Whoever later obtains the
  PSK can decrypt recorded sessions.
- **Concealment.** The hostname, the path `/poc/v1/exchange`, the `kid`, timing and
  approximate sizes are visible, and the payload is visibly ciphertext.
- **Availability.** Anyone on the path can block or delay the connection.
- **Protection from the endpoints.** Plaintext exists on the client machine, inside the
  gateway container and at the model provider.
