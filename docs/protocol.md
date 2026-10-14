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
  bytes, and one of three `info` strings:
  - request key: `codex-gateway-poc/v1/request`
  - response key: `codex-gateway-poc/v1/response`
  - admission key: `codex-gateway-poc/v1/admission`
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
Content-Length: <bytes>
CGW-Admission: 1.<kid>.<ts>.<rid base64url>.<mac base64url>

{"v":1,"kid":"...","rid":"<base64url>","ts":<seconds>,"header":"<base64url>","data":"<base64url>"}
```

### Admission tag

The `CGW-Admission` header lets the gateway refuse anyone without the key before it
commits any resources: before it charges a budget, and before it reads a single byte of
the body. Without it, anyone on the internet could make the gateway buffer and parse
bodies, or occupy its limited places with uploads that never finish.

```
mac = HMAC-SHA256(admission key,
                  "CGA1" || u16be(len(kid)) || kid || rid[32] || u64be(ts) || u64be(Content-Length))
```

`ts` is written in decimal without leading zeros; `rid` and `mac` are canonical
base64url without padding. The tag must:

- verify under the PSK of its `kid`, for the declared `Content-Length`;
- carry a `ts` within 120 seconds of server time;
- not have been used before (the gateway remembers used tags for 300 seconds, longer
  than any tag stays fresh);
- name the same `kid`, `rid` and `ts` as the envelope it arrives with.

The tag reveals nothing that the envelope does not already show. It is an addition to
version 1: a gateway that requires it refuses clients that do not send it, while an
older gateway ignores it.

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
2. Require a declared `Content-Length` and refuse one over the outer size limit.
3. Check the admission tag: it must verify, be fresh and be unused. It is then marked
   used. Everything so far reads only the request head and costs microseconds.
4. Admit the request against the budgets for the work itself: at most 8 such requests
   at once, and at most 24 MiB of declared length between them.
5. Read the body, which must arrive within 30 seconds.
6. Parse the envelope strictly and authenticate the record under the claimed `kid`.
   An unknown `kid` and a wrong key give the same answer. The envelope must match the
   admission tag.
7. Validate the metadata against the route and header rules.
8. Require `ts` to be within 120 seconds of server time, in either direction.
9. Record `(kid, rid)` in the replay ledger and commit. A duplicate stops here.
10. Take one of two in-flight slots.
11. Forward to the upstream and stream the response back.

A client without the key is refused at step 3, so it can never hold a place in step 4,
use the memory budget, or make the gateway read a body. Steps 4 and 5 still bound key
holders. Step 6 runs off the event loop so that it cannot stall streams in progress.

Nothing is sent upstream before step 11. A request ID stays consumed whatever happens
after step 9, including an upstream failure or a refusal at step 10.

### Failures before the response stream

These are plain, unencrypted JSON bodies of the form `{"error":"<code>"}`:

| Status | Code | Cause |
|---|---|---|
| 400 | `rejected` | Malformed, unauthenticated or disallowed request. Deliberately unspecific |
| 400 | `stale_timestamp` | `ts` outside the 120-second window |
| 403 | `forbidden` | `Origin` header present |
| 408 | `too_slow` | The body did not arrive within 30 seconds |
| 409 | `replayed` | Admission tag already used, or `(kid, rid)` already recorded |
| 411 | `length_required` | No `Content-Length` declared |
| 413 | `too_large` | Outer request over the size limit |
| 429 | `busy` | Both in-flight slots taken, or the budgets for receiving requests are full |
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

## Local bridge identity

The local bridge starts on demand, so its port is normally free, and any program on the
machine, including another user's, could bind it first. A caller that sent the local
key or a prompt to such a program would hand both over. The local bridge therefore
proves which program it is before it is trusted:

```
GET /cgw/identity?nonce=<32 to 128 lowercase hex characters>

{"proof": hex(HMAC-SHA256(local key, "cgw-local-bridge-identity/v1" || 0x00 || nonce))}
```

The request carries no credential. The launcher and the smoke test send a fresh random
nonce and compare the proof before sending anything else, and refuse to continue if it
does not match. Codex itself does not make this check on each request; see the limits
below.

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
| Requests being received (after admission) | 8 at once, 24 MiB declared in total, 30 s each |
| Open connections to the gateway | 1024 |
| Time for a connection to deliver a request head | 10 s; trickled bytes do not extend it |
| Used admission tags remembered | 300 s, at most 100,000 |
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
- **Availability.** Anyone on the path can block or delay the connection. Off the path,
  a client without the key cannot hold any of the gateway's places or budgets, but a
  large enough flood of connections can still exhaust the connection limit for as long
  as it is sustained. Stopping that is the job of the hosting platform's edge.
- **Protection from the endpoints.** Plaintext exists on the client machine, inside the
  gateway container and at the model provider.
- **Protection from other programs on the client machine.** Codex reaches the local
  bridge over plain HTTP on loopback. The launcher verifies the bridge's identity before
  starting Codex, but if the bridge stops while Codex is running, another local program
  could take the port and receive what Codex sends next. On a machine you share with
  people you do not trust, treat the gateway as you would any other loopback service.
