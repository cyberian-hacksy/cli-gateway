# Wire protocol, version 2

This is the protocol spoken between the local bridge and the remote bridge. It keeps
request and response bodies confidential and tamper-evident on a network that can read
and modify HTTPS traffic, and every request has forward secrecy: recordings stay
unreadable even if the pre-shared key is stolen later.

It is a proof-of-concept design assembled from established primitives. It has not been
independently audited.

The implementation is `src/cgw/protocol.py`. An independent construction written from
this description lives in `tests/wire_reference.py`, and frozen vectors produced by that
reference, with fixed X25519 keys on both sides, are in `tests/fixtures/protocol_v2.json`.

Version 2 replaced version 1, which derived every key from the pre-shared key alone. The
two are not compatible: a version-1 client gets 404 from a version-2 gateway.

## Shared state

| Value | Definition |
|---|---|
| PSK | 32 cryptographically random bytes per client, held by that client and the gateway. Never derived from a password, and never shared between clients |
| `kid` | The client's name, public: 1 to 64 characters of `A-Z a-z 0-9 _ -`. The gateway finds the client's PSK by it |

The gateway holds one PSK per client and admits no other `kid`. Its operator sets them
as environment variables, `CGW_CLIENT_<NAME>` for the client named `<name>` (the
runbook has the naming rule); the protocol itself only needs the lookup by `kid`.

## Per request

| Value | Definition |
|---|---|
| `hid` | 32 fresh random bytes naming this request's handshake |
| `rid` | 32 fresh random bytes naming the request itself. Never reused, including for a retry |
| `ts` | Unsigned Unix time in seconds; the handshake and the exchange carry the same value |
| Key pairs | One X25519 key pair on each side, generated for this request and dropped after it |

## Primitives

- **Key agreement:** X25519 (RFC 7748). A low-order public key, which forces an all-zero
  shared secret, is rejected.
- **Key derivation:** HKDF-SHA256 (RFC 5869), output 32 bytes:

  | Key | IKM | Salt | `info` |
  |---|---|---|---|
  | Handshake | PSK | `hid` | `codex-gateway/v2/handshake` |
  | Request | PSK ‖ X25519 secret | `rid` | `codex-gateway/v2/request` |
  | Response | PSK ‖ X25519 secret | `rid` | `codex-gateway/v2/response` |
  | Admission | PSK | `hid` or `rid` | `codex-gateway-poc/v1/admission` |

  The traffic keys need both secrets. Without the X25519 secret, which only ever exists
  in memory at the two ends, the PSK cannot reproduce them. If X25519 were ever broken,
  the PSK would still protect the content.
- **Encryption:** libsodium `crypto_secretstream_xchacha20poly1305`. Each direction has
  its own key, its own 24-byte stream header and its own state.
- **Binary fields on the wire:** base64url without padding, in canonical form. Padded
  or non-canonical encodings are rejected.

## A request takes two round trips

1. **Handshake.** The local bridge sends a fresh public key to `/poc/v2/handshake`; the
   gateway answers with one of its own. Both ends now share a secret nobody else has.
2. **Exchange.** The local bridge sends the encrypted request to `/poc/v2/exchange`,
   naming the handshake, and receives the encrypted response stream.

Each step carries an admission tag (below), so a client without the PSK is refused at
either step from the request head alone.

### Handshake

```
POST /poc/v2/handshake
Content-Type: application/json
Content-Length: <bytes, at most 1024>
CGW-Admission: 1.<kid>.<ts>.<hid base64url>.<mac base64url>

{"v":2,"kid":"...","hid":"<base64url>","ts":<seconds>,"epk":"<client public key>","mac":"<base64url>"}
```

```
mac = HMAC-SHA256(handshake key, "CGH-C" || u16be(len(kid)) || kid || hid[32] || u64be(ts) || epk[32])
```

The reply, `200`, `Content-Type: application/json`, `Cache-Control: no-store`:

```
{"v":2,"spk":"<gateway public key>","mac":"<base64url>"}
```

```
mac = HMAC-SHA256(handshake key, "CGH-S" || u16be(len(kid)) || kid || hid[32] || u64be(ts) || epk[32] || spk[32])
```

The client checks this MAC before using `spk`. It proves that the reply comes from a
holder of the PSK and answers this very handshake, so nobody in between can substitute a
key of their own. Both messages are parsed as strictly as the envelope below.

The gateway generates its key pair for this one answer and keeps neither half. It holds
the resulting session in memory for at most 30 seconds while it waits for the exchange,
and never writes it anywhere. The client likewise drops its private key as soon as the
reply has been checked, whether the check passes or not.

### Exchange

```
POST /poc/v2/exchange
Content-Type: application/json
Content-Length: <bytes>
CGW-Admission: 1.<kid>.<ts>.<rid base64url>.<mac base64url>

{"v":2,"kid":"...","hid":"<base64url>","rid":"<base64url>","ts":<seconds>,"header":"<base64url>","data":"<base64url>"}
```

The object has exactly these seven fields. Duplicate keys, unknown fields, wrong types
(`true` is not `1`) and any version other than `2` are rejected.

`hid` names the handshake whose session encrypts this request. The gateway uses that
session once: it is discarded as soon as the envelope authenticates. An envelope that
fails to authenticate does not use it up, so a forged envelope naming someone else's
handshake cannot spoil it.

`data` is a single secretstream record carrying the FINAL tag. Its plaintext is:

```
u32be(len(metadata)) || metadata || body
```

`metadata` is a UTF-8 JSON object with the fields `method`, `path` and `headers`, and a
fourth, `query`, when the tool's request had a query string:

```json
{"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
{"method": "POST", "path": "/v1beta/models/<model>:streamGenerateContent", "query": "alt=sse", "headers": {"content-type": "application/json"}}
```

`query` was added on 14 October 2026. A gateway from before then rejects a request that
carries it. An older local bridge never sends it, so it still works with a newer gateway.

### Admission tag

The `CGW-Admission` header lets the gateway refuse anyone without the key before it
commits any resources: before it charges a budget, and before it reads a single byte of
the body. Without it, anyone on the internet could make the gateway buffer and parse
bodies, or occupy its limited places with uploads that never finish.

```
mac = HMAC-SHA256(admission key,
                  "CGA1" || u16be(len(kid)) || kid || id[32] || u64be(ts) || u64be(Content-Length))
```

`id` is the `hid` for a handshake and the `rid` for an exchange. `ts` is written in
decimal without leading zeros; `id` and `mac` are canonical base64url without padding.
The tag must:

- verify under the PSK of its `kid`, for the declared `Content-Length`;
- carry a `ts` within 120 seconds of server time;
- not have been used before (the gateway remembers used tags for 300 seconds, longer
  than any tag stays fresh);
- name the same `kid`, `id` and `ts` as the message it arrives with.

The tag reveals nothing that the message does not already show.

## Additional authenticated data

Every record in both directions is bound to its handshake, request and position by this
AAD, in this exact byte order:

```
"CGP2" || u16be(len(kid)) || kid || hid[32] || rid[32] || u64be(ts) || direction[1] || u64be(sequence)
```

`direction` is `0x00` for the request and `0x01` for the response. The request's
sequence is 0. Response sequences start at 0 and increase by one per record. The
receiver builds the AAD from the session it expects, never from the record.

## Routes, query strings and headers

There is no field for a destination. The remote bridge forwards to one fixed upstream,
CLIProxyAPI on container loopback, and only these routes: CLIProxyAPI 8.0.27's routes
for text models, in each API format it serves. Both bridges apply the same rules
(`src/cgw/policy.py`).

| Format | Method | Path |
|---|---|---|
| OpenAI | `GET` | `/v1/models`, `/v1/models/<model>` |
| OpenAI | `POST` | `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/responses/compact` |
| Anthropic | `POST` | `/v1/messages`, `/v1/messages/count_tokens` |
| Gemini | `GET` | `/v1beta/models`, `/v1beta/models/<model>` |
| Gemini | `POST` | `/v1beta/models/<model>:<action>`, `/v1beta/interactions` |

`<model>` is 1 to 128 characters of `A-Z a-z 0-9 . _ @ + -`, starting with a letter or
digit. It never contains a slash, so a path cannot climb out of its route. `<action>` is
1 to 64 letters, such as `streamGenerateContent`. Everything else is unreachable:
CLIProxyAPI's management API, its image, audio, video, realtime and websocket
endpoints, its sign-in callbacks and its direct Codex route.

**Query strings** travel in the metadata's `query` field: at most 1,024 characters,
parameter names of 1 to 64 characters of `A-Z a-z 0-9 _ . -`, and no control
characters in values. The `key` and `auth_token` parameters are dropped: they are
credentials, and the gateway presents its own. The local bridge sends the query in
canonical form, as Python's `urlencode` writes it, and the remote bridge accepts it
only in that form, so both ends forward exactly the same thing.

**Headers.** Names must be valid HTTP tokens and values may not contain NUL, CR or LF.
Every header is passed on except these:

- credentials: `authorization`, `x-api-key`, `x-goog-api-key`, `cookie`,
  `x-management-key`, and any name containing `management`;
- connection plumbing: `host`, `content-length`, `connection`, `keep-alive`, `te`,
  `trailer`, `transfer-encoding`, `upgrade`, `expect`, `accept-encoding`, and names
  starting with `proxy-`;
- forwarding and browser context: `forwarded`, `via`, `x-real-ip`, `true-client-ip`,
  `cf-connecting-ip`, `origin`, `referer`, and names starting with `x-forwarded-`,
  `sec-` or `cgw-`.

At most 64 headers are passed on. Each tool sends headers of its own, and they travel
inside the encrypted metadata, so passing them on reveals nothing on the wire. The
remote bridge presents its own credential to the upstream and asks for an uncompressed
response. Of the upstream's response headers, only `content-type` and `retry-after`
come back.

### How the remote bridge processes a request

Both endpoints begin with the same checks, made from the request head alone:

1. Refuse a request with an `Origin` header (browsers are not clients).
2. Require a declared `Content-Length` and refuse one over the limit: 1 KiB for a
   handshake, 12 MiB for an exchange.
3. Check the admission tag: it must verify, be fresh and be unused. It is then marked
   used. Everything so far costs microseconds.

A **handshake** then continues:

4. Read the message, which must arrive within 30 seconds.
5. Verify its MAC and that it matches its admission tag (`kid`, `hid`, `ts`).
6. Generate a key pair, compute the shared secret, answer, and hold the session for at
   most 30 seconds. At most 256 sessions wait at once.

An **exchange** continues:

4. Admit the request against the budgets for the work itself: at most 8 such requests
   at once, and at most 24 MiB of declared length between them.
5. Read the body, which must arrive within 30 seconds.
6. Parse the envelope strictly, find the session its `hid` names, and authenticate the
   record with that session's keys. An unknown `kid`, an unknown or expired handshake
   and a wrong key all give the same answer. The envelope must match its admission tag.
   Only now is the session used up.
7. Validate the metadata against the route, query and header rules.
8. Require `ts` to be within 120 seconds of server time, in either direction.
9. Take one of two in-flight slots.
10. Forward to the upstream and stream the response back.

A client without the key is refused at step 3 of either endpoint, so it can never hold a
place, use a budget, make the gateway read a body, or leave a session waiting. The
exchange's steps 4 and 5 still bound key holders. Its step 6 runs off the event loop so
that it cannot stall streams in progress.

Nothing is sent upstream before step 10. The admission tag is used up at step 3 and the
session at step 6, and neither comes back whatever happens afterwards, including an
upstream failure or a refusal at step 9.

Replays are refused twice over, and both checks live in memory only. An admission tag
works once, and a used tag is remembered for longer than its timestamp stays fresh. A
session works once, lasts at most 30 seconds, and does not survive a restart, so after
one an old envelope has no session to authenticate against. The gateway stores nothing
on disk to refuse replays.

### Failures before the response stream

These are plain, unencrypted JSON bodies of the form `{"error":"<code>"}`:

| Status | Code | Cause |
|---|---|---|
| 400 | `rejected` | Malformed, unauthenticated or disallowed request, or an unknown, expired or used handshake. Deliberately unspecific |
| 400 | `stale_timestamp` | `ts` outside the 120-second window |
| 403 | `forbidden` | `Origin` header present |
| 408 | `too_slow` | The body did not arrive within 30 seconds |
| 409 | `replayed` | Admission tag already used |
| 411 | `length_required` | No `Content-Length` declared |
| 413 | `too_large` | Outer request over the size limit |
| 429 | `busy` | Both in-flight slots taken, the budgets for receiving requests are full, or 256 handshakes are already waiting |

The local bridge never shows the network's own text to its user. It maps an outer
failure to one of these codes if it recognises it, and to `bad_gateway_response`
otherwise.

## Response

```
HTTP/1.1 200
Content-Type: application/x-ndjson
Cache-Control: no-store

{"v":2,"header":"<base64url>"}
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
  complete SSE event at a time, byte for byte, and always one event behind: the newest
  complete event is held until the next one completes, and the last until `END`
  verifies. Every format ends with the event that says it is done
  (`response.completed`, `message_stop`, `[DONE]`, or Gemini's chunk carrying
  `finishReason`), so a truncated stream never shows its ending, and the bridge needs
  no list of event names. A stream that has verified is passed on exactly as upstream
  sent it, even one that never says it is done; the tool treats that as it would
  without the gateway.
- **Anything else** is buffered, up to 32 MiB, and delivered whole after `END`
  verifies, or not at all.
- **A failure before the first byte** becomes an HTTP 502 with a `gateway_error` code.
- **A failure after bytes were sent** drops the client connection without a clean end.
  Output already delivered cannot be taken back, but no completion is ever invented.

## The local bridge's own checks

The local bridge listens on loopback only. It takes the local key the way the tool's
API format sends a key: `Authorization: Bearer <key>` (OpenAI, and Anthropic's auth
token), `x-api-key` (Anthropic) or `x-goog-api-key` (Gemini). Before anything leaves the
machine it refuses a request:

| Status | Code | Cause |
|---|---|---|
| 401 | `invalid_local_key` | The local key is missing or wrong in every place it may be sent |
| 403 | `browser_origin_refused` | `Origin` header present |
| 404 | `not_found` | A route outside the list above |
| 400 | `invalid_query` | A query string the gateway would not carry |
| 400 | `too_many_headers` | More than 64 headers to pass on |

The local key itself is never sent on.

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
does not match. The tools themselves do not make this check on each request; see the
limits below.

## Limits

| Limit | Value |
|---|---|
| Handshake message | 1 KiB |
| Waiting handshakes | 30 s each, at most 256 |
| Request metadata | 8 KiB |
| Query string | 1,024 characters |
| Request headers passed on | 64 |
| Request body | 8 MiB |
| Outer request | 12 MiB |
| `DATA` payload | 16 KiB |
| Response line | 24 KiB |
| One SSE event | 8 MiB |
| Buffered (non-stream) response | 32 MiB |
| Timestamp tolerance | 120 seconds |
| Requests in flight | 2 |
| Requests being received (after admission) | 8 at once, 24 MiB declared in total, 30 s each |
| Open connections to the gateway | 1024 |
| Time for a connection to deliver a request head | 10 s; trickled bytes do not extend it |
| Used admission tags remembered | 300 s, at most 100,000 |
| Upstream connect / idle / overall | 15 s / 180 s / 600 s |

## What the protocol provides, and what it does not

Provided, against a party that can read, change, replay, reorder, delay and drop all
traffic between the bridges, including through a locally trusted inspection certificate:

- Confidentiality of method, path, query string, forwarded headers, request body,
  upstream status, response headers and response body.
- Integrity and ordering of every record, and detection of truncation.
- At-most-once delivery of a request to the upstream, across restarts: a request is
  sealed under a session that is used once and exists only in the gateway's memory.
- **Separation between clients.** One client's PSK does not let anyone act as another
  client, or as the gateway towards another client.
- **Forward secrecy, per request.** Each request's traffic keys depend on an X25519
  secret that exists only in memory at the two ends while that request is handled.
  Someone who records the traffic and later steals the PSK still cannot read it.

Not provided:

- **Protection against a stolen PSK going forward.** Whoever holds a client's PSK can
  act as that client, or as the gateway towards it, from then on. Forward secrecy
  protects past traffic, not future traffic; remove the client, or give it a new PSK,
  if its PSK may have leaked.
- **Guaranteed erasure.** Both bridges drop key material as soon as a request is over,
  but Python cannot guarantee that memory is overwritten. Someone who can read a
  running bridge's memory during a request can read that request.
- **Concealment.** The hostname, the paths `/poc/v2/handshake` and `/poc/v2/exchange`,
  the `kid`, timing and approximate sizes are visible, and the payload is visibly
  ciphertext.
- **Availability.** Anyone on the path can block or delay the connection. Off the path,
  a client without the key cannot hold any of the gateway's places or budgets, but a
  large enough flood of connections can still exhaust the connection limit for as long
  as it is sustained. Stopping that is the job of the hosting platform's edge.
- **Protection from the endpoints.** Plaintext exists on the client machine, inside the
  gateway container and at the model provider.
- **Protection from other programs on the client machine.** Tools reach the local
  bridge over plain HTTP on loopback. The launcher verifies the bridge's identity before
  starting a tool, but if the bridge stops while a tool is running, another local
  program could take the port and receive what the tool sends next. On a machine you share with
  people you do not trust, treat the gateway as you would any other loopback service.
