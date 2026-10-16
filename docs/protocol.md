# Wire protocol, version 3

This is the protocol spoken between the local bridge and the remote bridge. It keeps
request and response bodies confidential and tamper-evident on a network that can read
and modify HTTPS traffic, and every request has forward secrecy: recordings stay
unreadable even if the pre-shared key is stolen later. It also limits what the traffic
itself shows: no client name crosses the wire, requests and response records are padded,
and responses leave the gateway on a fixed 50 ms grid.

It is a proof-of-concept design assembled from established primitives. It has not been
independently audited.

The implementation is `src/cgw/protocol.py`. An independent construction written from
this description lives in `tests/wire_reference.py`, and frozen vectors produced by that
reference, with fixed X25519 keys on both sides, are in `tests/fixtures/protocol_v3.json`.

Version 3 replaced version 2, which carried the client's name in every request and sent
each response record at its exact length the moment upstream produced it. Version 2
replaced version 1, which derived every key from the pre-shared key alone. No version is
compatible with another: a client of an older version gets 404 from a newer gateway, and
a version-3 client reports `protocol_mismatch` against an older one.

## Shared state

| Value | Definition |
|---|---|
| PSK | 32 cryptographically random bytes per client, held by that client and the gateway. Never derived from a password, and never shared between clients |
| `kid` | The client's name: 1 to 64 characters of `A-Z a-z 0-9 _ -`. It never crosses the wire and takes no part in any key or MAC. The gateway recognises a client by its key alone, and names it in its logs |

The gateway holds one PSK per client and admits no other key. Its operator sets them as
environment variables, `CGW_CLIENT_<NAME>` for the client named `<name>` (the runbook
has the naming rule). The gateway holds at most 64 keys, clients and admins together,
and refuses to start with more: every request is checked against every key (see
"Admission tag"), so the limit bounds what an anonymous request can cost.

An admin has a second PSK, set as `CGW_ADMIN_<NAME>`, which the gateway names
`admin_<name>` in its logs. An admin key may make only the sign-in requests in "Admin
keys" below, and a client key never may. The gateway learns which kind of key a request
uses from the key that matches; nothing on the wire says. Both are otherwise handled
exactly alike: the same handshake, envelope, admission tag, padding and response stream.

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
  | Admission | PSK | none (empty) | `cli-gateway/v3/admission` |
  | Handshake | PSK | `hid` | `cli-gateway/v3/handshake` |
  | Request | PSK ‖ X25519 secret | `rid` | `cli-gateway/v3/request` |
  | Response | PSK ‖ X25519 secret | `rid` | `cli-gateway/v3/response` |

  The admission key depends on the PSK alone, so the gateway derives it once per key
  when it starts. The others are derived for each request. The traffic keys need both
  secrets. Without the X25519 secret, which only ever exists in memory at the two ends,
  the PSK cannot reproduce them. If X25519 were ever broken, the PSK would still protect
  the content.
- **Encryption:** libsodium `crypto_secretstream_xchacha20poly1305`. Each direction has
  its own key, its own 24-byte stream header and its own state.
- **Padding:** ISO/IEC 7816-4, the scheme of libsodium's `sodium_pad`. `pad(m, n)` is
  `m`, then one `0x80` byte, then zero bytes up to a total of `n` bytes. Every padded
  length is fixed by a rule (see "Padding").
- **Binary fields on the wire:** base64url without padding, in canonical form. Padded
  or non-canonical encodings are rejected.

## A request takes two round trips

1. **Handshake.** The local bridge sends a fresh public key to `/poc/v3/handshake`; the
   gateway answers with one of its own. Both ends now share a secret nobody else has.
2. **Exchange.** The local bridge sends the encrypted request to `/poc/v3/exchange`,
   naming the handshake, and receives the encrypted response stream.

Each step carries an admission tag (below), so a client without a PSK is refused at
either step from the request head alone.

### Handshake

```
POST /poc/v3/handshake
Content-Type: application/json
Content-Length: <bytes>
CGW-Admission: 2.<ts>.<hid base64url>.<mac base64url>

{"v":3,"hid":"<base64url>","ts":<seconds>,"epk":"<client public key>","mac":"<base64url>"}
```

```
mac = HMAC-SHA256(handshake key, "CGH3-C" || hid[32] || u64be(ts) || epk[32])
```

The reply, `200`, `Content-Type: application/json`, `Cache-Control: no-store`:

```
{"v":3,"spk":"<gateway public key>","mac":"<base64url>"}
```

```
mac = HMAC-SHA256(handshake key, "CGH3-S" || hid[32] || u64be(ts) || epk[32] || spk[32])
```

The handshake key is that of the client whose admission tag the gateway accepted. The
client checks the reply's MAC before using `spk`. It proves that the reply comes from a
holder of the PSK and answers this very handshake, so nobody in between can substitute a
key of their own. Both messages are parsed as strictly as the envelope below. Canonical
handshakes have the same length across clients when timestamps have the same decimal
width; replies have a fixed length. Accepted JSON whitespace can change those lengths.

The gateway generates its key pair for this one answer and keeps neither half. It holds
the resulting session, with the client it belongs to, in memory for at most 30 seconds
while it waits for the exchange, and never writes it anywhere. Sessions are held per
client: another client naming the same `hid` gets a session of its own, and a live
duplicate from the same client is refused without replacing the existing one. The
client likewise drops its private key as soon as the reply has been checked, whether
the check passes or not.

### Exchange

```
POST /poc/v3/exchange
Content-Type: application/json
Content-Length: <bytes>
CGW-Admission: 2.<ts>.<rid base64url>.<mac base64url>

{"v":3,"hid":"<base64url>","rid":"<base64url>","ts":<seconds>,"header":"<base64url>","data":"<base64url>"}
```

The object has exactly these six fields. Duplicate keys, unknown fields, wrong types
(`true` is not `1`) and any version other than `3` are rejected.

`hid` names the handshake whose session encrypts this request. That session must belong
to the client whose key passed this exchange's admission tag. The gateway uses the
session once: it is discarded atomically after authentication, while still unexpired,
and only if its owner and original handshake timestamp match. An envelope that
fails to authenticate does not use it up, so a forged envelope naming someone else's
handshake cannot spoil it.

`data` is a single secretstream record carrying the FINAL tag. Its plaintext is

```
u = u32be(len(metadata)) || metadata || body
plaintext = pad(u, padme(max(len(u) + 1, 4096)))
```

with `padme` as defined in "Padding". `metadata` is a UTF-8 JSON object with the fields
`method`, `path` and `headers`, and a fourth, `query`, when the tool's request had a
query string:

```json
{"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
{"method": "POST", "path": "/v1beta/models/<model>:streamGenerateContent", "query": "alt=sse", "headers": {"content-type": "application/json"}}
```

### Admission tag

The `CGW-Admission` header lets the gateway refuse anyone without a key before it
commits any resources: before it charges a budget, and before it reads a single byte of
the body. Without it, anyone on the internet could make the gateway buffer and parse
bodies, or occupy its limited places with uploads that never finish.

```
mac = HMAC-SHA256(admission key, "CGA2" || id[32] || u64be(ts) || u64be(Content-Length))
```

`id` is the `hid` for a handshake and the `rid` for an exchange. The leading `2` is the
version of the tag's format. `ts` is written in decimal without leading zeros; `id` and
`mac` are canonical base64url without padding.

The tag names no client. The gateway computes the MAC under every admission key it
holds and uses a constant-time comparison for each result, without stopping at the
first match. This removes the obvious early-exit signal of a key's position; it does
not make the Python endpoint or its subsequent processing constant-time.
Keys are unique per client, so at most one matches, and that one identifies the client.
The gateway refuses duplicate PSKs at startup. Measured costs are in the design record.

The tag must:

- verify under exactly one key, for the declared `Content-Length`;
- carry a `ts` within 120 seconds of server time;
- not have been used before (the gateway remembers used tags for 300 seconds, longer
  than any tag stays fresh);
- name the same `id` and `ts` as the message it arrives with.

The tag reveals nothing that the message does not already show.

## Additional authenticated data

Every record in both directions is bound to its handshake, request and position by this
AAD, in this exact byte order:

```
"CGP3" || hid[32] || rid[32] || u64be(ts) || direction[1] || u64be(sequence)
```

`direction` is `0x00` for the request and `0x01` for the response. The request's
sequence is 0. Response sequences start at 0 and increase by one per record. The
receiver builds the AAD from the session it expects, never from the record. The keys
themselves belong to one client, so the AAD needs no client name.

## Padding

Padding replaces exact plaintext lengths with size buckets. Small records of different
types have equal ciphertext lengths, though ordering, record counts and timing may
still suggest their types. It does not guarantee resistance to traffic analysis.

**Response records.** A record's plaintext, one type byte and its payload, is padded to
the next multiple of 512 bytes with at least one byte of padding:

```
plaintext = pad(type || payload, 512 * ceil((len(payload) + 2) / 512))
```

So `META`, `HEARTBEAT`, `END`, `ERROR` and `DATA` records of up to 510 bytes all encrypt
to the same 529 bytes, and the largest `DATA` record, 16 KiB, to 16,913.

**Requests.** The exchange's plaintext is padded to its Padmé length, with a floor of
4 KiB. Padmé is from Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
Communication with PURBs" (PETS 2019):

```
E = floor(log2(L))
S = floor(log2(E)) + 1
padme(L) = L rounded up to a multiple of 2^(E - S)
```

It rounds a length to a step that grows with the length: 256 bytes at 4 KiB, 2 KiB at
64 KiB, 256 KiB at 8 MiB. Rounding `L = max(len(u) + 1, 4096)` adds at most 6.25%
to `L`; this excludes expansion to the floor, the mandatory marker, encryption and
base64 overhead. Observers learn a bucket that can still be a narrow size interval.
Every request with `len(u) <= 4095` has the same padded plaintext size, including its
metadata and length prefix. The largest request, an 8 MiB body
with 8 KiB of metadata, pads to 8,650,752 bytes, about 11 MiB on the wire, within the
outer limit.

**Handshakes** have no padding; their canonical lengths are independent of client names
under the timestamp-width condition above.

**Removing padding.** The receiver reads back from the end of the plaintext over zero
bytes to the first byte that is not zero, which must be `0x80`, and removes it with the
zeros. It then computes the padded length the rule above gives for what remains and
requires the plaintext to have exactly that length. Any other plaintext is rejected as a
record that fails to authenticate would be, so a sender cannot pad differently and leak
a length that way.

## Timing

The remote bridge sends response records on a fixed grid, so their timing does not
follow the upstream's token by token. Let `t0` be the moment it starts the response,
after the request has authenticated and taken an in-flight slot. It sends the stream
header line at `t0` and schedules records at `t0 + k × 50 ms`, for integers `k >= 1`.
Upstream bytes wait for their tick in a backlog that holds at most 256 KiB, however many
pieces upstream sends them in. At each tick the bridge takes a finite snapshot of that
backlog and sends it in order, as one write:

1. `META`, if the upstream has answered;
2. the bytes received, in `DATA` records of up to 16 KiB;
3. `END` or `ERROR`, if the upstream has finished.

A tick with nothing to send sends nothing, except that the tick 15 seconds after the
last record (or after the header line) sends a `HEARTBEAT`. The overall deadline and
upstream timeouts are unchanged; the `ERROR` record they produce is also scheduled on a
tick. If the overall deadline has passed at a tick and upstream has not finished, that
tick sends what has arrived and then the timeout error. A reply whose end has reached
the gateway by that tick is delivered whole; one still arriving, even if only the
backlog holds back its last bytes, is cut off. Missed ticks are skipped rather than
replayed.

For bytes available to an unblocked relay, deliberate batching adds at most one tick;
25 ms is the mean only for arrivals uniformly distributed within a tick. Event-loop
scheduling, network writes and backpressure can add delay or regroup observed traffic.
The backlog bounds memory, so an upstream that sends more than 256 KiB per tick waits for
later ticks. This is an application emission schedule, not a network delivery deadline.

Several upstream events can share one DATA record. A tick may also contain a single
event, and idle ticks contain no filler. The local SSE gate still holds back the newest
complete event until a successor or authenticated completion arrives; an upstream
pause can extend that delay beyond one tick.

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
- CLIProxyAPI's own controls: names starting with `x-cpa-`;
- connection plumbing: `host`, `content-length`, `connection`, `keep-alive`, `te`,
  `trailer`, `transfer-encoding`, `upgrade`, `expect`, `accept-encoding`, and names
  starting with `proxy-`;
- forwarding and browser context: `forwarded`, `via`, `x-real-ip`, `true-client-ip`,
  `cf-connecting-ip`, `origin`, `referer`, and names starting with `x-forwarded-`,
  `sec-` or `cgw-`.

At most 64 headers are passed on. Each tool sends headers of its own, and they travel
inside the encrypted metadata, so passing them on reveals nothing on the wire. The
remote bridge presents its own credential to the upstream and asks for an uncompressed
response. A request body may be compressed (`content-encoding: zstd`, which CLIProxyAPI
decodes); CLIProxyAPI is configured to refuse a body that decodes to more than 32 MiB.
Of the upstream's response headers, only `content-type` and `retry-after` come back.

### Admin keys

An admin key may reach a small slice of CLIProxyAPI's management API: enough to sign
the gateway in to a subscription, list its sign-ins and remove one. Nothing else in
that API is reachable with any key: not its configuration, API keys, logs or plugins,
and not the download of a sign-in file. A client key may reach none of it, and an
admin key none of the model routes.

| Method | Path | Query | Purpose |
|---|---|---|---|
| `GET` | `/v0/management/<provider>-auth-url` | none | Start a sign-in; returns the provider's sign-in address and a `state` |
| `POST` | `/v0/management/oauth-callback` | none | Hand back the address the browser was sent to, as `{"provider", "redirect_url"}` |
| `GET` | `/v0/management/get-auth-status` | `state=<state>` only | Follow the sign-in: `wait`, `ok` or `error` |
| `GET` | `/v0/management/auth-files` | none | List the sign-ins |
| `DELETE` | `/v0/management/auth-files` | `name=<file>.json`, exactly one | Remove one sign-in |

`<provider>` is one of `anthropic`, `codex`, `antigravity`, `xai`, `kimi`, `kimi-ai`,
`meta`, `devin`. `<state>` is 1 to 128 characters of `A-Z a-z 0-9 . _ -`, and `<file>`
a name of the same kind without a slash; neither may contain `..`. So `all=true`, which
would remove every sign-in, and `is_webui`, which would make CLIProxyAPI listen on a
callback port inside the container, are refused. A `GET` or `DELETE` that carries a
body is refused.

CLIProxyAPI's management API is switched on only when the gateway has a management key
(`CGW_CLIPROXY_MANAGEMENT_KEY`), and stays on container loopback only, with its web
panel off. The remote bridge presents that key, as `Authorization: Bearer`, on admin
requests only; on every other request it presents the ordinary CLIProxyAPI key. No
client ever sees the management key. A gateway with admin keys but no management key
refuses to start.

The list of sign-ins is filtered by the remote bridge before it is sealed: each entry
keeps only `name`, `provider`, `type`, `email`, `label`, `account_type`, `status`,
`status_message`, `disabled`, `unavailable`, `last_refresh`, `updated_at` and
`created_at`. Identity tokens, file paths and everything else CLIProxyAPI lists stay in
the container.

Every admin request is logged by what it did, for example
`manage client=admin_work-laptop request=GET /v0/management/auth-files outcome=completed upstream_status=200`.

### How the remote bridge processes a request

Both endpoints begin with the same checks, made from the request head alone:

1. Refuse a request with an `Origin` header (browsers are not clients).
2. Require a declared `Content-Length` and refuse one over the limit: 1 KiB for a
   handshake, 12 MiB for an exchange.
3. Check the admission tag against every key: it must verify under one, be fresh and be
   unused. It is then marked used. The key search is bounded by the 64-key startup
   limit; the design record reports measured validation costs.

A **handshake** then continues:

4. Read the message, which must arrive within 30 seconds.
5. Verify its MAC under the key that passed admission, and that it matches the tag
   (`hid`, `ts`).
6. Generate a key pair, compute the shared secret, answer, and hold the session for at
   most 30 seconds. At most 256 sessions wait at once.

An **exchange** continues:

4. Admit the request against the budgets for the work itself: at most 8 such requests
   at once, and at most 24 MiB of declared length between them.
5. Read the body, which must arrive within 30 seconds.
6. Parse the envelope strictly, find the session its `hid` names, require that it
   belongs to the client whose key passed admission, authenticate the record with that
   session's keys and remove the padding. An unknown or expired handshake, another
   client's session, a wrong key and wrong padding all give the same answer. The
   envelope must match its admission tag. Only now is the session used up.
7. Validate the metadata against the route, query and header rules: the model routes
   for a client key, the sign-in routes for an admin key.
8. Require `ts` to be within 120 seconds of server time, in either direction.
9. Take one of two in-flight slots.
10. Forward to the upstream and stream the response back on the grid.

A client without a key is refused at step 3 of either endpoint, so it can never hold a
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
| 400 | `rejected` | Malformed, unauthenticated or disallowed request (including a route the key may not use), or an unknown, expired or used handshake. Deliberately unspecific |
| 400 | `stale_timestamp` | `ts` outside the 120-second window |
| 403 | `forbidden` | `Origin` header present |
| 408 | `too_slow` | The body did not arrive within 30 seconds |
| 409 | `replayed` | Admission tag already used |
| 411 | `length_required` | No `Content-Length` declared |
| 413 | `too_large` | Outer request over the size limit |
| 429 | `busy` | Both in-flight slots taken, the budgets for receiving requests are full, or 256 handshakes are already waiting |

The local bridge never shows the network's own text to its user. It maps an outer
failure to one of these codes if it recognises it, a 404 from either path to
`protocol_mismatch` (an older gateway or an incorrectly routed endpoint can answer
404), and anything else to
`bad_gateway_response`.

**Waiting for a place.** `busy` always comes before anything is sent upstream, so the
local bridge does not pass it on at once. It sends at most two requests at a time, the
gateway's in-flight limit, and holds the rest in order on the machine; a request keeps
its place from its handshake until its response is over, as it holds the gateway's
slot. A request refused as `busy` all the same, by contention from other machines, is
sent again with a fresh handshake and a new `rid`, after a pause that grows from 0.1 to
2 seconds. The local bridge reports `busy` only once a request has waited 120 seconds
in all. A tool that gives up while its request waits takes nothing from the queue.

## Response

```
HTTP/1.1 200
Content-Type: application/x-ndjson
Cache-Control: no-store

{"v":3,"header":"<base64url>"}
{"seq":0,"data":"<base64url>"}
{"seq":1,"data":"<base64url>"}
...
```

The first line carries the response stream header. Each following line is one
secretstream record. Lines have exactly the fields shown and are at most 24 KiB.

The plaintext of a record, before padding, is one type byte followed by its payload:

| Type | Byte | Tag | Payload |
|---|---|---|---|
| `META` | `0x01` | MESSAGE | JSON object with exactly `status` (100 to 599) and `headers` (string to string). At most 8 KiB |
| `DATA` | `0x02` | MESSAGE | Upstream bytes, unchanged. 1 byte to 16 KiB |
| `HEARTBEAT` | `0x03` | MESSAGE | Empty. Sent after 15 seconds without a record |
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
- Each record's padding must be exactly as "Padding" specifies.
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

{"proof": hex(HMAC-SHA256(local key, "cgw-local-bridge-identity/v1" || 0x00 || nonce)), "protocol": 3}
```

The request carries no credential. The launcher and the smoke test send a fresh random
nonce and compare the proof before sending anything else, and refuse to continue if it
does not match. The tools themselves do not make this check on each request; see the
limits below.

`protocol` is the wire protocol version the bridge speaks. When a bridge proves itself
but names another version, or none, as every bridge before version 3 does, the launcher
attempts to stop it and starts the current one. It requires `lsof` to identify a single
listener owned by the current user, then checks the proof and PID again before sending
TERM. It refuses ambiguous or changed listeners and does not escalate to KILL. The new
bridge must prove itself before a tool receives credentials. These checks reduce but
cannot atomically eliminate local process/port handover races.

`verify-bridge` exits 0 for a verified v3 bridge, 3 for no listener, 4 for a verified
bridge with another or missing protocol version, and 1 for an unverified response.
Version fields are considered only after the challenge proof verifies.

## Limits

| Limit | Value |
|---|---|
| Keys the gateway holds, clients and admins together | 64 |
| Handshake message | 1 KiB |
| Waiting handshakes | 30 s each, at most 256 |
| Request metadata | 8 KiB |
| Query string | 1,024 characters |
| Request headers passed on | 64 |
| Request body | 8 MiB |
| Request plaintext, padded | Padmé length, at least 4 KiB |
| Outer request | 12 MiB |
| `DATA` payload | 16 KiB |
| Response record plaintext, padded | A multiple of 512 bytes |
| Response line | 24 KiB |
| Response grid | 50 ms |
| Response bytes waiting for a tick | 256 KiB |
| One SSE event | 8 MiB |
| Buffered (non-stream) response | 32 MiB |
| Timestamp tolerance | 120 seconds |
| Requests in flight | 2 |
| Local bridge's wait for a place, queued and retried | 120 s |
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
- **Separation between uses.** A client's PSK cannot manage sign-ins, and an admin's PSK
  cannot make model requests or read a subscription's tokens.
- **Forward secrecy, per request.** Each request's traffic keys depend on an X25519
  secret that exists only in memory at the two ends while that request is handled.
  Someone who records the traffic and later steals the PSK still cannot read it.
- **Less to read from the traffic itself.** No explicit client name, role or stable
  client identifier crosses the wire. The fresh `hid` links a handshake to its exchange.
  Response plaintext lengths are rounded to 512-byte steps and requests to Padmé
  buckets with a 4 KiB floor. Response emission is scheduled on a 50 ms grid, merging
  adjacent data available in the same tick. These measures reduce direct length and
  timing disclosure; they do not establish that tokens, topics or roles cannot be inferred.

Not provided:

- **Protection against a stolen PSK going forward.** Whoever holds a client's PSK can
  act as that client, or as the gateway towards it, from then on. Forward secrecy
  protects past traffic, not future traffic; remove the client, or give it a new PSK,
  if its PSK may have leaked.
- **Guaranteed erasure.** Both bridges drop key material as soon as a request is over,
  but Python cannot guarantee that memory is overwritten. Someone who can read a
  running bridge's memory during a request can read that request.
- **Concealment.** The hostname, the paths `/poc/v3/handshake` and `/poc/v3/exchange`,
  and that the payload is ciphertext are visible. So is what padding and the grid leave:
  how many requests are made and when; each request's size to its Padmé length, so a
  conversation that grows turn by turn still shows it in those steps; the size of what
  each record carries, to 512 bytes, and record counts and sequence numbers (whose
  decimal widths also affect line length); which ticks carry anything, so pauses and
  how long they last; and each response's duration and total size. Scheduling and
  network effects add their own variation. Requests can still be
  linked by the network address they come from.
- **Availability.** Anyone on the path can block or delay the connection. Off the path,
  a client without a key cannot hold any of the gateway's places or budgets, but a
  large enough flood of connections can still exhaust the connection limit for as long
  as it is sustained. Stopping that is the job of the hosting platform's edge. A client
  with a key can hold places: the waiting handshakes, the requests being received and
  the two in-flight slots are shared by all clients, so one client can crowd out the
  others.
- **Protection from the endpoints.** Plaintext exists on the client machine, inside the
  gateway container and at the model provider.
- **Protection from other programs on the client machine.** Tools reach the local
  bridge over plain HTTP on loopback. The launcher verifies the bridge's identity before
  starting a tool, but if the bridge stops while a tool is running, another local
  program could take the port and receive what the tool sends next. On a machine you share with
  people you do not trust, treat the gateway as you would any other loopback service.
