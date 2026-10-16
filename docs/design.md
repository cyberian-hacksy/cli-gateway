# Design and verification record

Date: 13 October 2026
Status: implemented and deployed on 13 October 2026; all five stages passed (results below)
Operations: see `runbook.md`. Wire protocol: see `protocol.md`.

This is a dated record of how the gateway was designed, built and checked. It builds on
an earlier design note, referred to below as "the original note", which is not part of
this repository; the protocol it specified is written up in `protocol.md`.

## Purpose

Give command-line AI tools one secure endpoint to a server that holds the subscriptions
they use. The server runs CLIProxyAPI, which signs in to each subscription and calls the
providers. The gateway is the only way in, and only machines holding a key get through.

The design assumes the worst case for the path in between: a network that can decrypt
HTTPS through a trusted CA, and a hosting edge that terminates TLS. Request and response
bodies are therefore encrypted at the application layer between a local bridge on each
machine and a remote bridge beside CLIProxyAPI, so both see ciphertext only.

The first version serves the Codex CLI. Other tools that CLIProxyAPI supports, such as
Claude Code, are meant to follow.

This does not help if a provider itself is down or an account loses access. The gateway
calls the same upstream services.

## Decisions

| Question | Decision | Reason |
|---|---|---|
| Threat model | Assume TLS inspection between client and gateway | Content stays private whatever the network or the hosting edge can decrypt |
| Activation | Chosen explicitly, through a separate Codex profile | Nothing switches silently, and a request never goes out unencrypted |
| Topology | One Railway container, one volume, one replica | The replay ledger needs a single writer |
| Build order | Feasibility gates before any encryption work | Both ways the project can be dead on arrival are cheap to test |
| Railway plan | Hobby ($5/month) from the start | Guarantees full outbound networking; volume persists |
| Language | Python | PyNaCl is a maintained binding that exposes libsodium secretstream |

## Corrections to the original note

| Topic | Original note | Checked 13 October 2026 | Effect |
|---|---|---|---|
| Railway trial network | "verify outbound access" | Unverified "Limited Trial" has restricted outbound networking | Moot on Hobby |
| Railway trial lifetime | $5 for 30 days, then $1/month | Same; trial volumes are deleted 30 days after credits expire | A standing gateway needs a paid plan |
| Railway RAM | 0.5 GiB | 1 GB on trial | More headroom |
| CLIProxyAPI config keys | `remote-management`, `request-retry`, `streaming.bootstrap-retries` | Legacy names. Current schema nests them: `management.*`, `routing.retry.request-retry`, `server.port`, `oauth.auth-dir`, `access.api-keys`. `request-retry` defaults to 3 | Pin one release by image digest; write config against that release's schema; set retries to 0 explicitly |
| CLIProxyAPI language | not stated | Go, shipped as image `eceasy/cli-proxy-api` | We run the binary; it does not constrain our language |
| Codex profiles | Provider block in `config.toml` | Profiles are separate files: `$CODEX_HOME/<name>.config.toml`, selected with `codex --profile <name>` | The existing `config.toml` stays untouched |

Built and tested with Codex CLI 0.160.1 and the model `gpt-6-astra`.

## Architecture

```
Codex --profile gateway
   │ plain HTTP, loopback
   ▼
local bridge 127.0.0.1:8318      encrypts request, verifies response
   │ HTTPS, encrypted envelope
   ▼
Railway container
   remote bridge 0.0.0.0:$PORT   decrypts, replay check, re-encrypts stream
   │ loopback
   CLIProxyAPI 127.0.0.1:8317    holds OAuth credentials, calls upstream
   volume /data                  auth files + replay ledger
```

Plaintext exists on the local machine, inside the Railway container and at the model
provider. The inspecting proxy and the Railway edge see encrypted bodies.

## Feasibility gates

Nothing encrypted is built until both pass.

### Gate 1: local compatibility

1. Start Docker Desktop. Run the pinned CLIProxyAPI image bound to `127.0.0.1:8317`,
   with its auth directory outside the repo and owner-only.
2. Do the Codex OAuth login with `--codex-login` (add `-no-browser` if needed).
3. Point a temporary Codex profile at `http://127.0.0.1:8317/v1`.

Pass: `/v1/models` lists the model; a response streams; a tool call completes a full
cycle; cancelling mid-stream stops the upstream call. Record the headers Codex sends,
because the bridge forwards only those.

### Gate 2: Railway

1. Streaming probe. A throwaway service with a public domain that emits one line per
   second for five minutes. Pass: lines arrive incrementally, not as one buffered lump.
2. Upstream egress. The pinned CLIProxyAPI deployed with no public domain. Auth files
   go onto the volume over `railway ssh`. One real streamed request is run inside the
   container against loopback. Pass: real model output comes back from Railway's IPs.

Step 2 answers whether upstream accepts Railway egress without exposing the raw proxy,
and rehearses credential provisioning.

### What the gates cannot prove

Only the networks available at the time can be tested. TLS inspection is simulated in
stage 4 with mitmproxy.

## Components

Python package with two entry points: Starlette on uvicorn, HTTPX, PyNaCl,
`cryptography` for HKDF, stdlib `sqlite3`. All versions pinned.

```
cli-gateway/
  bin/codex-gateway    launcher: setup, run Codex, smoke, status, stop
  src/cgw/
    protocol.py        envelope, AAD, key derivation, record framing
    policy.py          allowed routes and headers, shared by both bridges
    sse.py             SSE event buffering, terminal-event hold
    ledger.py          SQLite replay ledger
    local_bridge.py    ASGI app, 127.0.0.1:8318
    remote_bridge.py   ASGI app, 0.0.0.0:$PORT
    streaming.py       streaming response that reacts to a client leaving
    supervisor.py      runs the container's two processes as a unit
    config.py          environment and file configuration
    cli.py             command-line entry points
  deploy/
    Dockerfile         pinned CLIProxyAPI digest + bridge
    entrypoint.py      renders config, starts both processes
    cliproxy.yaml      no secrets, management API disabled
    requirements.lock  hash-pinned Python packages for the image
  probe/               streaming probe used in gate 2
  tests/               suite, independent wire reference, frozen vectors
  docs/                this record, protocol.md, runbook.md
```

- `protocol.py` is pure: bytes in, bytes out, no network, no disk. Both bridges import
  it, so the two ends cannot drift apart.
- `ledger.py` does one thing, the atomic insert of `(kid, rid)`, and fails closed if
  the database is missing or corrupt.
- `sse.py` is separate because holding the terminal event until `END` verifies is the
  subtlest logic in the project.
- `supervisor.py` is all the supervision there is. If either process exits, the
  container exits and Railway restarts it.

### Secrets

| Secret | Location |
|---|---|
| PSK, `kid`, local bearer key | `~/.cli-gateway/`, owner-only, outside the repo |
| PSK, internal CLIProxyAPI key | Railway service variables |
| OAuth files | Volume, `/data/cliproxy/auth` |
| Replay ledger | Volume, `/data/bridge/replay.sqlite` |

The repo carries example configuration only.

## Data flow

The wire protocol is specified in `protocol.md`: envelope, AAD layout, record types
and size limits.

1. Codex → local bridge. Check the local bearer key and the allowlist
   (`GET /v1/models`, `POST /v1/responses`, no query string).
2. Encrypt. Fresh 32-byte `rid` and timestamp. Derive request and response keys from
   the PSK with HKDF-SHA256. Seal metadata plus the raw body as one final secretstream
   record.
3. Local → Railway. `POST /poc/v1/exchange` through the configured proxy and CA. TLS
   verification is never disabled.
4. Remote bridge. Authenticate the whole request, check the timestamp is within 120
   seconds, commit `(kid, rid)` to the ledger, then call CLIProxyAPI on loopback with
   the internal key injected.
5. Response. NDJSON lines carrying encrypted records in order: `META`, `DATA`…,
   `HEARTBEAT` during silence, then `END` or `ERROR` with the final tag.
6. Local bridge → Codex. Release only verified plaintext. Hold the terminal Responses
   event until `END` verifies.

## Failure behaviour

| Failure | Result |
|---|---|
| Bad key, tampered or malformed envelope | Rejected before any upstream call; generic outer error |
| Replayed `rid`, including after restart | Rejected; exactly one upstream call ever |
| Stale timestamp | Rejected; check clock skew first |
| Ledger missing, corrupt or full | Fails closed until key rotation |
| Upstream 4xx/5xx | Status and body preserved inside the encrypted response |
| Unencrypted outer error (edge HTML, proxy block page) | Generic local gateway error; never passed on as model output |
| Stream cut, reordered or missing `END` | Local stream aborted; terminal event never released |
| Codex disconnects | Upstream call cancelled, target within 2 seconds |

Retries are off in both bridges, Codex and CLIProxyAPI. A retried request would need a
new `rid` and could spend quota twice.

## Build stages

| Stage | Work | Passes when |
|---|---|---|
| 0 | The two feasibility gates | Real model output locally and from Railway egress; streaming is incremental |
| 1 | `protocol.py`, test-first against fixed vectors | Byte-exact round trip; wrong key, flipped byte, changed context, reordered and truncated records all fail |
| 2 | Both bridges against a synthetic streaming upstream | SSE byte-for-byte; terminal event held until `END`; cancellation and upstream errors behave as specified |
| 3 | Ledger, container, Railway deploy | One envelope sent twice, concurrently and after restart gives exactly one upstream call; only `/poc/v1/exchange` and `/healthz` are public |
| 4 | Real network and adversarial checks | mitmproxy sees no prompt or reply canaries; bridge overhead p95 under 100 ms across 20 runs; memory measured |

The outcome of each stage is recorded further down.

## Operations

**Bootstrap, on a trusted network.** Generate the PSK, `kid`,
local bearer key and internal key locally. Set the remote ones as Railway variables
through the CLI. Move the OAuth files over `railway ssh`.

**Switching.** A Codex profile file plus a launcher script that starts the local bridge
and exports the local key, so using the gateway is one command.

```toml
# ~/.codex/gateway.config.toml
model = "gpt-6-astra"
model_provider = "encrypted_gateway"

[model_providers.encrypted_gateway]
name = "Encrypted gateway"
base_url = "http://127.0.0.1:8318/v1"
env_key = "CGW_LOCAL_API_KEY"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = 300000
```

**Keeping it alive.** An idle gateway drifts: OAuth refresh tokens lapse and Codex
updates past the tested version. A `smoke` command pushes one small request through the
whole path. Run it monthly and after Codex updates. It is not automated.

**Runbook.** Setup, switch, smoke test, key rotation, and troubleshooting ordered by
likelihood. It is self-contained, so operating the gateway never depends on
documentation elsewhere.

## Gate 1 results (13 October 2026): passed

Run locally with Codex CLI 0.160.1 against CLIProxyAPI in Docker, no encryption.

| Check | Result |
|---|---|
| Pinned release | v8.0.27, `eceasy/cli-proxy-api@sha256:b7cf456bf6ef7f6489f18144e7cc166dbb8b2e5f46d6ee8881a321aaea563730` |
| Config schema | v8 layout (`config-version: 8`), as used in `deploy/cliproxy.yaml` |
| Login | `-codex-login -no-browser` with `-p 127.0.0.1:1455:1455`. Callback port is 1455. The device-code flow is refused unless enabled in the account's security settings; it was left disabled |
| Models | 14 served, including `gpt-6-astra` |
| Profile file | A Codex profile file may define `[model_providers.*]` and is selected with `--profile <name>` |
| Tool-call cycle | Passed: model requested a shell command, Codex ran it, model answered with its output |
| Streaming | Incremental: first bytes at 0.8 s, last at 13.7 s, 261 chunks for a 200-word answer |
| Cancellation | Client dropped at 4.0 s; the proxy ended the request at 4.006 s. Whether upstream stops generating cannot be observed from here |
| Access control | No key gives 401; management API and panel give 404 |

### What Codex sends

- Transport: HTTP/1.1 `POST /v1/responses`, `accept: text/event-stream`, uncompressed
  JSON body. `codex exec` made no `GET /v1/models` call.
- Body: 69 to 76 KB for a one-line prompt, far under the 8 MiB limit. Top-level keys:
  `client_metadata`, `include`, `input`, `model`, `parallel_tool_calls`,
  `prompt_cache_key`, `reasoning`, `store`, `stream`, `text`, `tool_choice`.
- Headers to allowlist in the bridge (1.2 KB in total, under the 8 KiB metadata limit):
  `accept`, `content-type`, `originator`, `user-agent`, `session-id`, `thread-id`,
  `x-client-request-id`, `x-codex-beta-features`, `x-codex-turn-metadata`,
  `x-codex-window-id`, `x-openai-internal-codex-responses-lite`.
- A plain request with only `authorization`, `content-type` and `accept` also works.
- `x-codex-turn-metadata` carries installation and session IDs. It travels inside the
  encrypted metadata, never in the outer request.

### What CLIProxyAPI returns

- SSE events in order: `response.created`, `response.in_progress`,
  `response.output_item.added`, `response.content_part.added`,
  `response.output_text.delta`…, `response.output_text.done`,
  `response.content_part.done`, `response.output_item.done`, `response.completed`.
- The terminal event `sse.py` must hold is `response.completed`.
- Response headers include `Access-Control-Allow-Origin: *` and `X-Cpa-Trace-Id`. The
  remote bridge must drop these and forward only `content-type`.

### Findings that affect the deployment

- At startup CLIProxyAPI makes unrelated outbound calls (version lookups for other
  providers, to npm and elsewhere) and refreshes model catalogs from remote sources
  every 3 hours. Start it with `-local-model` on Railway and review the remaining
  outbound traffic.
- The image defaults to a UTC+8 timezone. The bridge must use Unix time, never the
  container's local clock.

## Gate 2 results (13 October 2026): passed

Run on a new Railway account, Hobby plan, region `iad` (US East).

| Check | Result |
|---|---|
| Streaming through the Railway edge | 300 of 300 lines over five minutes, in order, largest gap 1.3 s. The edge does not buffer |
| Upstream egress | A real streamed request from inside the container returned model output. Upstream accepts Railway's IPs |
| No public exposure | The `gateway` service has no domain; CLIProxyAPI listens on `127.0.0.1:8317` only |
| Credential provisioning | Credential file piped over `railway ssh` stdin into `/data/cliproxy/auth`, verified by SHA-256, mode 0600 |
| `-local-model` | Works: 14 models from the embedded catalog, including `gpt-6-astra` |
| Idle footprint | 46 MB RAM, under 0.01 vCPU, 85 MB of the 5 GB volume |

Idle cost is roughly $0.50 a month at Railway's published memory rate (about $10 per
GB-month, to be rechecked), well inside Hobby's included $5. The Python bridge will add
to this.

### Railway resources

One project with one service, `gateway`, and one 5 GB volume mounted at `/data`.
`railway status` shows their identifiers. A throwaway `probe` service carried the
streaming test and was deleted afterwards; its code stays in `probe/` and can be
redeployed to diagnose a network later.

### Operational notes from gate 2

- `railway ssh` and `railway volume files` need an SSH key registered with Railway, and
  the CLI finds keys only in the SSH agent or `~/.ssh`. The project key is
  `~/.cli-gateway/railway_ed25519`. Load it with `ssh-add` before using `railway ssh`;
  the agent forgets it on logout.
- `railway volume add` crashes when given a service name. Pass the service ID.
- Service variable `CGW_CLIPROXY_KEY` holds the internal CLIProxyAPI key. It was
  generated at deploy time and exists only on Railway.
- During the gates the same OAuth login existed in two places, the Railway volume and
  a local directory. Only one may stay in use, because a token refresh by one copy can
  invalidate the other. The local copy was deleted once the gateway was verified.
- A workspace usage limit is optional; the runbook's "Cost" section explains it.

## Stage 1 results (13 October 2026): passed

`src/cgw/protocol.py` was written test-first: 203 tests, all passing.

- **Independent reference.** `tests/wire_reference.py` builds the wire format straight
  from the specification with raw libsodium calls and shares no code with the module.
  The implementation opens what the reference seals, and the reverse.
- **Frozen vectors.** `tests/fixtures/protocol_v1.json` was generated by the reference.
  A failure there after an upgrade means the wire format changed.
- **Mutation check.** 26 single-rule weakenings of the module (dropping an AAD field,
  skipping the final-tag check, accepting duplicate JSON keys, off-by-one limits and so
  on) were each caught by the suite.

Run the tests with `uv run pytest`. Dependencies are pinned in `uv.lock`: PyNaCl 1.6.2,
cryptography 50.0.2, Python 3.13.

### Protocol details settled in stage 1

The original note leaves these open or states them more strictly; the implementation does this:

| Point | Decision | Reason |
|---|---|---|
| Records before `META` | `HEARTBEAT` and `ERROR` are allowed before `META`; `DATA` and `END` are not | Upstream can be silent or fail before it returns headers. The doc says only that `META` is the first record |
| Empty `DATA` | Rejected | The sender never needs one, and it would be a cheap way to pad a stream |
| `ERROR` payload | JSON object, at most 1 KiB | The doc says "small" without a number |
| `META` payload | Exactly `status` (100 to 599) and `headers` (string to string), at most 8 KiB | Bounds what an authenticated but buggy peer can send |
| After a rejected record | The opener stays failed; no later record is accepted | A caller cannot skip a bad record and carry on |
| Unknown `kid` | Same error as a wrong key | Does not reveal which key identifiers exist |

## Stage 2 results (13 October 2026): passed

Both bridges, the SSE gate, the ledger, configuration, the command line and the process
supervisor were written test-first. On that date the suite was 512 tests and passed on
consecutive full runs in about 90 seconds.

| Module | What its tests establish |
|---|---|
| `sse.py` | The terminal event is held until the stream verifies. Detection uses the JSON `type` in the event's data, because that is what Codex reads; the `event:` line alone is not trusted |
| `ledger.py` | Each request ID is accepted once, including under 16 concurrent attempts and after reopening. Missing, corrupt, foreign or full ledgers are refused |
| `remote_bridge.py` | Nothing invalid, stale, replayed or off the allowlist reaches upstream. Heartbeats, timeouts, upstream failures and client disconnects behave as specified |
| `local_bridge.py` | Run end to end through a hostile proxy that drops, flips, swaps, duplicates and injects records, cuts the connection, and sends an endless line. None of these yields a completion or releases unauthenticated bytes |
| `config.py`, `cli.py` | Secrets are validated and never echoed. `bootstrap` sends the key to Railway on stdin |
| `supervisor.py` | Either process dying takes the container down; the bridge waits for a ledger |

Bridge tests run real servers on loopback sockets, because streaming and disconnects do
not behave realistically in-process.

### Mutation checks

Beyond the 26 protocol mutations of stage 1, 51 single-rule weakenings of the bridges,
the streaming response and the SSE gate were applied to a copy of the tree. All 51 are
caught. Getting there exposed seven rules that had no binding test, each now covered:
header-injection characters in sealed headers, early rejection by declared length, the
size limit for bodies without a declared length, health when upstream answers but
refuses, a non-streamed response cut mid-body, a client leaving before any header, and
an endless response line.

### Defects found by the tests and fixed

| Finding | Fix |
|---|---|
| Replayed envelopes briefly occupied in-flight slots, so a replay flood could answer real requests with `busy` | The ledger is consulted first; only a fresh request takes a slot. A request refused as busy therefore consumes its ID, which is harmless because every attempt uses a new one |
| A stream using bare carriage returns as line endings never recognised its final event | The ambiguity of a trailing carriage return is resolved when the stream finishes |
| A client disconnect during upstream silence went unnoticed for up to a heartbeat interval (15 s) | Both bridges watch for the disconnect directly, not only for a failed write |

## Stage 3 results (13 October 2026): passed

Deployed to Railway as one container: `deploy/Dockerfile`, both base images pinned by
digest, Python packages installed with `--require-hashes` from `deploy/requirements.lock`.

| Check | Result on the live deployment |
|---|---|
| Public surface | Only `POST /poc/v1/exchange` and `GET /healthz` answer. Ten other requests, including CLIProxyAPI's management routes, return 404 or 405. No CORS headers; the only `Server` header is Railway's edge |
| Authentication | Wrong key, unknown key ID, altered timestamp, disallowed route, garbage and a browser `Origin` are all refused with a generic body |
| Replay | Same envelope twice: 200 then 409. Eight concurrent copies: one 200, seven 409. After a container restart: 409 |
| Fresh volume | The bridge stays down and nothing listens until `init-ledger` is run on purpose |
| Process isolation | CLIProxyAPI listens on container loopback only and receives none of the bridge's secrets |
| Logs | Railway logs contain no key, token, prompt or reply. One summary line per exchange |
| Codex | `codex exec --profile gateway` completed a tool-call cycle and a 123-word answer |
| Key rotation | Exercised once end to end; the old key is refused afterwards |

## Stage 4 results (13 October 2026): passed

| Check | Result |
|---|---|
| HTTPS inspection | mitmproxy, with its CA trusted by the local bridge, decrypted both flows. In 34,831 bytes of raw and base64-decoded traffic the prompt canary, reply canary, session header, model name, upstream path and every key were absent. Hostname, path and key ID were visible, as expected |
| Streaming through an inspector | With the inspector streaming: first bytes at 1.0 s, last at 10.9 s, matching the direct path. With the inspector buffering: nothing until the end |
| Cancellation | Client aborted a long generation at 3.0 s; the remote bridge recorded the exchange as aborted 0.4 s later |
| Bridge overhead | 40 runs each, loopback, 70 KB request body. Added total time: p95 7.6 ms for a 2 KB response, p95 52.7 ms for a 1.3 MB response. Target was 100 ms |
| Memory | About 105 MB for both processes under traffic |

### Not tested

- Proxy authentication and PAC files. No such proxy was available.
- The two-request concurrency limit on the live deployment. It is covered on loopback.
- Whether upstream stops generating when a request is cancelled. Only the gateway's side
  is observable.
- A network whose only way out is a restrictive, inspecting proxy.

### Changes to earlier decisions

| Earlier | Now | Reason |
|---|---|---|
| Local bridge gives up after 60 s of outer silence | 300 s | An inspector that buffers whole responses delivers nothing, heartbeats included, until upstream finishes. 300 s matches Codex's own idle timeout |
| Dockerfile path set in `railway.json` | Service variable `RAILWAY_DOCKERFILE_PATH` | Railway treats that config file as deprecated and did not pick it up |
| Env variable `POC_LOCAL_API_KEY`, provider `encrypted_poc` | `CGW_LOCAL_API_KEY`, `encrypted_gateway` | One consistent prefix across both ends |
| A `supervisor` process manager | `cgw/supervisor.py`, 36 lines | Enough for two processes and one replica |

## Security review after publication (14 October 2026)

A review of the first published commit found two defects. Both are fixed, each with
tests that fail without the fix.

| Finding | Fix |
|---|---|
| **Port squatting on the client.** The launcher treated "something is listening on the local port" as "the bridge is running". The bridge starts on demand, so the port is usually free; another local user could bind it and be sent the local key and every prompt | The bridge answers a challenge, `GET /cgw/identity`, with an HMAC of the caller's nonce under the local key. The launcher and the smoke test verify it before sending anything else, both before and after starting the bridge, and refuse an impostor. Tested with a program that holds the port and records what it receives: it gets only the identity probes |
| **Resource bounds placed after authentication.** The two-request limit applied only once a request had authenticated. Before that, any number of anonymous connections could each make the gateway buffer and parse 12 MiB, or stall an upload forever. An unhealthy gateway also probed upstream on every anonymous health request | Before any body byte is read: a `Content-Length` is required, and the request is admitted against a count limit (8) and a memory budget charged at the declared length (24 MiB). Uploads have a 30-second deadline. Authentication runs off the event loop. Health results are cached for both outcomes and only one probe runs at a time. The public listener caps open connections at 64 |

What remains, and is documented as a limit and not fixed:

- Codex does not verify the bridge's identity on each request. If the bridge stops
  while Codex runs, another local program could take the port.
- The new limits bound memory and work, not availability. A flood can still fill the
  budgets and cause `busy` answers.

## Second security review (14 October 2026)

A review of the fix commit found that two of its own limits could be used against it.

| Finding | Fix |
|---|---|
| **Admission lockout.** The admission limits could not tell a key holder from anyone else, because authentication happened only after the body was read. Eight stalled anonymous uploads filled them and real requests were refused, as the first fix had already demonstrated live | A keyed admission tag in a request header, checked before any budget is charged or any body byte is read. It is single-use and must match the envelope. Anonymous clients are refused from the request head alone. This changes the wire protocol (see `protocol.md`); a newer local bridge still works with an older gateway |
| **Connection cap held by idle connections.** The web server keeps a connection that never sends a request forever, and its cap counts it, so 64 idle connections locked everyone out | The public listener closes a connection that has not delivered a complete request head within 10 seconds; trickled bytes do not extend the deadline, and requests being served are never cut. The cap is raised to 1,024, against a container limit of 524,288 open files |

What remains: a sufficiently large sustained flood of connections can still exhaust the
connection cap. No application-level control fixes that; it belongs at the hosting
platform's edge.

## Further verification (14 October 2026)

Two items previously listed as untested were tested.

**A network whose only way out is a restrictive proxy.** A Docker client on an internal
network with no route out, whose only exit was a mitmproxy that required a password,
intercepted TLS and refused everything except the gateway. The repository was set up
beforehand.

| Check | Result |
|---|---|
| Direct connections | No route; names do not resolve |
| Any destination other than the gateway, through the proxy | Refused (403) |
| Proxy without a password | Refused (407) |
| Gateway without trusting the proxy's CA | TLS verification fails, as it should |
| `bin/codex-gateway setup` | `PASS`, and it tightened the copied config to owner-only |
| Codex through the launcher, with a tool call | Correct answer. Codex's own Linux sandbox cannot run inside an unprivileged container, so this run disabled it; that is a property of the test container |
| What the proxy decrypted | Neither the prompt, the reply, the model name, nor any key |
| Wrong proxy password | Reported as `proxy_refused`, a code added for this case |

**Whether a cancel reaches upstream.** Sampled read-only inside the live gateway: the bytes
CLIProxyAPI reads, and the state of its connections to port 443. A long generation was
cancelled by the client after 5 seconds, and an identical one ran to completion.

| | Result |
|---|---|
| Cancelled run | About 0.07 s after the client cancelled, CLIProxyAPI made its last read and closed its connection to the provider. No unread data was left on it, and nothing more was read |
| Uncancelled run | The same request kept streaming for 67.5 seconds |

The cancel therefore reaches the provider as a closed connection almost at once.
Whether its servers stop generating internally at that moment cannot be observed from
outside.

**Still not run:** the runbook's login-renewal and rebuild-from-scratch sections. Testing
them needs a throwaway gateway and two subscription sign-ins; the owner chose to skip that.

## Forward secrecy: protocol version 2 (14 October 2026)

Requested by the owner after the review showed that version 1 derived every key from the
pre-shared key alone, so a recording plus a later key theft would expose everything.

| Option | Verdict |
|---|---|
| Fold a key exchange into the response | Rejected: the request, which carries the prompt, would still be encrypted under the pre-shared key alone |
| A gateway key rotated every few minutes, fetched in advance | Rejected: saves the round trip, but a request is only protected once its rotated key has been deleted, and it adds key distribution and expiry handling |
| A fresh handshake per request | **Chosen.** Both directions of every request get forward secrecy, no key material outlives the request, and nothing is cached. It costs one round trip |

How it works is in `protocol.md`. In short: the local bridge and the gateway exchange
fresh X25519 public keys, authenticated with the pre-shared key; the traffic keys come
from the pre-shared key and the X25519 secret together; both private keys are dropped as
soon as they have been used, and the gateway's session waits in memory for at most 30
seconds and serves one exchange.

| Check | Result |
|---|---|
| Independent reference | `tests/wire_reference.py` builds the handshake with libsodium's X25519; the implementation uses the `cryptography` library's. They agree byte for byte, and the frozen vectors use fixed keys on both sides |
| Mutation check | 18 single-rule weakenings of the handshake, sessions and key derivation, each caught |
| Recorded traffic | A test captures a whole request on the wire and tries to open it with the pre-shared key plus every value seen on the wire; it fails |
| Cost on loopback | Bridge overhead p95 rose from 7.6 ms to 9.1 ms |
| Cost on the live path | One handshake round trip: median 68 ms. A model reply's first token takes 1 to 2 seconds, so the difference is small in practice |
| Live | Smoke test passes; a Codex session completed a tool call |

Version 2 cannot talk to version 1 in either direction; the old path now returns 404.

**A consequence for the replay ledger.** Sessions are single-use and do not survive a
restart, so a replayed envelope is now refused before the ledger is ever consulted. The
ledger is a third line of defence rather than the main one. Retiring it would remove the
`init-ledger` step and the gateway's dependency on its volume for anything but the
subscription login. That is left as a decision for the owner.

## Replay ledger removed (14 October 2026)

The owner chose to retire the ledger, as the previous section allowed for.

Version 2 had already made it redundant. Every exchange must authenticate against a
session that exists only in the gateway's memory, serves one exchange and lasts at most
30 seconds, and a restart loses every session. An envelope therefore cannot be accepted
twice whether or not its request ID is written down anywhere. Admission tags stay
single-use in memory as well, so a duplicate is refused before its body is read.

What changed:

- `ledger.py`, the `init-ledger` command and the ledger path setting are gone. The bridge
  keeps nothing on disk.
- The supervisor starts both processes together instead of holding the bridge back
  until a ledger exists. A fresh deployment needs no manual step before it answers.
- The `unavailable` error, which meant a missing, corrupt or full ledger, no longer
  exists. Neither does the 100,000-request ceiling that forced a key rotation.
- The volume holds only CLIProxyAPI's subscription login. A `replay.sqlite` left by an
  earlier deployment is unused and can be deleted (see the runbook, "Updating").

| Check | Result |
|---|---|
| Tests | 836 passing; a new test checks that serving a request writes nothing to disk |
| Replay | Same envelope twice: 200 then 409. Six concurrent copies: one 200, five 409, one upstream call. Sent again after a bridge restart: 400, still one upstream call |
| Mutation check | 20 single-rule weakenings, among them reusable admission tags and reusable sessions, each caught |
| Live | Deployed; `/healthz` returns 200 and the smoke test passes |

The sections above describe the gateway as it was at the time, ledger included.

## A key per machine (14 October 2026)

Requested by the owner: several machines use one gateway, and a new one should be able
to join without the Railway CLI. Until now every machine held a copy of the same key,
so one machine could not be shut out without re-keying all of them, a leak from any
one exposed them all, and the gateway could not tell them apart.

| Option | Verdict |
|---|---|
| One Railway variable per client, `CGW_CLIENT_<NAME>` | Chosen. An explicit list: removing a variable shuts that client out and nothing else. Railway's CLI or dashboard edits one variable at a time, and the list of names is the list of clients |
| One variable holding every client as JSON | Rejected: each change rewrites every key, and a dashboard edit can break them all at once |
| Client keys derived from one master key | Rejected: adding a client needs no restart, but removing one needs a deny-list that fails open if forgotten, and the gateway could not list who has access |

The wire protocol is unchanged: it always carried the client's `kid` and the gateway
always looked the key up by it. What changed:

- The gateway reads every `CGW_CLIENT_<NAME>` variable and admits exactly those. It
  refuses to start with none, with a malformed name, or with two clients holding the
  same key. `CGW_KID` and `CGW_PSK` are no longer read, so they admit no one.
- `python -m cgw add-client <name>` writes the new machine's config and, given
  `--railway-service`, sets its variable over standard input and redeploys. Without
  Railway it names the variable to add in the dashboard. `remove-client` deletes one
  and redeploys; it will not remove the last. `list-clients` prints names, never keys.
- `bootstrap` takes `--client-name`, so the first machine is a named client too.
- The exchange log line names the client.
- Only the admin needs Railway access. A new machine needs the file it is given.

Adding or removing a client restarts the gateway, which is the cost of an explicit list
held in environment variables. Both are rare. The two in-flight slots are shared by all
clients.

| Check | Result |
|---|---|
| Tests | 887 passing. Two clients served side by side; one client's name with the other's key, and an unknown name, refused; a removed client refused after the restart; the commands checked against a fake Railway CLI that keeps the variables |
| Mutation check | 15 single-rule weakenings of the new rules, each caught |
| Live | The deployed gateway moved over as the runbook describes: this machine named as the first client, deployed, the old single-key variables deleted. Smoke test passes with the new key; a handshake with the old shared key is refused with `rejected` |
| Railway behaviour | `railway variable delete` runs without a prompt and does not redeploy. `remove-client` therefore redeploys itself, or a removed client would keep working until the next deploy |

## A gateway for more than one tool (14 October 2026)

At the owner's request the project is described as what it has become: one secure
endpoint to a server that holds one or more subscriptions through CLIProxyAPI, meant for
several command-line tools rather than Codex alone. The protocol, the keys and the
gateway's limits are not specific to any tool. Three parts are, and each new tool needs
its own version of them:

- the allowlist of routes and headers in `src/cgw/policy.py`, today `GET /v1/models`
  and `POST /v1/responses` with the headers Codex sends;
- the SSE gate in `src/cgw/sse.py`, which holds Codex's terminal event,
  `response.completed`, until the stream verifies;
- the client setup: the Codex profile written by `install-profile`, and the launcher
  `bin/codex-gateway`.

The next section replaced all three with versions that need no knowledge of any one tool.

## Any tool, any host (14 October 2026)

Requested by the owner: the gateway should serve any command-line tool that CLIProxyAPI
supports, and run on any host, not only Railway.

### What the tools send

Each tool was pointed at a local recording sink that answered in its format. Each ran
from an empty home folder, so no settings or credentials of the machine were involved.
The sink recorded routes, header names and the shape of bodies, never their text.

| Tool | Version | Request |
|---|---|---|
| Claude Code | 2.1.299 | `POST /v1/messages?beta=true`, with `anthropic-version`, `anthropic-beta`, `x-stainless-*`, `x-app` and `x-claude-code-session-id`; the key as a Bearer token |
| opencode | 1.19.0 | `POST /v1/chat/completions`, with session headers of its own; the key as a Bearer token |
| Gemini CLI | 0.64.0 | `POST /v1beta/models/<model>:streamGenerateContent?alt=sse`, with `x-goog-api-client`; the key in `x-goog-api-key` |

Codex on this machine is now 0.162.1.

Three findings shaped the design. Two of the three tools send a query string, which the
gateway refused until now. Every tool sends headers of its own, which an allowlist would
have to know in advance. And each format sends its key in a different place.

CLIProxyAPI 8.0.27's own source settled two more questions. It accepts its client key
as a Bearer token on every route, so the gateway can always present its key that way.
And the only request headers it reads itself are the credentials, its management key,
`Anthropic-Version`, `User-Agent`, `Idempotency-Key` and `Content-Type`.

### Decisions

| Question | Decision | Reason |
|---|---|---|
| Which routes | CLIProxyAPI's routes for text models, in each of its three formats; the list is in `protocol.md` | One list covers every tool that speaks a format, where a list per tool would change with each new tool. The management API, media, realtime and websocket routes and sign-in callbacks stay unreachable. Model names in a path cannot contain a slash |
| Which headers | Pass everything on except a drop list: credentials, connection and proxy plumbing, forwarding and browser headers, and any name containing `management` | Headers travel inside the encrypted metadata, so passing them on reveals nothing on the wire. The headers CLIProxyAPI acts on that a client should not set are all on the drop list. A list of what to keep would have to know every tool |
| Query strings | Allowed: at most 1,024 characters, plain parameter names, no control characters, `key` and `auth_token` dropped. Carried in canonical form in a new, optional `query` metadata field, which the gateway accepts only in that form | Claude Code sends `?beta=true` and Gemini CLI streams with `?alt=sse`. CLIProxyAPI also accepts keys in the query, so a client's must not reach it |
| The local key | Accepted as `Authorization: Bearer`, `x-api-key` or `x-goog-api-key` | Each format sends its key in its own place |
| The stream gate | Release events one behind: the newest complete event waits for the next, the last for a verified `END` | Every format ends with the event that says it is done, so holding the newest event keeps a truncated stream from looking finished without knowing any event names. The cost is a delay of one event: each reaches the tool when the next one arrives. A verified stream that never says it is done is passed on as it is; the tool decides, as it would without the gateway |
| Running the tools | `bin/cgw codex`, `claude`, `gemini` and `run <command>`; `bin/codex-gateway` kept as an alias | Claude Code and Gemini CLI read an address and a key from the environment, so the launcher sets them for that run only. Claude Code's telemetry, error reports and update checks would go around the gateway, so they are switched off for gateway runs. Gemini CLI reads its sign-in method from its settings; a system-settings override did not win over a user's own choice in a test, so gateway runs get a settings folder of their own (`GEMINI_CLI_HOME`) |
| Where the gateway's keys live | `--env-file`, an owner-only KEY=VALUE file, or `--railway-service`, as before | An env file is what Docker Compose and most hosts read. The commands refuse a file that others can read, and write it whole, owner-only, on every change |
| Any host | Docker Compose: the gateway behind Caddy, both pinned by digest | Caddy obtains and renews the certificate by itself and passes the stream on as it arrives (`flush_interval -1`). The env file stays out of git, the image's build context and Railway uploads |

The pinned CLIProxyAPI has no sign-in for Gemini CLI accounts. Gemini models come
through `-antigravity-login`, with a Google account, or through a Gemini API key in its
configuration, which this project does not set up.

### Checks

| Check | Result |
|---|---|
| Tests | 940 passing. Each format streams through both bridges byte for byte and incrementally. A stream cut before its last event never shows its ending, in any format. Queries reach upstream canonical and without credentials. Credentials and plumbing headers never leave the machine, whichever header carried the local key. The env-file store adds, removes and lists clients, keeps other lines, and refuses a file others can read |
| Docker Compose, on one machine | With `CGW_DOMAIN=localhost` and Caddy's own certificate authority: `/healthz` through Caddy with strict TLS; the whole encrypted path answered (an empty model list, since nothing was signed in); a client added to the env file was accepted after `docker compose up -d`, which recreated only the gateway container; a removed client was refused after the next restart |
| Not run | A public certificate on the Compose recipe, and a real subscription sign-in on it |
| Live, Railway | Deployed. Smoke test passes in the responses format and the chat format. Codex 0.162.1 completed a shell tool call through `bin/cgw codex`. opencode 1.19.0 answered correctly through `bin/cgw run opencode`, both of its requests going through chat completions |
| Live, Railway, after the Claude and Antigravity sign-ins | Both appeared in the model list without a restart. Smoke test passes in the Anthropic format (`claude-haiku-5-5`) and the Gemini format (`gemini-3-flash`). Claude Code 2.1.299 completed a shell tool call through `bin/cgw claude` (two `/v1/messages` requests). Gemini CLI 0.64.0 completed a shell tool call through `bin/cgw gemini` (two `streamGenerateContent` requests), once given a model name the gateway serves: it rewrote `-m gemini-3-flash` into `gemini-3.8-flash`, which upstream refused with 400, passed on unchanged |

### Review of this change

A security review of the commit found two weaknesses, both fixed with tests that fail
without the fix.

| Finding | Fix |
|---|---|
| **Header drop list let compression through.** With the keep list, `content-encoding` never reached CLIProxyAPI. Now it does, and CLIProxyAPI decodes zstd request bodies with no size limit by default, so a client key could send a body under the gateway's 8 MiB cap that expands without bound inside the container. Headers starting with `x-cpa-`, CLIProxyAPI's own controls, also passed | `deploy/cliproxy.yaml` sets `server.max-request-body-bytes` to 32 MiB, which bounds the decoded body. Checked against the pinned CLIProxyAPI: a zstd body expanding to 40 MiB is refused with 413; with the default it was decoded in full. `x-cpa-` headers are dropped. Compression itself stays allowed, because CLIProxyAPI supports it for Codex |
| **Env-file writes through a predictable temporary name.** The key store wrote to `<file>.tmp` with `O_CREAT`, so a file or symlink planted there would keep its own permissions or redirect the keys | The store writes through a randomly named file created exclusively and owner-only (`mkstemp`), then renames it into place |

## Signing in through the gateway (14 October 2026)

Requested by the owner. Signing the gateway in to a subscription meant running
CLIProxyAPI's sign-in in Docker on one's own machine and copying the resulting token
file onto the gateway in a way that differs per host (`railway ssh`, `docker compose
cp`), with the tokens sitting on the local disk in between.

CLIProxyAPI's management API already signs in remotely: it hands out a provider's
sign-in address, accepts the address the browser is sent back to, and reports when it
has turned that into tokens, on the server. The PKCE verifier, where the provider uses
one, never leaves the server.

| Option | Verdict |
|---|---|
| Expose CLIProxyAPI's own management panel through the gateway | Rejected: it reaches the whole management API, including configuration, API keys, plugins and downloading the token files |
| A public sign-in page served by the gateway | Rejected: an internet-facing admin surface, next to an endpoint that otherwise refuses anyone without a key from the request head alone |
| An upload endpoint for token files | Rejected: the tokens would still be created on the admin's machine and travel from it |
| **An admin-only slice of the management API, through the encrypted channel, with a local page and commands** | Chosen. Five requests (start a sign-in, hand back the redirect, follow its status, list sign-ins, remove one); tokens are created on the gateway and never leave it; the same on every host |

**Who may do it.** Granting admin rights is anchored in access to the gateway's host,
the strongest credential the owner already protects: `grant-admin` sets a variable in
the same place as the client keys, and no request over the network can grant it. An
admin cannot make another machine an admin, so a stolen admin key cannot spread.
`bootstrap` makes the machine that sets up the gateway its first admin.

**How the right is held.** A simple list of admin names would let a copied
`config.json` manage sign-ins too. Instead each admin has a second, separate key
(`CGW_ADMIN_<NAME>`, `kid` `admin_<name>`), kept in `admin.json` encrypted with a
passphrase: Argon2id at libsodium's moderate setting (about 2 seconds and 256 MiB here),
then libsodium's secretbox, with the gateway address and `kid` inside the sealed part.
A copied `config.json` gives model access only; a copied `admin.json` is useless without
the passphrase. A hardware-backed key would also resist malware running while the
passphrase is typed; it is left for later.

**What the gateway allows.** The rules are in `protocol.md`, "Admin keys": an admin key
reaches only the five requests, a client key none of them. The management API is
switched on only once a management key exists, rendered into CLIProxyAPI's
configuration (CLIProxyAPI replaces it with a bcrypt hash on load), still loopback-only
with its panel off; the remote bridge presents that key on admin requests only. The
list of sign-ins is cut down to harmless fields before it leaves the gateway, so
identity tokens and file paths stay inside. Removing takes exactly one file name; the
"remove all" form and CLIProxyAPI's in-container callback listener are refused.

**The local page.** `cgw admin` serves it on `127.0.0.1` only while it runs, holding the
decrypted admin key in memory. A one-time link, printed in the terminal, trades its
token for an HttpOnly, SameSite=Strict session cookie. Every request must name the
page's own host, which defeats DNS rebinding. Every action must come from the page's
origin with a custom header that other sites cannot send without a CORS preflight,
never approved. A strict Content-Security-Policy allows scripts and styles from the
page only, and framing and caching are refused. The provider's redirect is caught by a
listener on that one loopback port and path, for as long as the sign-in waits; when the
port is taken, the address can be pasted instead.

### Checks

| Check | Result |
|---|---|
| Tests | 1,034 passing. Remote bridge, 23 admin tests: an admin key starts a sign-in and the management key is presented for it; the whole round trip; the list leaves without tokens or paths; removing one sign-in; 13 requests refused, among them `all=true`, `is_webui`, a path climbing out, two names, the file download, configuration, plugins and the model routes; a body on `DELETE`; a client key managing; no management key; the audit line. Admin tools and page, 18 tests: a sign-in caught locally and completed on the gateway; a refused sign-in; the paste path when the port is taken; a machine that is not an admin refused before anything reaches upstream; the catcher answers only its own path and only for loopback addresses; the one-time link, the cookie's flags, the host, origin and header checks, the security headers, a sign-in from the page and a list without tokens. Commands: bootstrap writes an encrypted admin key; a short or mismatched passphrase leaves nothing behind; grant, revoke and remove; the key file refuses a wrong passphrase, loose permissions, tampering and overwriting |
| Mutation check | 25 single-rule weakenings, each caught. Three survived the first run (the key file accepting a short passphrase, the catcher accepting any redirect host, the gateway starting with admin keys but no management key) and got tests of their own. An earlier run also found that an error raised while reading the upstream left the stream open; it now ends with an error |
| Docker Compose, on one machine, with the real CLIProxyAPI | The rendered management key was replaced by its bcrypt hash. The filtered list of sign-ins came back empty. Sign-in addresses were obtained for Claude (claude.ai, PKCE, `localhost:54545/callback`), Codex (auth.openai.com, PKCE, `localhost:1455/auth/callback`) and Google through Antigravity (accounts.google.com, **no PKCE**, `localhost:51121/oauth-callback`), each with status `wait`. A request for `/v0/management/config` with the admin key was refused. In a real browser, the page rendered under its Content-Security-Policy and the one-time link left no token in the address bar |
| Live, Railway | Deployed, then `grant-admin` run on a gateway set up before admin keys: it set the admin and management keys and restarted the gateway once. From `bin/cgw admin`, one old sign-in was removed and Claude signed in again; the gateway logged each step as a `manage` line with upstream status 200: list, `DELETE`, `anthropic-auth-url`, `oauth-callback`, `get-auth-status` twice, list. The volume then held the new Claude sign-in beside the Codex and Antigravity ones. Without a restart, a messages-format request to a Claude model passed, as did the default smoke test |

Google's sign-in uses no code verifier, so for it a program already running on the
admin's machine that took port 51121 first could use a caught code itself. That is the
same limit as for any program running as the owner.

## Less to read from the traffic: protocol version 3 (16 October 2026)

Requested by the owner after a review of what a network that inspects HTTPS sees of the
gateway's traffic. Version 2 protected content, but its traffic showed three things it
need not:

- **The client's name**, in clear in the admission header and in every handshake and
  envelope, with `admin_` marking an admin key. Every request from a machine carried the
  same identifier.
- **The exact length of every response record.** The remote bridge sealed each upstream
  read as it came, unpadded. Reads often followed streamed events, exposing their exact
  lengths; TCP buffering could merge or split those events. Published token-length
  attacks motivated reducing this signal; no such reconstruction was demonstrated
  against this gateway.
- **The exact timing of every record.** Whisper Leak used packet sizes and timing
  together to infer what a conversation is about.

Several providers padded their own streams after those papers. That protects their own
connection, which here starts at the gateway, not the network the client is on, and
whether any such padding survives CLIProxyAPI has not been checked.

| Option, response timing | Verdict |
|---|---|
| Padding only | Rejected: lengths become buckets, but record counts and timing can still follow upstream events |
| A fixed 50 ms grid | **Chosen.** Batches adjacent upstream bytes and schedules emission on ticks. Occupied ticks, size buckets, counts, pauses and duration stay visible. Adds up to one tick of deliberate delay for available data at an unblocked relay; backpressure can add more. Measured costs are below |
| A constant rate, with filler when upstream is quiet | Rejected: hides pauses too, but sends about 14 KB/s for as long as a stream is open, through every silence |

| Option, request sizes | Verdict |
|---|---|
| Padmé, at least 4 KiB | **Chosen.** Rounding adds at most 6.25% to the length including its marker and floor; floor expansion and base64 are additional. A length reveals a size bucket, not merely an order of magnitude |
| Powers of two | Rejected: up to double the upload, for little more |

| Option, the client's name | Verdict |
|---|---|
| Meaningless client names | Rejected: costs nothing, but admin keys still say `admin_`, and every request still carries one fixed identifier |
| A random identifier per client on the wire | Rejected: hides the name and the kind of key, but stays one fixed identifier per machine, and changes the config format |
| No identifier: the gateway tries every key | **Chosen.** Removes the explicit stable client identifier and role. The handshake and exchange remain linked by `hid`, and network metadata can link calls. Every key is checked; the gateway caps the combined client/admin set at 64 |

| Option, moving over | Verdict |
|---|---|
| Both versions for a while | Rejected: machines could update at their own pace, but every version-2 request would keep showing what version 3 hides, and both versions would need tests |
| A hard cut, as from version 1 to version 2 | **Chosen.** Keys, configs and variables stay as they are: deploy the gateway, then `git pull` on each machine. Until then a machine gets `bad_gateway_response`. A local bridge left running from version 2 is replaced by the launcher |

How it works is in `protocol.md`, under "Admission tag", "Padding" and "Timing". What a
network observer still sees is listed there under "Concealment". This is not traffic
camouflage: the gateway's hostname and the fact that it is in use stay visible.

Implementation checks, 16 October 2026:

| Check | Result |
|---|---|
| Full local suite | 1,201 tests passed in 233.19 s before final documentation and benchmark-harness additions; 1,236 in 237.43 s after both follow-up reviews below; 1,253 in 240.88 s once the local bridge waited for a place; 1,255 in 244.27 s once the gateway also refused handshakes while full |
| Final focused checks | 381 passed, followed by 3 new endpoint-mapping cases passing after correcting their test configuration; duplicate-JSON checks and restart guidance were also rechecked |
| Independent reference and frozen v3 vectors | Passed, including request floor and response bucket boundaries, all record types, and both interoperability directions |
| Captured traffic | Four API formats and an admin request round-trip; client-name, prompt and key canaries absent from outer traffic |
| Grid and equal-size comparisons | Fake-clock tests cover batching, idle ticks, heartbeats, late wakeups, slow writes, a large monotonic clock, the deadline and slow consumers; equal buckets produce equal line-length traces, crossing a bucket does not |
| Mutation checks | All 23 targeted weakenings caught by behavioral failures; import/collection errors, runtime exceptions and timeouts are not accepted as kills |
| Launcher | Actual Bash tests with controlled process stubs cover old/current/impostor listeners, changed PIDs, failed replacement, TERM timeout, an old bridge that outlives its listener, a listener that closes between two probes, concurrent launchers before and after each check, and `stop` and `status` |
| Full-backlog disconnect | A real loopback exchange blocks its upstream reader on a full backlog; disconnect cancels that reader and releases the only in-flight slot for the next request |
| Review | Inline self-review, then a follow-up code review whose findings are fixed below; no independent security audit |
| Live, Railway: deployment | Deployed from `f3b69b0`, as a hard cut. Before it: the keys were within the limit, with no duplicate PSKs, and the v3 loader accepted the deployment's variables. After it: `/healthz` answered 200, `/poc/v2/handshake` 404, and a v3 handshake without an admission tag was refused as `rejected` from its head alone. The first `bin/cgw smoke` replaced the machine's v2 local bridge by itself |
| Live, Railway: formats and tools | Smoke tests pass in all four formats: responses and chat (`gpt-6-astra`), messages (`claude-haiku-5-5`) and Gemini (`gemini-3-flash`), first bytes after 1.3 to 2.7 s. Codex CLI 0.163.0 (`bin/cgw codex exec`) and Claude Code 2.1.301 (`bin/cgw claude -p`) each completed a shell tool call. Gemini CLI was not installed on the test machine; its API format is covered by the smoke test |
| Live, Railway: captured traffic | A capture proxy between a local bridge and the live gateway recorded two streamed requests, in the responses and messages formats: 282,081 bytes of outer traffic, raw and base64-decoded. The client name, the PSK, the local key, a prompt canary, both model names and both upstream paths were absent. Both handshakes were 179 bytes, their replies 111, and both exchanges 5,665 bytes, padded to the 4 KiB floor. All 79 response records were padded to 512-byte steps. Records arrived in groups spaced within 6.7 ms of a multiple of 50 ms (median 1.5 ms and 0.3 ms for the two streams), across the internet |
| Live, Railway: admin | `bin/cgw subscriptions` with the admin key listed the gateway's three sign-ins, all active. The gateway logged it as a `manage` line for the admin, `GET /v0/management/auth-files` with upstream status 200: it told the admin from the clients by the key alone, with no role on the wire |
| Live, Railway: concurrency | Claude Code sends several requests at once, and a session started through `bin/cgw claude` passes the gateway's address and key to its hooks and plugins: a plugin's background sync kept sending `/v1/messages` requests for about a minute after the run ended. Together they far exceeded the two in-flight places: 27 requests were served, 77 refused as `busy` and retried, and 6 abandoned by the client. Every run still completed. Version 2 had the same limit. This led to the local bridge waiting for a place (below) |
| Live, Railway: waiting for a place | The same Claude Code run, plugin sync included, once the local bridge waited for a place: 17 requests served, none refused as `busy` by the gateway, none failed towards a tool. The queue alone did this: no request needed a retry, so the result stands for the corrected version below. 21 waiting requests were abandoned by their client, two or three at the same instant each time, just after another of its requests succeeded. The plugin had less left to sync than in the first run, so the counts are not a matched comparison |

`tests/benchmark_v3.py --runs 40` measures a 70,000-byte request through loopback HTTP,
including the capture proxy, against the same upstream directly. One warm-up pair is
excluded; direct/gateway order alternates. Percentiles use nearest rank. Added latency
is the percentile of paired gateway-minus-direct samples, not a difference of percentiles.
These figures are from a run after the follow-up fixes below, with nothing else running;
they are observations from this machine, not production latency guarantees.

| Response | Added first byte/event p50 / p95 | Added total p50 / p95 | Median outer response body bytes |
|---|---|---|---|
| 2,000 bytes, buffered | 77.6 / 81.1 ms | 77.6 / 81.2 ms | 4,389 |
| 1,300,000 bytes, buffered | 330.3 / 334.4 ms | 330.5 / 334.5 ms | 1,792,348 |
| 20 SSE deltas, 10 ms requested spacing; 2,199 upstream bytes | 92.1 / 96.9 ms | 73.9 / 77.8 ms | 5,927 |

Outer request bodies total 95,956 bytes for each handshake/exchange pair. Response byte
counts also include both responses. They exclude HTTP headers, chunk framing and TLS;
large-response totals varied from 1,792,348 to 1,793,031 bytes and streaming totals from
5,245 to 6,609 because upstream read boundaries and tick occupancy vary. The stream
measurement is the first forwarded complete SSE event, not the first model text token.
Buffered responses are released only after their authenticated FINAL record.

The backlog holds at most 256 KiB of DATA, however many chunks upstream sends it in. One
snapshot per 50 ms tick therefore limits sustained DATA release to at most about 5 MiB/s
before other overhead; a fast 1.3 MB burst needs multiple ticks. This exceeds the earlier 100 ms overhead target for
large buffered replies. The earlier 7.6/52.7 ms historical figures and v2's 9.1 ms small
reply p95 used different harness conditions and are not a matched v2/v3 comparison.
No complete historical first-event p50/p95 dataset exists.

Admission validation, including parsing and all HMAC comparisons, took p50/p95
6.4/8.8 µs with 1 key, 14.6/19.5 µs with 16, and 40.0/42.4 µs with 64 in 40 batches
of 100 checks, with each key's HMAC prepared once at startup. Before that change, with
the suite running alongside, 64 keys took 56.9/58.5 µs. These timings are descriptive;
tests count all evaluations rather than using noisy timings as evidence of
constant-time execution.

### Follow-up review (16 October 2026)

A review of the implementation against `protocol.md` found the defects below. Each is
fixed, with a test or mutation check that fails without the fix.

| Finding | Fix |
|---|---|
| **Small upstream chunks held back.** The relay's queue held at most 16 items, and each upstream HTTP chunk was one item, so an upstream that sends one event per chunk was held to 320 chunks a second: 2,000 small events took 6.3 s through the remote bridge | The backlog is bounded by bytes, 256 KiB, not by chunks, and each tick releases everything that has arrived. The same 2,000 events take 0.08 s |
| **A finished reply reported as a timeout.** When the 600 s deadline passed between upstream's last byte and the next tick, the timeout replaced the completed reply | A reply that finished by that tick is delivered whole. Otherwise the tick sends what has arrived, then the timeout |
| **A copied `hid` blocked another client's handshake.** Waiting sessions were filed by `hid` alone. A key holder who copied another client's `hid` from its clear admission header could make that client's handshake fail as `busy`, logged as `sessions_full` | Sessions are filed per client, so another client's `hid` reaches nothing. A duplicate from the same client, which admission already refuses, is answered `rejected`. The places themselves stay shared: one key holder can still fill the 256 waiting handshakes, as it can the two in-flight slots (`protocol.md`, "Availability") |
| **Replacement after an update failed needlessly.** The launcher waited about 7 s for the old bridge's process to exit, though it may take 10 s to finish a stream it is serving. A second launcher started at the same moment failed because the first had already replaced the bridge | The launcher waits for the port to be free, not the process. A bridge that another launcher stopped or replaced in the meantime is used as found |
| **Misleading messages.** A replacement bridge that proved itself but spoke another version was reported as an impostor. Every outer 404 told the user to update the gateway, even when a proxy or a wrong address had answered | Each message names its likely causes |
| **`stop` and `status` matched a command line.** Both found the bridge with `pgrep -f` | Both use the PID of the listener from `lsof`. `stop` signals it only if it proves itself this gateway's bridge |
| **Tamper tests that no longer reached the decryption.** The tests that change `ts` or `rid` were refused by the comparison with the admission tag, so they no longer showed that the AAD binds those fields | The admission in those tests names the changed values too. A mutation that drops `ts` from the AAD is now caught |
| **Avoidable work.** Admission keyed 64 HMACs afresh for every request, anonymous ones included. Removing request padding copied the plaintext twice and the body once more. An idle stream woke every 50 ms. Each record was its own write | HMACs are keyed once at startup, about 25% less per check at 64 keys. Removing padding copies the plaintext at most once: its peak memory fell from 1.95 to 0.97 times the padded size. An idle stream waits for data, a heartbeat or the deadline. A tick's records leave as one write. A check that could never fail and a comment that still put the client's name on the wire were removed |

Most of the remaining peak memory for a maximum request, about five times its body,
comes from parsing the JSON envelope and decoding its base64 before decryption.

A second review, of these fixes, found the problems below. Each is fixed, with a test
or mutation check that fails without the fix. Two were reproduced against a real
server or event loop first.

| Finding | Fix |
|---|---|
| **The launcher could still fail the replacement.** The old bridge closes its listener on the server's next tick after TERM. When that fell between the launcher's two probes, the free port looked like a changed listener: 4 of 15 replacements failed against a real server. A second launcher still failed if the first stopped or replaced the bridge after its own check | A listener that vanishes between probes is looked at again. When the listener changes during the upgrade, the port is checked once more: free, or the current bridge, is success. Anything else is still left alone |
| **Heartbeats drifted.** The next heartbeat counted 15 s from when the last write finished, not from the record's tick, and float rounding at a large monotonic clock (about 115 days of uptime) put ticks one late | The grid keeps its schedule in whole ticks: a heartbeat falls exactly 300 ticks after the last record, and the deadline on a fixed tick |
| **The grid outlived its stream.** A stream closed while a write was blocked left the grid to be closed later by the garbage collector | The stream closes the grid as it closes |
| **Prepared keys could be skipped.** `open_admission` quietly prepared a plain mapping on every call, which would bring back the cost just removed | It accepts only prepared keys |
| **A memory claim without a test.** The test covered removing padding, not the split into metadata and body | That split has a function and a test of its own, and a mutation that copies the plaintext is caught |
| **Two overstatements.** The fix log claimed that one client can no longer block another, and that a finished reply is always delivered at the deadline | One client can still crowd out others through the shared places; a reply whose last bytes the backlog still holds is cut off at the deadline. Both are now stated in `protocol.md` |

### Waiting for a place (16 October 2026)

The two in-flight places proved tight for Claude Code on the live gateway (above).
Raising the limit would loosen the bound on the gateway's work for every client, so the
local bridge waits instead. It sends at most two requests at once and holds the rest in
order; a request keeps its place until its response is over, an event stream until it
ends. A handshake refused as `busy` is tried again after a pause growing from 0.1 to
2 s, for up to 120 s in all. Against a remote bridge, twice as many concurrent requests
as it has places all completed, where half of them had failed before.

The first version also sent an exchange refused as `busy` again, reasoning that `busy`
comes before anything is sent upstream. A security review of that commit pointed out
that the refusal is not authenticated: someone on the path could let the exchange
through, then replace the gateway's answer with a forged `busy`, and the bridge would
deliver the request twice, breaking at-most-once delivery. Only a refused handshake is
retried now, since nothing that could be forwarded has been sent before it succeeds. An
exchange refused as `busy` is reported as before. Four mutation checks cover the
handshake retry, the queue, a stream's place and that a refused exchange is never sent
again.

So that another machine's traffic is also waited for, the gateway now refuses a
handshake as `busy` while both places are taken, before reading its body: its exchange
would be refused anyway. Requests then meet the limit where trying again is safe. Only a
place taken in the moment between a request's handshake and its exchange still reaches
a tool as `busy`. A fifth mutation check covers the gateway's refusal.

## Known limits

- No protection against a pre-shared key that is stolen and then used. Forward secrecy
  (protocol version 2) protects past traffic only.
- Does not hide that a gateway is in use. The hostname stays visible, and so do timing
  and sizes, to the precision protocol version 3 leaves (`protocol.md`, "Concealment").
- No protection if the local device itself is monitored or compromised. That includes
  an admin's passphrase typed on it.
- No help during an upstream outage or loss of account access.
- CLIProxyAPI is a community bridge. Subscription terms, quotas and model access still
  apply.

## Not built yet

- Recipes for hosts other than a Docker host and Railway. Fly.io, Render and others can
  run the same image, but have no tested recipe and no key-store option of their own;
  `add-client` without an option names the variable to set by hand.
- Wiring a Gemini API key into CLIProxyAPI's configuration.
- A hardware-backed admin key, such as a security key or the Secure Enclave.
- Sign-ins that use a device code rather than a browser redirect: the commands would
  only follow their status, and none has been tried.
- Websocket, realtime, image, audio and video routes.
- Automatic failover, more than one gateway instance, and traffic camouflage.

## Sources

- Railway free trial: https://docs.railway.com/reference/pricing/free-trial
- CLIProxyAPI repository: https://github.com/router-for-me/CLIProxyAPI
- CLIProxyAPI config template: https://raw.githubusercontent.com/router-for-me/CLIProxyAPI/main/config.example.yaml
- CLIProxyAPI quick start: https://help.router-for.me/introduction/quick-start.html
- CLIProxyAPI Railway template: https://railway.com/deploy/cliproxyapi
- Codex CLI: https://github.com/openai/codex
- Weiss et al., "What Was Your Prompt? A Remote Keylogging Attack on AI Assistants", USENIX Security 2024: https://www.usenix.org/conference/usenixsecurity24/presentation/weiss
- Whisper Leak, as reported: https://www.theregister.com/2025/11/11/llm_sidechannel_attack_microsoft_researcher/
- Cloudflare's padding of its own AI streams: https://blog.cloudflare.com/ai-side-channel-attack-mitigated
- Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (Padmé), PETS 2019: https://www.petsymposium.org/popets/2019/popets-2019-0056.php
