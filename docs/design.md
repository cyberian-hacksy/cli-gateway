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

## Known limits

- No protection against a pre-shared key that is stolen and then used. Forward secrecy
  (protocol version 2) protects past traffic only.
- Does not hide that a gateway is in use; hostname, timing and sizes stay visible.
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
