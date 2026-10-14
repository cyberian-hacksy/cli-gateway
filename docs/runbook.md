# Runbook

Operating a gateway that is already deployed. To set one up, see the README.

This file is self-contained on purpose. The Codex documentation lives under
`chatgpt.com`, so it disappears in exactly the situation this gateway exists for.

In the commands below, `<gateway-url>` is your gateway's address. `bin/codex-gateway
status` prints it.

The everyday commands, the troubleshooting checks, the ledger count and the key
rotation were all run against a live deployment, with the real address in place of the
placeholder. "Renewing the upstream login" was not run in this form; it says so again
where it starts.

## What is running

```
Codex --profile gateway
   │ plain HTTP, loopback
   ▼
local bridge 127.0.0.1:8318        this machine; encrypts requests, verifies responses
   │ HTTPS, encrypted envelope
   ▼
<gateway-url>                      one container on Railway
   remote bridge                   decrypts, refuses replays, re-encrypts the stream
   │ container loopback
   CLIProxyAPI 127.0.0.1:8317      holds the ChatGPT login, calls upstream
```

A network that can decrypt your HTTPS sees the hostname, the path `/poc/v1/exchange`,
the key identifier, sizes and timing. It does not see prompts, replies, tool calls,
model names or any key.

It does not help if upstream is down, if your account loses access, or if the network
blocks the gateway's hostname.

## Everyday use

Run all commands from the repository root.

| To do this | Run |
|---|---|
| Use Codex through the gateway | `bin/codex-gateway` (arguments go to Codex, e.g. `bin/codex-gateway exec "..."`) |
| Check the whole path works | `bin/codex-gateway smoke` |
| See the gateway address and whether the local bridge is running | `bin/codex-gateway status` |
| Stop the local bridge | `bin/codex-gateway stop` |

The launcher starts the local bridge when needed and uses the project's own `.venv`,
so it downloads nothing at run time. Plain `codex`, with no profile, is unchanged.

**Run the smoke test monthly and after every Codex update.** An unused fallback rots:
the upstream login lapses, and Codex moves past the version this was tested with
(0.160.1). The smoke test sends one small model request and uses a little quota.

A passing smoke test looks like this:

```
models: 14 served (0.22s)
model request: 7788 bytes, first byte after 1.40s, response.completed after 5.17s
PASS
```

## When something fails

Codex shows gateway failures as HTTP 502 with a `code`. Work down this table; it is
ordered by how likely each cause is.

| Code or symptom | Meaning | What to do |
|---|---|---|
| `stale_timestamp` | Your clock and the server's differ by more than 120 seconds | Fix the system clock (enable automatic time). Nothing else is wrong |
| `gateway_unreachable` | The local bridge cannot reach the gateway at all | Check the network. Try `curl <gateway-url>/healthz`. If the network needs a proxy, see "Proxy and CA" |
| `bad_gateway_response` | Something between you and the gateway answered instead of it, or altered the stream | Usually a proxy block page or an inspecting proxy modifying traffic. Same check as above; an HTML reply to that `curl` confirms it |
| Stream breaks mid-answer | A record failed verification, or the connection was cut | Retry. If it repeats, the network is tampering with or truncating the stream |
| Nothing arrives, then everything at once | An inspecting proxy is buffering whole responses | Expected with such proxies. Answers longer than 300 seconds will fail |
| `upstream_unreachable`, `upstream_failed`, `upstream_timeout` | The gateway is fine but upstream is not answering it | Wait and retry. If `curl <gateway-url>/healthz` returns 503, see "Gateway unhealthy" |
| Smoke test: "serves no models", or upstream 401 | The ChatGPT login on the gateway has lapsed | See "Renewing the upstream login" |
| `busy` | More than two requests in flight | Wait for one to finish |
| `unavailable` | The replay ledger is missing, corrupt or full | See "Replay ledger" |
| `rejected` | The two ends disagree on the key | See "Rotating the keys" |
| `invalid_local_key` (HTTP 401) | Codex is not sending the local key | Start Codex through `bin/codex-gateway`, which exports it |
| `local bridge is not running` | The smoke test could not connect to the local bridge | `bin/codex-gateway status`, then read `~/.cli-gateway/local-bridge.log` |

### Gateway unhealthy

`/healthz` returns 200 only when the bridge, the ledger and CLIProxyAPI are all usable.

```
railway service status --service gateway
railway logs --service gateway          # streams; press Ctrl-C when you have seen enough
```

If the log says `no replay ledger`, the bridge is deliberately down; see "Replay
ledger". Otherwise redeploy with `railway redeploy --service gateway --yes`.

## Proxy and CA

If the network requires an outbound proxy or re-signs TLS with its own CA, add either
or both to `~/.cli-gateway/config.json`:

```json
"proxy": "http://proxy.example.com:8080",
"ca_bundle": "/path/to/corporate-ca.pem"
```

Then `bin/codex-gateway stop`; the bridge restarts with the new settings on next use.
`ca_bundle` replaces the system trust store for this connection, so it must contain the
CA that signs what you actually receive. There is no setting that disables certificate
verification, by design.

This was tested with mitmproxy as the intercepting proxy and its CA as `ca_bundle`.
Proxy authentication and PAC files were not tested.

## Replay ledger

The gateway records every request ID it accepts, so a captured request cannot be sent
again. The ledger lives on the Railway volume at `/data/bridge/replay.sqlite`.

- The bridge will not start without a ledger and never creates one by itself. A
  silently recreated ledger would forget everything already used.
- It holds at most 100,000 requests. At the ceiling every request is refused with
  `unavailable` until the keys are rotated.
- If the ledger or the volume is lost or restored from a backup, rotate the keys. Do
  not simply create a new ledger for the old key.

Count the rows:

```
ssh-add ~/.cli-gateway/railway_ed25519
railway ssh --service gateway -- 'python -c "
from cgw import ledger
print(ledger.Ledger(\"/data/bridge/replay.sqlite\").count())"'
```

## Rotating the keys

Do this when the ledger nears its ceiling, when the ledger or volume was lost, or if
either end may have been exposed. It takes about three minutes, during which the
gateway is briefly unavailable.

```
bin/codex-gateway stop
mv ~/.cli-gateway/config.json ~/.cli-gateway/config.json.old

# 1. New keys: writes the local file and sets CGW_KID and CGW_PSK on Railway.
#    The pre-shared key travels on stdin and is never printed.
.venv/bin/python -m cgw bootstrap --remote-url <gateway-url> --railway-service gateway

# 2. A fresh ledger for the new key. The old one stays until the switch.
ssh-add ~/.cli-gateway/railway_ed25519
railway ssh --service gateway -- \
    'mv /data/bridge/replay.sqlite /data/bridge/replay.sqlite.old && python -m cgw init-ledger'

# 3. Switch: the container restarts with the new key. Takes about two minutes.
railway redeploy --service gateway --yes

# 4. Confirm, then remove the old material.
bin/codex-gateway smoke
rm ~/.cli-gateway/config.json.old
railway ssh --service gateway -- 'rm -f /data/bridge/replay.sqlite.old'
```

If step 1 fails it removes the new local file again, so nothing is half-configured;
move `config.json.old` back and retry. Carry over any `proxy` or `ca_bundle` settings
from the old file by passing `--proxy` and `--ca-bundle` to `bootstrap`.

Every other machine that uses this gateway needs the new `config.json` afterwards,
copied over a channel you trust.

To also replace the key between the remote bridge and CLIProxyAPI, add
`--set-cliproxy-key` in step 1.

## Renewing the upstream login

CLIProxyAPI holds a ChatGPT OAuth login and refreshes it by itself. If it lapses, a new
login is needed, and **that requires a network where `auth.openai.com` is reachable**.
Renew it before you need it.

**Not run in this form.** First-time setup used the same login command and the same
transfer over `railway ssh`, but onto an empty volume. Replacing an existing credential,
the `rm -f` below, has not been exercised.

```
mkdir -p ~/.cli-gateway/login/auth && chmod 700 ~/.cli-gateway/login ~/.cli-gateway/login/auth
printf 'config-version: 8\noauth:\n  auth-dir: "/root/.cli-proxy-api"\n' > ~/.cli-gateway/login/config.yaml

docker run --rm -it -p 127.0.0.1:1455:1455 \
    -v ~/.cli-gateway/login/config.yaml:/CLIProxyAPI/config.yaml \
    -v ~/.cli-gateway/login/auth:/root/.cli-proxy-api \
    eceasy/cli-proxy-api@sha256:b7cf456bf6ef7f6489f18144e7cc166dbb8b2e5f46d6ee8881a321aaea563730 \
    ./CLIProxyAPI -no-browser -codex-login
```

Open the printed URL, sign in, and wait for "Codex authentication successful". Ignore
the SSH tunnel instructions it prints. Then move the credential to the gateway and
delete the local copy, because two copies of one login invalidate each other when
either refreshes:

```
ssh-add ~/.cli-gateway/railway_ed25519
f="$(ls ~/.cli-gateway/login/auth/codex-*.json | head -1)"
railway ssh --service gateway -- \
    "rm -f /data/cliproxy/auth/codex-*.json; umask 077; cat > /data/cliproxy/.incoming && mv /data/cliproxy/.incoming '/data/cliproxy/auth/$(basename "$f")'" < "$f"
rm -rf ~/.cli-gateway/login
bin/codex-gateway smoke
```

The device-code login (`-codex-device-login`) is refused unless device codes are
enabled in ChatGPT's security settings. The browser login above needs no such change.

## Updating

**Bridge code.** Change it, then:

```
uv run pytest                 # about 90 seconds
railway up --service gateway --ci
bin/codex-gateway stop && bin/codex-gateway smoke
```

**Python dependencies.** After `uv lock --upgrade`, regenerate the image's hash-pinned
list, run the tests, and deploy as above:

```
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o deploy/requirements.lock
```

**CLIProxyAPI.** It releases several times a day, so it is pinned by digest in
`deploy/Dockerfile`. To move to a newer release, replace the digest, check
`deploy/cliproxy.yaml` against that release's `config.example.yaml`, deploy, and run
the smoke test. Its configuration layout changed between major versions.

**Codex.** After Codex updates, run the smoke test and one real `bin/codex-gateway exec`
with a tool call. If Codex starts sending a header that upstream needs, add it to
`FORWARDED_REQUEST_HEADERS` in `src/cgw/policy.py`; both bridges read that list.

## Railway CLI behaviour worth knowing

- `railway ssh` finds keys only in the SSH agent or `~/.ssh`. The agent forgets the
  project key at logout, so run `ssh-add ~/.cli-gateway/railway_ed25519` first.
- `railway logs` streams until interrupted, and `railway restart` sometimes does not
  return after the restart has happened. Press Ctrl-C once you have what you need.
- Restarting the container takes a few seconds. `railway redeploy` takes about two
  minutes.
- `railway volume add` crashes when given a service name. Pass the service ID.

## Cost

The container uses about 105 MB of memory and almost no CPU when idle. At Railway's
published rates ($10 per GB of memory per month, $20 per vCPU, $0.15 per GB of volume,
$0.05 per GB of egress) that is a little over $1 a month, which the Hobby plan's
included $5 of usage covers. Check with `railway usage`.

To be alerted, or to cap spending:

```
railway usage limit set --target workspace --soft 5 --hard 10
```

`--soft` only sends an email at that amount. `--hard` takes every workload in the
workspace offline when usage reaches it, and the minimum is $10.

## Reference

| Item | Where |
|---|---|
| Gateway address | `bin/codex-gateway status` |
| Public endpoints | `POST /poc/v1/exchange`, `GET /healthz`. Everything else is 404 |
| Railway project, service and volume IDs | `railway status` |
| Railway variables | `CGW_KID`, `CGW_PSK`, `CGW_CLIPROXY_KEY`, `PORT`, `RAILWAY_DOCKERFILE_PATH` |
| Local config (secret, owner-only) | `~/.cli-gateway/config.json` |
| Railway SSH key (secret) | `~/.cli-gateway/railway_ed25519` |
| Local bridge log | `~/.cli-gateway/local-bridge.log` |
| Codex profile (no secret) | `~/.codex/gateway.config.toml`, written by `python -m cgw install-profile` |
| On the volume | `/data/cliproxy/auth/` (ChatGPT login), `/data/bridge/replay.sqlite` (ledger) |
| Limits | 2 requests in flight; 8 MiB request body; 600 s per request; 120 s clock tolerance |

Retries are off everywhere on purpose. Each attempt uses a new request ID, and a silent
retry could spend quota twice.

## What this does not protect against

- A compromised or monitored device. Plaintext exists on this machine.
- Railway or the model provider reading the content. Plaintext exists there too.
- Later theft of the pre-shared key, which would expose recorded past sessions. There
  is no forward secrecy.
- Being noticed. The traffic is visibly encrypted application data sent to Railway.
- Being blocked. Anyone on the path can drop or delay the connection.
