# Runbook

Operating a gateway that is already deployed. To set one up, see the README.

This file is self-contained on purpose, so operating the gateway never depends on
documentation elsewhere.

In the commands below, `<gateway-url>` is your gateway's address. `bin/codex-gateway
status` prints it.

The everyday commands, the troubleshooting checks, the key rotation and the move to
per-machine keys were all run against a live deployment, with the real address in
place of the placeholder. The rotation was run when it still had a step for the replay
ledger, since removed.
"Renewing the upstream login" was not run in this form; it says so again where it
starts.

## What is running

```
Codex --profile gateway            the only command-line tool supported so far
   │ plain HTTP, loopback
   ▼
local bridge 127.0.0.1:8318        this machine; encrypts requests, verifies responses
   │ HTTPS, encrypted envelope
   ▼
<gateway-url>                      one container on Railway
   remote bridge                   admits only known machines, decrypts, re-encrypts the stream
   │ container loopback
   CLIProxyAPI 127.0.0.1:8317      holds the subscription logins, calls the providers
```

A network that can decrypt your HTTPS sees the hostname, the paths `/poc/v2/handshake`
and `/poc/v2/exchange`, the key identifier, sizes and timing. It does not see prompts,
replies, tool calls, model names or any key. Every request uses its own X25519 key
exchange, so a recording stays unreadable even if the pre-shared key is stolen later.

It does not help if a provider is down or your account loses access.

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

**Run the smoke test monthly and after every Codex update.** An idle gateway drifts:
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
| `proxy_refused` | The configured proxy turned the connection down | Check the user name and password in `proxy` (see "Proxy and CA"). If they are right, the proxy blocks the gateway's hostname |
| `bad_gateway_response` | Something between you and the gateway answered instead of it, or altered the stream | Usually a proxy block page or an inspecting proxy modifying traffic. Same check as above; an HTML reply to that `curl` confirms it |
| Stream breaks mid-answer | A record failed verification, or the connection was cut | Retry. If it repeats, the network is tampering with or truncating the stream |
| Nothing arrives, then everything at once | An inspecting proxy is buffering whole responses | Expected with such proxies. Answers longer than 300 seconds will fail |
| `upstream_unreachable`, `upstream_failed`, `upstream_timeout` | The gateway is fine but upstream is not answering it | Wait and retry. If `curl <gateway-url>/healthz` returns 503, see "Gateway unhealthy" |
| Smoke test: "serves no models", or upstream 401 | The subscription login on the gateway has lapsed | See "Renewing the upstream login" |
| `busy` | More than two requests in flight, counting every machine that uses the gateway | Wait for one to finish |
| `rejected` | The gateway does not know this machine's key: it was removed or replaced, or the two ends run incompatible versions of this code | Ask the admin to check `list-clients` (see "Adding and removing machines"). Otherwise check that this machine and the gateway run the same revision (see "Updating") |
| `invalid_local_key` (HTTP 401) | Codex is not sending the local key | Start Codex through `bin/codex-gateway`, which exports it |
| "port 8318 ... is held by a program that is not this gateway's local bridge" | Another program took the local bridge's port. The launcher sent it nothing | Find it with `lsof -nP -iTCP:8318 -sTCP:LISTEN` and stop it. If it is a legitimate program that needs the port, see "Changing the local port" |
| `too_slow` | A request took more than 30 seconds to upload | The connection is very slow or stalled. Retry on a better connection |
| `local bridge is not running` | The smoke test could not connect to the local bridge | `bin/codex-gateway status`, then read `~/.cli-gateway/local-bridge.log` |

### Gateway unhealthy

`/healthz` returns 200 only when the bridge and CLIProxyAPI are both usable.

```
railway service status --service gateway
railway logs --service gateway          # streams; press Ctrl-C when you have seen enough
```

If nothing in the log explains it, redeploy with `railway redeploy --service gateway
--yes`.

### Changing the local port

Set `"port"` in `~/.cli-gateway/config.json`, then replace the Codex profile, which
carries the port:

```
bin/codex-gateway stop
rm ~/.codex/gateway.config.toml
.venv/bin/python -m cgw install-profile
bin/codex-gateway smoke
```

## Proxy and CA

If the network requires an outbound proxy or re-signs TLS with its own CA, add either
or both to `~/.cli-gateway/config.json`:

```json
"proxy": "http://user:password@proxy.example.com:8080",
"ca_bundle": "/path/to/corporate-ca.pem"
```

Leave out `user:password@` if the proxy needs no login. Characters such as `@`, `:` or
`/` in the password must be percent-encoded, for example `%40` for `@`.

Then `bin/codex-gateway stop`; the bridge restarts with the new settings on next use.
`ca_bundle` replaces the system trust store for this connection, so it must contain the
CA that signs what you actually receive. There is no setting that disables certificate
verification, by design.

Tested on 14 October 2026 in an isolated Docker network whose only way out was a
mitmproxy that required a password, intercepted TLS and refused everything except the
gateway. Direct connections failed, every other destination was refused, and
`bin/codex-gateway setup` followed by a Codex session with a tool call worked through
the proxy. A wrong proxy password gives `proxy_refused`.

Not supported: PAC files and Windows-integrated proxy login (NTLM, Kerberos). For a
PAC file, find out which proxy it chooses for the gateway's hostname and set that proxy
explicitly. A proxy that accepts only NTLM or Kerberos cannot be used.

## Adding and removing machines

Every machine has its own key and its own name. The gateway holds one Railway variable
per machine, `CGW_CLIENT_<NAME>`, and admits exactly those. A name is lowercase letters
and digits in words joined by hyphens, such as `work-laptop`; its variable spells the
same name in capitals with underscores, `CGW_CLIENT_WORK_LAPTOP`.

Only the admin needs Railway access. The new machine needs only the file it is given
and the README's "Set up a machine".

**Add a machine.** On the admin's machine:

```
.venv/bin/python -m cgw add-client work-laptop --railway-service gateway
```

This writes `~/.cli-gateway/clients/work-laptop.json`, readable by you only, sets
`CGW_CLIENT_WORK_LAPTOP` on Railway over standard input, and redeploys the gateway,
which takes about two minutes. The gateway address comes from the admin's own config;
on a machine without one, pass `--remote-url <gateway-url>`. If the new machine needs a
proxy or its own CA, pass `--proxy` and `--ca-bundle` as well.

Hand the file over as `~/.cli-gateway/config.json` on the new machine, over a channel
you trust: a password manager, `scp` between machines you control, or a USB stick. Not
plain chat or email: the file is the key. Then delete the copy in
`~/.cli-gateway/clients/`.

**Without the Railway CLI.** Leave out `--railway-service`. The command writes the file
and names the variable to create; add that variable in the Railway dashboard with the
`"psk"` value from the file as its value, and redeploy from the dashboard. To remove a
machine there, delete its variable and redeploy: deleting a variable does not restart
the gateway by itself, and until it restarts the machine still gets in.

**See who has access.** Names only, never keys:

```
.venv/bin/python -m cgw list-clients --railway-service gateway
```

**Remove a machine** that is lost, retired or may have leaked its key:

```
.venv/bin/python -m cgw remove-client work-laptop --railway-service gateway
```

It deletes the variable and then redeploys, because deleting alone does not restart
the gateway. Once the gateway has restarted, that machine's
requests are `rejected`; no other machine is affected. The last client cannot be
removed, because the gateway refuses to start without one.

**Give a machine a new key** with `add-client <name> --replace --railway-service
gateway`. Its old file stops working once the gateway has restarted.

Adding or removing a machine restarts the gateway. A request running on another
machine at that moment may be cut off and need sending again. The gateway's log names
the client of every request (`exchange client=work-laptop ...`).

## Rotating the keys

To replace another machine's key, see "Give a machine a new key" above. To replace
this machine's own key, and optionally the internal key between the remote bridge and
CLIProxyAPI, do the following. It takes about three minutes, during which the gateway
is briefly unavailable.

```
bin/codex-gateway stop
mv ~/.cli-gateway/config.json ~/.cli-gateway/config.json.old

# 1. A new key under this machine's existing name (list-clients shows it). Writes the
#    local file and sets CGW_CLIENT_<NAME> on Railway. The key travels on stdin and is
#    never printed.
.venv/bin/python -m cgw bootstrap --remote-url <gateway-url> --railway-service gateway --client-name <name>

# 2. Switch: the container restarts with the new key. Takes about two minutes.
railway redeploy --service gateway --yes

# 3. Confirm, then remove the old file.
bin/codex-gateway smoke
rm ~/.cli-gateway/config.json.old
```

If step 1 fails it removes the new local file again, so nothing is half-configured;
move `config.json.old` back and retry. Carry over any `proxy` or `ca_bundle` settings
from the old file by passing `--proxy` and `--ca-bundle` to `bootstrap`.

To also replace the key between the remote bridge and CLIProxyAPI, add
`--set-cliproxy-key` in step 1. If every key may have been exposed, for example through
the Railway account, give every machine a new key.

## Renewing the upstream login

CLIProxyAPI holds an OAuth login for each subscription and refreshes it by itself. If
one lapses, you sign in again, which **needs a browser on a network that can reach the
provider's sign-in page**. Renew it before you need it.

The steps below are for the Codex subscription, the one this gateway serves today. Other
providers sign in through CLIProxyAPI's matching login option instead of `-codex-login`.

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
enabled in the account's security settings. The browser login above needs no such change.

## Updating

**When the wire protocol changes, update both ends together.** On each machine run `git
pull`, then `bin/codex-gateway stop` so the next use starts the new bridge; deploy the
gateway as below. The design record notes which revisions changed the protocol and
whether the two versions can talk to each other. Version 2, the per-request key
exchange, cannot talk to version 1 in either direction, so expect failures on any
machine not yet updated.

**Gateways set up before per-machine keys** hold a single key in `CGW_KID` and
`CGW_PSK`. The current code does not read those, so name this machine as the first
client before deploying it, then delete them:

```
bin/codex-gateway stop
mv ~/.cli-gateway/config.json ~/.cli-gateway/config.json.old
.venv/bin/python -m cgw bootstrap --remote-url <gateway-url> --railway-service gateway --client-name <name>
railway up --service gateway --ci
bin/codex-gateway smoke && rm ~/.cli-gateway/config.json.old
railway variable delete CGW_KID --service gateway
railway variable delete CGW_PSK --service gateway
```

Deleting them needs no redeploy; the running gateway already ignores them.

Every other machine then needs its own key: see "Adding and removing machines".

**Gateways deployed before the replay ledger was removed** keep an unused
`/data/bridge/replay.sqlite` on their volume. It can be deleted:

```
ssh-add ~/.cli-gateway/railway_ed25519
railway ssh --service gateway -- 'rm -f /data/bridge/replay.sqlite /data/bridge/replay.sqlite.old'
```

**Bridge code.** Change it, then:

```
uv run pytest                 # about two minutes
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
| Public endpoints | `POST /poc/v2/handshake`, `POST /poc/v2/exchange`, `GET /healthz`. Everything else is 404 |
| Railway project, service and volume IDs | `railway status` |
| Railway variables | `CGW_CLIENT_<NAME>` (one per machine), `CGW_CLIPROXY_KEY`, `PORT`, `RAILWAY_DOCKERFILE_PATH` |
| Local config (secret, owner-only) | `~/.cli-gateway/config.json` |
| Configs made for other machines (secret, delete once handed over) | `~/.cli-gateway/clients/` |
| Railway SSH key (secret) | `~/.cli-gateway/railway_ed25519` |
| Local bridge log | `~/.cli-gateway/local-bridge.log` |
| Codex profile (no secret) | `~/.codex/gateway.config.toml`, written by `python -m cgw install-profile` |
| On the volume | `/data/cliproxy/auth/` (subscription logins). The gateway stores nothing else |
| Limits | 2 requests in flight, shared by all machines; 8 MiB request body; 600 s per request; 120 s clock tolerance; 30 s to upload a request |

Retries are off everywhere on purpose. Each attempt uses a new request ID, and a silent
retry could spend quota twice.

## What this does not protect against

- A compromised or monitored device. Plaintext exists on this machine.
- Other people's programs on a shared machine, fully. The launcher checks that the
  program on the local port really is the bridge before sending it anything, but Codex
  does not repeat that check on each request.
- A flood of connections to the gateway. A client without the key cannot hold any of
  the gateway's places or budgets, and idle connections are closed after 10 seconds,
  but a large enough sustained flood can still use up its connection limit. That is
  for the hosting platform's edge to stop.
- Railway or the model provider reading the content. Plaintext exists there too.
- A stolen key, going forward. Past recordings stay unreadable thanks to the
  per-request key exchange, but whoever holds a machine's key can act as that machine,
  or as the gateway towards it, from then on. Remove that machine if its key may have
  leaked; the other machines' keys are unaffected.
- Being noticed. The traffic is visibly encrypted application data sent to Railway.
- Interference with availability. Anyone on the path can drop or delay the connection.
