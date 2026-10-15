# Runbook

Operating a gateway that is already deployed. To set one up, see the README.

This file is self-contained on purpose, so operating the gateway never depends on
documentation elsewhere.

In the commands below, `<gateway-url>` is your gateway's address. `bin/cgw status`
prints it. Commands for a Docker host are run on that host, from the repository's root,
with `compose` set up as `alias compose='docker compose -f deploy/docker/compose.yaml'`.

The Codex commands, the troubleshooting checks, the key rotation and the move to
per-machine keys were run against a live deployment on Railway, with the real address
in place of the placeholder, using `bin/codex-gateway`, which `bin/cgw` now runs for
Codex unchanged. The rotation was run when it still had a step for the replay ledger,
since removed. The Docker host commands were run against a test deployment on one
machine, with Caddy's own certificate authority instead of a public certificate. The
design record has the live status of the other tools. "Signing in a subscription" says
which of its steps have been run. The admin commands have been run on the live Railway
gateway: granting the first admin to a gateway set up before admin keys, then a Claude
sign-in and the removal of an old sign-in from the page.

## What is running

```
Codex, Claude Code, Gemini CLI, ...  started through bin/cgw
   │ plain HTTP, loopback, in the tool's own API format
   ▼
local bridge 127.0.0.1:8318          this machine; encrypts requests, verifies responses
   │ HTTPS, encrypted envelope
   ▼
<gateway-url>                        one container, on a Docker host (behind Caddy) or on Railway
   remote bridge                     admits only known machines, decrypts, re-encrypts the stream
   │ container loopback
   CLIProxyAPI 127.0.0.1:8317        holds the subscription logins, calls the providers
```

A network that can decrypt your HTTPS sees the hostname, the paths `/poc/v2/handshake`
and `/poc/v2/exchange`, the key identifier, sizes and timing. It does not see prompts,
replies, tool calls, model names, which tool is in use, or any key. Every request uses
its own X25519 key exchange, so a recording stays unreadable even if the pre-shared key
is stolen later.

It does not help if a provider is down or your account loses access.

## Everyday use

Run all commands from the repository root.

| To do this | Run |
|---|---|
| Use Codex through the gateway | `bin/cgw codex` (arguments go to Codex, e.g. `bin/cgw codex exec "..."`) |
| Use Claude Code | `bin/cgw claude` |
| Use Gemini CLI | `bin/cgw gemini` |
| Use any other tool | `bin/cgw run <command> [arguments]` |
| See the model names the gateway serves | `bin/cgw models` |
| Check the whole path works | `bin/cgw smoke` |
| See the variables a tool needs | `bin/cgw env` (`bin/cgw env --export` prints them with the local key, for `eval`) |
| See the gateway address and whether the local bridge is running | `bin/cgw status` |
| Stop the local bridge | `bin/cgw stop` |
| Manage the gateway's subscription sign-ins (admins) | `bin/cgw admin`, or `sign-in`, `subscriptions`, `sign-out`; see "Signing in a subscription" |

The launcher starts the local bridge when needed and uses the project's own `.venv`,
so it downloads nothing at run time. A tool started without `bin/cgw` is unchanged:
plain `codex`, `claude` and `gemini` still use their own setup.

`bin/cgw gemini` keeps Gemini CLI's settings for gateway runs in `~/.cli-gateway/gemini`.
Run headless with `-p`, Gemini CLI works only in a folder you have already trusted, or
with `--skip-trust`. Give `-m` a model name exactly as `bin/cgw models` lists it: Gemini
CLI rewrites some short names (`gemini-3-flash` became `gemini-3.8-flash`), and the
gateway answers a name it does not serve with an upstream 400.

**Run the smoke test monthly and after every tool update.** An idle gateway drifts:
the upstream logins lapse, and the tools move past the versions they were tested with
(the design record lists them). The smoke test sends one small model request and uses a
little quota. It speaks one API format at a time:

| Format | Command |
|---|---|
| OpenAI responses (Codex) | `bin/cgw smoke` |
| OpenAI chat completions | `bin/cgw smoke --format chat` |
| Anthropic messages (Claude Code) | `bin/cgw smoke --format messages --model <model>` |
| Gemini | `bin/cgw smoke --format gemini --model <model>` |

The first two use `gpt-6-astra` unless given `--model`. `bin/cgw models` lists the
names to choose from.

A passing smoke test looks like this:

```
models: 14 served (0.22s)
model request (responses format, gpt-6-astra): 7788 bytes, first byte after 1.40s, response.completed after 5.17s
PASS
```

## When something fails

Tools show gateway failures as HTTP 502 with a `code`. Work down this table; it is
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
| Smoke test: "serves no models", or upstream 401 | The subscription login on the gateway has lapsed, or none is signed in yet | See "Signing in a subscription" |
| The tool reports an unknown or unsupported model | No subscription signed in on the gateway serves that model | Pick a name from `bin/cgw models`, or sign the gateway in to the subscription that serves it |
| `busy` | More than two requests in flight, counting every machine that uses the gateway | Wait for one to finish |
| `rejected` | The gateway does not know this machine's key: it was removed or replaced, or the two ends run incompatible versions of this code | Ask the admin to check `list-clients` (see "Adding and removing machines"). Otherwise check that this machine and the gateway run the same revision (see "Updating") |
| `invalid_local_key` (HTTP 401) | The tool is not sending the local key | Start the tool through `bin/cgw`, which provides it |
| `not_found` (HTTP 404) | The tool called a route the gateway does not carry, such as image, audio or realtime endpoints | Expected: the gateway carries text-model routes only. `docs/protocol.md` lists them |
| `invalid_query` (HTTP 400) | The tool sent a query string the gateway does not carry: malformed, over 1,024 characters, or with control characters | Report it with the tool and its version |
| `too_many_headers` (HTTP 400) | The tool sent more than 64 headers the gateway would forward | Report it with the tool and its version |
| Gemini CLI asks you to sign in with Google | It was started without `bin/cgw`, so it uses your own settings | Start it with `bin/cgw gemini` |
| An admin command says "the gateway refused: rejected" | This machine has no admin key on the gateway, it was revoked, or the gateway has not restarted since `grant-admin` | Check `list-clients`, which marks admins. On a Docker host, `compose up -d` after granting |
| "wrong passphrase, or the admin key file was altered" | The passphrase is wrong, or `admin.json` was changed | Retry the passphrase. A lost passphrase cannot be recovered: grant the machine a new admin key (see "Admins") |
| "port ... is taken, so the redirect cannot be caught automatically" | Another program holds the provider's callback port on this machine, often that provider's own tool signing in | Finish the sign-in in the browser, then paste the address it ended on, which starts with `http://localhost`. Or stop the other program and retry |
| "port 8318 ... is held by a program that is not this gateway's local bridge" | Another program took the local bridge's port. The launcher sent it nothing | Find it with `lsof -nP -iTCP:8318 -sTCP:LISTEN` and stop it. If it is a legitimate program that needs the port, see "Changing the local port" |
| `too_slow` | A request took more than 30 seconds to upload | The connection is very slow or stalled. Retry on a better connection |
| `local bridge is not running` | The smoke test could not connect to the local bridge | `bin/cgw status`, then read `~/.cli-gateway/local-bridge.log` |

### Gateway unhealthy

`/healthz` returns 200 only when the bridge and CLIProxyAPI are both usable.

On a Docker host:

```
compose ps
compose logs --tail 50 gateway
compose up -d                 # starts whatever is not running
```

On Railway:

```
railway service status --service gateway
railway logs --service gateway          # streams; press Ctrl-C when you have seen enough
```

If nothing in the log explains it, redeploy with `railway redeploy --service gateway
--yes`.

### Changing the local port

Set `"port"` in `~/.cli-gateway/config.json`. `bin/cgw` passes the port to every tool
it starts, but the Codex profile carries it too, so replace that:

```
bin/cgw stop
rm ~/.codex/gateway.config.toml
.venv/bin/python -m cgw install-profile
bin/cgw smoke
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

Then `bin/cgw stop`; the bridge restarts with the new settings on next use. `ca_bundle`
replaces the system trust store for this connection, so it must contain the CA that
signs what you actually receive. There is no setting that disables certificate
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

Every machine has its own key and its own name. The gateway holds one variable per
machine, `CGW_CLIENT_<NAME>`, and admits exactly those. A name is lowercase letters and
digits in words joined by hyphens, such as `work-laptop`; its variable spells the same
name in capitals with underscores, `CGW_CLIENT_WORK_LAPTOP`.

The commands below change those variables where the gateway keeps them. Name the place
with one of:

| Host | Option | Where the commands run |
|---|---|---|
| Docker host | `--env-file deploy/docker/gateway.env` | On the host, where the file is |
| Railway | `--railway-service gateway` | On any machine with the Railway CLI, signed in |

Only the admin needs this access. The new machine needs only the file it is given and
the README's "Set up a machine".

**Add a machine.**

```
.venv/bin/python -m cgw add-client work-laptop --env-file deploy/docker/gateway.env
.venv/bin/python -m cgw add-client work-laptop --railway-service gateway
```

This writes `~/.cli-gateway/clients/work-laptop.json`, readable by you only, and adds
`CGW_CLIENT_WORK_LAPTOP` where the gateway keeps its keys.

- **Docker host:** restart the gateway so it reads the file: `compose up -d`. Docker
  Compose sees that the env file changed and recreates only the gateway container,
  which takes a few seconds. The command refuses an env file that others can read.
- **Railway:** the key travels to Railway on standard input, and the command redeploys
  the gateway, which takes about two minutes.

The gateway address comes from the admin's own config; on a machine without one, pass
`--remote-url <gateway-url>`. If the new machine needs a proxy or its own CA, pass
`--proxy` and `--ca-bundle` as well.

Hand the file over as `~/.cli-gateway/config.json` on the new machine, over a channel
you trust: a password manager, `scp` between machines you control, or a USB stick. Not
plain chat or email: the file is the key. Then delete the copy in
`~/.cli-gateway/clients/`.

**With neither option.** The command writes the file and names the variable to create.
Add it yourself, with the `"psk"` value from the file as its value: a line
`CGW_CLIENT_<NAME>=<psk>` in the env file, or a variable in the Railway dashboard. Then
restart the gateway. To remove a machine by hand, delete its variable and restart:
deleting a variable does not restart the gateway by itself, and until it restarts the
machine still gets in.

**See who has access.** Names only, never keys:

```
.venv/bin/python -m cgw list-clients --env-file deploy/docker/gateway.env
.venv/bin/python -m cgw list-clients --railway-service gateway
```

**Remove a machine** that is lost, retired or may have leaked its key:

```
.venv/bin/python -m cgw remove-client work-laptop --env-file deploy/docker/gateway.env
compose up -d

.venv/bin/python -m cgw remove-client work-laptop --railway-service gateway
```

On Railway the command redeploys by itself, because deleting a variable alone does not
restart the gateway. Once the gateway has restarted, that machine's requests are
`rejected`; no other machine is affected. The last client cannot be removed, because
the gateway refuses to start without one.

**On Railway, do not roll back past a removal.** A Railway rollback restores the
variables the earlier deployment started with, so rolling back to a deployment from
before a `remove-client` lets that machine in again. After any rollback, run
`list-clients` and remove the machine again if it is back. Rollbacks are possible for
72 hours on the Hobby plan.

**Give a machine a new key** with `add-client <name> --replace` and the same option as
above. Its old file stops working once the gateway has restarted.

Adding or removing a machine restarts the gateway. A request running on another
machine at that moment may be cut off and need sending again. The gateway's log names
the client of every request (`exchange client=work-laptop ...`).

### Admins

An admin signs the gateway in to subscriptions, from their own machine (see "Signing in
a subscription"). Being an admin means holding a second key, separate from the
machine's everyday key:

- On the gateway it is `CGW_ADMIN_<NAME>`, next to `CGW_CLIENT_<NAME>`. On the wire it
  is called `admin_<name>`, which can never be a client's name.
- On the machine it is `admin.json`, next to `config.json`, readable by its owner only
  and encrypted with a passphrase of at least 10 characters. It is decrypted only in
  memory while an admin command runs.
- The gateway accepts it for the sign-in requests and nothing else, and the everyday key
  for model requests and nothing else. A copied `config.json` cannot touch the sign-ins;
  a copied `admin.json` is useless without the passphrase.

Making a machine an admin needs the same access to the gateway's host as adding a
machine. No request over the network can grant it, and an admin cannot make another
machine an admin. The machine that ran `bootstrap` is the first admin (unless
`bootstrap` was given `--no-admin`).

**Make a machine an admin**, on that machine, which needs its own working config:

```
.venv/bin/python -m cgw grant-admin work-laptop --env-file deploy/docker/gateway.env   # on the Docker host
.venv/bin/python -m cgw grant-admin work-laptop --railway-service gateway
```

It asks twice for the passphrase, writes `admin.json` next to the machine's config, and
sets `CGW_ADMIN_WORK_LAPTOP`, and `CGW_CLIPROXY_MANAGEMENT_KEY` if the gateway has none
yet. The gateway restarts as for `add-client`: Railway redeploys by itself; on a Docker
host, run `compose up -d`. On a Docker host the command runs on the host, so pass
`--remote-url <gateway-url>` and `--admin-key <file>`, then move that file to the
machine as `~/.cli-gateway/admin.json` over a channel you trust.

`list-clients` marks admins with `(admin)`.

**Take it away:** `revoke-admin work-laptop` with the same option. The machine's
everyday key keeps working, and its `admin.json` becomes useless; delete it.
`remove-client` takes away a machine's admin key along with its everyday key.

**A new admin key**, for a lost passphrase or a key that may have leaked: move the old
`admin.json` aside, then `grant-admin work-laptop --replace` with the same option. The
old key stops working once the gateway has restarted.

## Rotating the keys

To replace another machine's key, see "Give a machine a new key" above. To replace
this machine's own key, and optionally the internal key between the remote bridge and
CLIProxyAPI, do the following. On Railway it takes about three minutes, during which
the gateway is briefly unavailable.

```
bin/cgw stop
mv ~/.cli-gateway/config.json ~/.cli-gateway/config.json.old

# 1. A new key under this machine's existing name (list-clients shows it). Writes the
#    local file and sets CGW_CLIENT_<NAME> where the gateway keeps its keys. The key is
#    never printed. --no-admin keeps this machine's admin key as it is.
.venv/bin/python -m cgw bootstrap --remote-url <gateway-url> --railway-service gateway --client-name <name> --no-admin

# 2. Switch: the gateway restarts with the new key. On Railway this takes about two minutes.
railway redeploy --service gateway --yes

# 3. Confirm, then remove the old file.
bin/cgw smoke
rm ~/.cli-gateway/config.json.old
```

On a Docker host, run step 1 on the host with `--env-file deploy/docker/gateway.env`
and `--config ~/.cli-gateway/clients/<name>.json` instead of `--railway-service`, make
step 2 `compose up -d`, and copy the new file to this machine as
`~/.cli-gateway/config.json` before step 3.

If step 1 fails it removes the new local file again, so nothing is half-configured;
move `config.json.old` back and retry. Carry over any `proxy` or `ca_bundle` settings
from the old file by passing `--proxy` and `--ca-bundle` to `bootstrap`.

To also replace the key between the remote bridge and CLIProxyAPI, add
`--set-cliproxy-key` in step 1. To replace this machine's admin key, see "Admins". If
every key may have been exposed, for example through the hosting account, give every
machine a new key and every admin a new admin key.

## Signing in a subscription

CLIProxyAPI on the gateway holds one OAuth login per subscription and refreshes each by
itself. It picks the subscription for each request by the model name the tool asks for.
Sign the gateway in once for each subscription you want to use, and again if a login
lapses. Signing in needs a browser on a network that can reach the provider's sign-in
page, so do it before you need it.

An admin does it from their own machine, through the gateway (see "Admins" for who is an
admin). Each command asks for the admin passphrase; a wrong one is refused before
anything is sent. The commands use the machine's `proxy` and `ca_bundle` settings, and
do not need the local bridge running.

| To do this | Run |
|---|---|
| Open the sign-in page | `bin/cgw admin` |
| Sign in from the terminal | `bin/cgw sign-in <provider>` (`--no-browser` prints the address instead of opening it) |
| See what the gateway is signed in to | `bin/cgw subscriptions`: provider, account, status and file name; never a token |
| Remove one sign-in | `bin/cgw sign-out <file>`, with the file name `subscriptions` shows |

| Provider | `sign-in` name | Callback on this machine | Code verifier (PKCE) |
|---|---|---|---|
| Claude | `claude` | `localhost:54545/callback` | Yes |
| A plan that includes Codex | `codex` | `localhost:1455/auth/callback` | Yes |
| A Google account through Antigravity, for Gemini models | `google` (or `gemini`) | `localhost:51121/oauth-callback` | **No** |
| xAI, Kimi, Kimi.ai, Meta, Devin | `xai`, `kimi`, `kimi-ai`, `meta`, `devin` | Whatever the provider's sign-in address names | Not checked |

The ports and PKCE were checked against the pinned CLIProxyAPI on 14 October 2026.

**How a sign-in works.** The gateway asks CLIProxyAPI for the provider's sign-in
address, and your browser opens it. You sign in on the provider's own site. The provider
sends the browser back to `http://localhost:<port>/...` on your machine, where the
command listens on that one port and path only while it waits, catches the address and
hands it to the gateway through the encrypted channel. CLIProxyAPI turns it into tokens
on the gateway and stores them where it reads them; the new subscription's models are
served at once, with no restart. The tokens never reach your machine. A sign-in nobody
finishes is dropped by the gateway after 5 minutes.

**The page.** `bin/cgw admin` prints a one-time link and opens it. The page lists the
sign-ins, with a button to remove each (press it twice), and a button per provider. It
runs on `127.0.0.1:8319` (`--port` to change) only while the command runs; stop it with
Ctrl-C. The link works once and starts a session that only this browser holds; other
websites cannot use the page, and requests that name another host are refused.

**When the callback port is taken**, for example while that provider's own tool is
signing in, the address cannot be caught. Finish signing in in the browser; it ends on
an error page whose address starts with `http://localhost`. Paste that address into the
page's box, or at the terminal prompt.

**Google has no code verifier.** For the providers marked "Yes", the code in the
address is useless without a secret that only the gateway holds. Google's sign-in does
not use one, so a program already running on your machine that took port 51121 first
could use a caught code itself. That is the same limit as for any program running as
you; sign in to Google from a machine you trust.

**Run so far:** on the live Railway gateway, `grant-admin` for a gateway set up before
admin keys, then from the page a Claude sign-in, caught locally and completed on the
gateway, and the removal of an old sign-in; the new sign-in served Claude models at once.
Against a test deployment on one machine with the real CLIProxyAPI: the Claude, Codex
and Google sign-in addresses and their status, listing and the refusals. Codex and
Google sign-ins have not yet been completed this way.

### Without an admin key

The older way still works, for a gateway or a machine without an admin key. It needs
Docker on your machine and access to the gateway's host: it runs CLIProxyAPI on your
machine, and the file it produces is then copied onto the gateway.

| Subscription | Sign-in option | Callback port |
|---|---|---|
| A plan that includes Codex | `-codex-login` | 1455 |
| Claude | `-claude-login` | 54545 |
| A Google account through Antigravity, for Gemini models | `-antigravity-login` | 51121 |
| xAI, Kimi, Meta, Devin | `-xai-login`, `-kimi-login`, `-meta-login`, `-devin-login` | The port in the `redirect_uri` of the URL it prints |

The pinned CLIProxyAPI release (8.0.27) has no sign-in for Gemini CLI accounts. Gemini
models are reached through an Antigravity sign-in, or through a Gemini API key in
CLIProxyAPI's configuration, which this project does not set up.

**Run so far:** the Codex sign-in, copied over `railway ssh` onto an empty volume; the
Claude and Antigravity sign-ins, copied over `railway ssh` onto the running gateway,
which served their models at once, with no restart. Replacing an existing login and the
copy onto a Docker host have not been run.

**1. Sign in, on your machine.**

```
mkdir -p ~/.cli-gateway/login/auth && chmod 700 ~/.cli-gateway/login ~/.cli-gateway/login/auth
printf 'config-version: 8\noauth:\n  auth-dir: "/root/.cli-proxy-api"\n' > ~/.cli-gateway/login/config.yaml

# <option> and <port> from the table, for example -codex-login and 1455
docker run --rm -it -p 127.0.0.1:<port>:<port> \
    -v ~/.cli-gateway/login/config.yaml:/CLIProxyAPI/config.yaml \
    -v ~/.cli-gateway/login/auth:/root/.cli-proxy-api \
    eceasy/cli-proxy-api@sha256:b7cf456bf6ef7f6489f18144e7cc166dbb8b2e5f46d6ee8881a321aaea563730 \
    ./CLIProxyAPI -no-browser <option>
```

Open the printed URL, sign in, and wait for the message that authentication succeeded.
Ignore the SSH tunnel instructions it prints. The login is now one JSON file in
`~/.cli-gateway/login/auth/`.

**2. Copy it onto the gateway, then delete the local copy.** Two copies of one login
invalidate each other when either refreshes. When replacing a lapsed login, list the
gateway's logins first and remove the old file for that subscription.

On Railway:

```
ssh-add ~/.cli-gateway/railway_ed25519
railway ssh --service gateway -- 'ls /data/cliproxy/auth'          # the logins it holds now
f="$(ls ~/.cli-gateway/login/auth/*.json | head -1)"
railway ssh --service gateway -- \
    "umask 077; cat > /data/cliproxy/.incoming && mv /data/cliproxy/.incoming '/data/cliproxy/auth/$(basename "$f")'" < "$f"
rm -rf ~/.cli-gateway/login
```

For Codex, the earlier login is replaced by starting the remote command with
`rm -f /data/cliproxy/auth/codex-*.json;`.

On a Docker host, copy the file to the host first (`scp "$f" <host>:`), then on the
host:

```
compose exec gateway ls /data/cliproxy/auth                       # the logins it holds now
compose cp ~/<file> gateway:/data/cliproxy/auth/<file>
rm ~/<file>
```

and delete `~/.cli-gateway/login` on your machine.

**3. Check.** `bin/cgw models` should now list that subscription's models. Then run the
smoke test in the format of a tool that uses it, for example
`bin/cgw smoke --format messages --model <model>` after a Claude sign-in. If the new
models do not appear, restart the gateway (`compose restart gateway`, or
`railway redeploy --service gateway --yes`).

The device-code login (`-codex-device-login`) is refused unless device codes are
enabled in the account's security settings. The browser login above needs no such change.

## Updating

**When the wire protocol changes, update both ends together.** On each machine run `git
pull`, then `bin/cgw stop` so the next use starts the new bridge; deploy the gateway as
below. The design record notes which revisions changed the protocol and whether the two
versions can talk to each other. Version 2, the per-request key exchange, cannot talk to
version 1 in either direction, so expect failures on any machine not yet updated.

**Update the gateway before the machines when a tool sends a query string.** Since the
gateway carries tools other than Codex, the local bridge passes a query string on
inside the encrypted request (Claude Code and Gemini CLI send one). A gateway from
before that change refuses such a request as `rejected`. An older local bridge keeps
working with a newer gateway.

**Gateways set up before admin keys** have no admin. Deploy the new code, then, on the
machine that should be the admin:

```
.venv/bin/python -m cgw grant-admin <this machine's name> --railway-service gateway   # redeploys
bin/cgw admin
```

On a Docker host, run `grant-admin` on the host with `--env-file deploy/docker/gateway.env`
as described in "Admins", then `compose up -d`.

**Gateways set up before per-machine keys** hold a single key in `CGW_KID` and
`CGW_PSK`. The current code does not read those, so name this machine as the first
client before deploying it, then delete them. Such gateways ran on Railway:

```
bin/cgw stop
mv ~/.cli-gateway/config.json ~/.cli-gateway/config.json.old
.venv/bin/python -m cgw bootstrap --remote-url <gateway-url> --railway-service gateway --client-name <name>
railway up --service gateway --ci
bin/cgw smoke && rm ~/.cli-gateway/config.json.old
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

**Bridge code.** Change it and run the tests (`uv run pytest`, about two and a half
minutes), then deploy:

```
git pull && compose up -d --build              # on a Docker host
railway up --service gateway --ci              # on Railway
```

and on each machine `bin/cgw stop && bin/cgw smoke`.

**Python dependencies.** After `uv lock --upgrade`, regenerate the image's hash-pinned
list, run the tests, and deploy as above:

```
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o deploy/requirements.lock
```

**CLIProxyAPI.** It releases several times a day, so it is pinned by digest in
`deploy/Dockerfile`. To move to a newer release, replace the digest, check
`deploy/cliproxy.yaml` against that release's `config.example.yaml`, deploy, and run
the smoke test. Its configuration layout changed between major versions. The gateway
carries the routes CLIProxyAPI 8.0.27 serves for text models; a new release may add
routes, which `src/cgw/policy.py` would need.

**Caddy.** On a Docker host, Caddy is pinned by digest in `deploy/docker/compose.yaml`.
Replace the digest to move to a newer release, then `compose up -d`.

**Tools.** After a tool updates, run the smoke test in its format and one real session
with a tool call. A tool that starts calling a route the gateway does not carry gets
`not_found`; the routes are in `src/cgw/policy.py`, which both bridges read. Headers
need no list: everything except credentials and connection plumbing is passed on.

## Docker host behaviour worth knowing

- Caddy needs ports 80 and 443 reachable from the internet, and the hostname in
  `deploy/docker/.env` pointing at the host, before it can obtain a certificate.
  `compose logs caddy` shows its progress.
- `compose up -d` after the env file changes recreates only the gateway container.
  Caddy and its certificates stay as they are.
- The subscription logins live in the `gateway-data` volume and the certificates in
  `caddy-data`. `compose down` keeps both; `compose down -v` deletes them.
- `CGW_HTTP_PORT` and `CGW_HTTPS_PORT` in `deploy/docker/.env` move Caddy off ports 80
  and 443, and `CGW_ENV_FILE` points at an env file elsewhere.

## Railway CLI behaviour worth knowing

- `railway ssh` finds keys only in the SSH agent or `~/.ssh`. The agent forgets the
  project key at logout, so run `ssh-add ~/.cli-gateway/railway_ed25519` first.
- `railway logs` streams until interrupted, and `railway restart` sometimes does not
  return after the restart has happened. Press Ctrl-C once you have what you need.
- Restarting the container takes a few seconds. `railway redeploy` takes about two
  minutes.
- `railway variable delete` runs without a prompt and does not redeploy.
- A rollback restores the earlier deployment's variables as well as its image, so it can
  bring back a client key that was removed since. See "Remove a machine".
- `railway volume add` crashes when given a service name. Pass the service ID.

## Cost

The container uses about 105 MB of memory and almost no CPU when idle. On your own
host, that and Caddy are all it adds to what the host already costs.

At Railway's published rates ($10 per GB of memory per month, $20 per vCPU, $0.15 per
GB of volume, $0.05 per GB of egress) that is a little over $1 a month, which the Hobby
plan's included $5 of usage covers. Check with `railway usage`.

To be alerted on Railway, or to cap spending:

```
railway usage limit set --target workspace --soft 5 --hard 10
```

`--soft` only sends an email at that amount. `--hard` takes every workload in the
workspace offline when usage reaches it, and the minimum is $10.

## Reference

| Item | Where |
|---|---|
| Gateway address | `bin/cgw status` |
| Public endpoints | `POST /poc/v2/handshake`, `POST /poc/v2/exchange`, `GET /healthz`. Everything else is 404 |
| Routes the gateway carries for tools | `docs/protocol.md`, "Routes"; the code is `src/cgw/policy.py` |
| Gateway keys, Docker host | `deploy/docker/gateway.env` on the host: `CGW_CLIENT_<NAME>` (one per machine), `CGW_ADMIN_<NAME>` (one per admin), `CGW_CLIPROXY_KEY`, `CGW_CLIPROXY_MANAGEMENT_KEY` |
| Docker host settings | `deploy/docker/.env` on the host: `CGW_DOMAIN`, optionally `CGW_HTTP_PORT`, `CGW_HTTPS_PORT`, `CGW_ENV_FILE` |
| Railway variables | `CGW_CLIENT_<NAME>` (one per machine), `CGW_ADMIN_<NAME>` (one per admin), `CGW_CLIPROXY_KEY`, `CGW_CLIPROXY_MANAGEMENT_KEY`, `PORT`, `RAILWAY_DOCKERFILE_PATH` |
| Railway project, service and volume IDs | `railway status` |
| Local config (secret, owner-only) | `~/.cli-gateway/config.json` |
| Admin key (secret, owner-only, encrypted with a passphrase) | `~/.cli-gateway/admin.json` |
| Sign-in page | `bin/cgw admin`, at `127.0.0.1:8319` while it runs |
| Configs made for other machines (secret, delete once handed over) | `~/.cli-gateway/clients/` |
| Railway SSH key (secret) | `~/.cli-gateway/railway_ed25519` |
| Local bridge log | `~/.cli-gateway/local-bridge.log` |
| Codex profile (no secret) | `~/.codex/gateway.config.toml`, written by `python -m cgw install-profile` |
| Gemini CLI settings for gateway runs (no secret) | `~/.cli-gateway/gemini` |
| Variables tools read | `bin/cgw env` |
| On the volume | `/data/cliproxy/auth/` (subscription logins). The gateway stores nothing else |
| Gateway log lines | `exchange client=<name> ...` per request; `manage client=admin_<name> request=<method> <path> ...` per sign-in request |
| Limits | 2 requests in flight, shared by all machines; 8 MiB request body; 600 s per request; 120 s clock tolerance; 30 s to upload a request; 64 forwarded headers; 1,024-character query string |

Retries are off everywhere on purpose. Each attempt uses a new request ID, and a silent
retry could spend quota twice.

## What this does not protect against

- A compromised or monitored device. Plaintext exists on this machine.
- Other people's programs on a shared machine, fully. The launcher checks that the
  program on the local port really is the bridge before sending it anything, but the
  tools do not repeat that check on each request.
- Traffic a tool sends elsewhere. Only the API requests a tool sends to the local
  bridge go through the gateway. `bin/cgw claude` switches Claude Code's other traffic
  off; other tools may still contact their makers for updates or telemetry.
- A flood of connections to the gateway. A client without the key cannot hold any of
  the gateway's places or budgets, and idle connections are closed after 10 seconds,
  but a large enough sustained flood can still use up its connection limit. That is
  for the hosting platform's edge to stop.
- The host or the model provider reading the content. Plaintext exists there too.
- A stolen key, going forward. Past recordings stay unreadable thanks to the
  per-request key exchange, but whoever holds a machine's key can act as that machine,
  or as the gateway towards it, from then on. Remove that machine if its key may have
  leaked; the other machines' keys are unaffected.
- A stolen admin key together with its passphrase. Whoever has both can add and remove
  the gateway's sign-ins, though never read their tokens, until the admin key is
  revoked.
- A program running as you that takes a sign-in callback port first. For Google's
  sign-in, which has no code verifier, it could use the code it catches.
- Being noticed. The traffic is visibly encrypted application data sent to the
  gateway's host.
- Interference with availability. Anyone on the path can drop or delay the connection.
