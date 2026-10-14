# cli-gateway

A fallback route for the [Codex CLI](https://github.com/openai/codex) for when
`chatgpt.com` cannot be reached from your network. Codex talks to a small bridge on
your machine, which sends every request through a gateway you host yourself. Requests
and responses are encrypted between the two, so a network that inspects HTTPS sees only
ciphertext.

```
Codex --profile gateway
   │ plain HTTP, loopback
   ▼
local bridge 127.0.0.1:8318        your machine; encrypts requests, verifies responses
   │ HTTPS, encrypted envelope
   ▼
your gateway                       one container on Railway
   remote bridge                   decrypts, refuses replays, re-encrypts the stream
   │ container loopback
   CLIProxyAPI                     holds your ChatGPT login, calls upstream
```

Normal Codex use is untouched. The gateway is a separate Codex profile that you select
when you need it.

## Before you rely on it

- **It is a proof of concept.** The protocol uses established primitives (X25519,
  libsodium secretstream, HKDF-SHA256) and is heavily tested, but it has not been
  independently audited. Every request runs its own key exchange, so a recording of
  your traffic stays unreadable even if the pre-shared key is stolen later.
- **It protects content in transit, nothing more.** A network observer still sees the
  gateway's hostname, traffic timing and sizes, and that the payload is encrypted. It
  does not hide that you use a gateway, and it cannot stop the network from blocking it.
- **It does not replace upstream.** If the model provider is down, or your account
  loses access, the gateway cannot help.
- **It depends on [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI),** a
  community project that is not an official endpoint. You need your own ChatGPT
  subscription that includes Codex, and your provider's terms still apply. This project
  adds no entitlement and bypasses no quota.

The full list is in [the protocol notes](docs/protocol.md#what-the-protocol-provides-and-what-it-does-not).

## Requirements

| For | You need |
|---|---|
| Any machine that uses a gateway | macOS or Linux, [uv](https://docs.astral.sh/uv/), the Codex CLI, and a config file from the gateway's admin |
| Deploying a gateway, or adding and removing machines | A [Railway](https://railway.com) account on the Hobby plan, the Railway CLI, Docker |

Windows is not supported; the launcher is a bash script.

## Set up a machine

Use this on every machine that should reach a gateway that already exists. To create
the gateway first, see [Deploy your own gateway](#deploy-your-own-gateway).

```
git clone https://github.com/cyberian-hacksy/cli-gateway.git
cd cli-gateway
```

Every machine has its own key. Ask the gateway's admin for this machine's config file
(they make it with `add-client`; see
[Adding and removing machines](docs/runbook.md#adding-and-removing-machines)) and save
it as `~/.cli-gateway/config.json`. It must reach you over a channel you trust, because
it holds this machine's key. This machine needs no Railway account or Railway CLI.
Then:

```
bin/codex-gateway setup
```

`setup` does four things:

1. installs the Python environment into `.venv` from the lock file;
2. makes the configuration file readable by you only;
3. writes the Codex profile `~/.codex/gateway.config.toml`, which holds no secret;
4. starts the local bridge and sends one small request through the whole path.

It ends with `PASS` when everything works. From then on:

| To do this | Run |
|---|---|
| Use Codex through the gateway | `bin/codex-gateway` (arguments go to Codex, e.g. `bin/codex-gateway exec "..."`) |
| Check the whole path | `bin/codex-gateway smoke` |
| See the gateway address and bridge state | `bin/codex-gateway status` |
| Stop the local bridge | `bin/codex-gateway stop` |

The local bridge starts on demand. After setup nothing is downloaded at run time, which
matters on a restricted network.

Before the launcher sends your key or a prompt to the local port, it makes whatever is
listening there prove that it is the bridge. If another program has taken the port, the
launcher says so and sends it nothing.

If your network needs an outbound proxy, with or without a password, or uses its own TLS
certificate authority, see [Proxy and CA](docs/runbook.md#proxy-and-ca). PAC files and
Windows-integrated proxy login (NTLM, Kerberos) are not supported.

## Deploy your own gateway

Done once. It creates one Railway service with one volume, costing a little over $1 a
month in usage, which the Hobby plan's included $5 covers.

These commands were each used to build a working deployment, but not as one
uninterrupted sequence, so expect to adjust a step.

Do this on a network where `chatgpt.com` still works, because the ChatGPT login in step
6 needs it.

**1. Prepare the repository and Railway.**

```
uv sync
railway login
railway init --name cli-gateway
railway add --service gateway          # note the service ID it prints
```

**2. Add storage, settings and a public address.**

```
railway volume --service <service-id> add --mount-path /data
railway variable set PORT=8080 RAILWAY_DOCKERFILE_PATH=deploy/Dockerfile --service gateway --skip-deploys
railway domain --service gateway --port 8080     # note the URL: this is <gateway-url>
```

Pass the service ID to `volume add`; that command crashes when given the name.

**3. Register an SSH key with Railway.** It is used to reach the container.

```
mkdir -p ~/.cli-gateway && chmod 700 ~/.cli-gateway
ssh-keygen -t ed25519 -N "" -f ~/.cli-gateway/railway_ed25519
ssh-add ~/.cli-gateway/railway_ed25519
railway ssh keys add
```

**4. Generate the keys.** This makes this machine the gateway's first client, under a
name you choose, such as `work-laptop`. It writes `~/.cli-gateway/config.json` and sets
the matching variables on Railway: `CGW_CLIENT_<NAME>` for this machine's key and
`CGW_CLIPROXY_KEY`. Keys are sent on standard input and never printed.

```
.venv/bin/python -m cgw bootstrap --remote-url <gateway-url> --railway-service gateway \
    --client-name <name> --set-cliproxy-key
```

**5. Deploy.**

```
railway up --service gateway --ci
```

`curl <gateway-url>/healthz` should now return `{"status":"ok"}`.

**6. Log the gateway in to ChatGPT.** Follow
[Renewing the upstream login](docs/runbook.md#renewing-the-upstream-login); on a new
gateway the steps are the same.

**7. Finish on this machine.**

```
bin/codex-gateway setup
```

**8. Add other machines.** Each gets its own key and its own config file, and can be
removed on its own later. See
[Adding and removing machines](docs/runbook.md#adding-and-removing-machines).

For day-to-day operation, troubleshooting, key rotation and updates, see the
[runbook](docs/runbook.md).

## Keeping secrets out of the repository

Nothing secret is stored in this repository, and nothing deployment-specific either.

| What | Where it lives |
|---|---|
| This machine's key, local bearer key, gateway address | `~/.cli-gateway/config.json`, readable by you only |
| Config files made for other machines, until handed over | `~/.cli-gateway/clients/`, readable by you only |
| Railway SSH key | `~/.cli-gateway/railway_ed25519` |
| Gateway-side keys | Railway service variables, one `CGW_CLIENT_<NAME>` per machine |
| ChatGPT login | The gateway's volume |

`tests/test_repo_hygiene.py` scans every file git would track for key material, tokens,
real hostnames, account identifiers, email addresses and home-directory paths. Turn on
the pre-commit hook so it runs before every commit:

```
git config core.hooksPath .githooks
```

## Development

```
uv sync                # runtime and test dependencies
uv run pytest          # the whole suite, about 90 seconds
```

The bridge tests start real servers on loopback sockets and run the full path through
a hostile proxy that drops, flips, reorders and injects records.

| Path | Contents |
|---|---|
| `bin/codex-gateway` | Launcher: setup, run Codex, smoke test, status, stop |
| `src/cgw/protocol.py` | Wire protocol: envelope, key derivation, record framing |
| `src/cgw/local_bridge.py` | The endpoint Codex talks to on loopback |
| `src/cgw/remote_bridge.py` | The gateway's only public surface |
| `src/cgw/sse.py` | Holds the completion event until the stream has verified |
| `src/cgw/policy.py` | Allowed routes and headers, shared by both bridges |
| `src/cgw/config.py`, `cli.py` | Configuration loading and the `python -m cgw` commands |
| `deploy/` | Container image for the gateway |
| `probe/` | A small streaming probe for diagnosing a network path |
| `tests/` | Test suite, an independent reference for the wire format, frozen vectors |

## Documentation

- [Runbook](docs/runbook.md): everyday use, troubleshooting, key rotation, renewing the
  login, updating, cost.
- [Wire protocol](docs/protocol.md): the envelope, the record stream, limits, and what
  the protocol does and does not provide.
- [Design and verification record](docs/design.md): the decisions behind the design and
  the results of each test stage.

## Licence

MIT. See [LICENSE](LICENSE).
