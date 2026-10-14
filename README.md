# cli-gateway

A secure, self-hosted gateway to a server that holds your AI subscriptions. The server
runs [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI), which signs in to
your subscriptions and serves them through one API. cli-gateway puts that server behind
a single encrypted endpoint that only the machines you authorise can use.

Each machine runs a small local bridge, and your command-line tools talk to it as if it
were the provider's API. Requests and responses are encrypted end to end between the
bridge and the gateway, so neither the network nor the hosting platform's edge can read
prompts, replies or keys, even where they inspect HTTPS.

The gateway runs as one container on any Docker host, with a recipe that obtains its
TLS certificate by itself, or on Railway.

```
Codex, Claude Code, Gemini CLI, ...  started through bin/cgw
   │ plain HTTP, loopback, in the tool's own API format
   ▼
local bridge 127.0.0.1:8318          your machine; encrypts requests, verifies responses
   │ HTTPS, encrypted envelope
   ▼
your gateway                         one container, on any Docker host or on Railway
   remote bridge                     admits only your machines, decrypts, re-encrypts the stream
   │ container loopback
   CLIProxyAPI                       holds your subscription logins, calls the providers
```

## Supported tools

Any command-line tool that speaks one of the API formats CLIProxyAPI serves can use the
gateway: OpenAI (chat completions and responses), Anthropic (messages) or Gemini.
CLIProxyAPI picks the subscription for each request by the model name the tool asks for,
so the gateway needs a sign-in for that subscription.

| Tool | API format | Run it with | The gateway needs signed in |
|---|---|---|---|
| [Codex CLI](https://github.com/openai/codex) | OpenAI responses | `bin/cgw codex` | A plan that includes Codex (`-codex-login`) |
| Claude Code | Anthropic messages | `bin/cgw claude` | A Claude subscription (`-claude-login`) |
| Gemini CLI | Gemini | `bin/cgw gemini` | A Google account through Antigravity (`-antigravity-login`) |
| opencode, and other OpenAI-compatible tools | OpenAI chat completions | `bin/cgw run <tool>` | Whichever subscription serves the model the tool asks for |

Your tools' normal setup is untouched. `bin/cgw` points a tool at the gateway for that
run only. Which tools have been run through a live gateway so far is in the
[design record](docs/design.md).

## Before you rely on it

- **It is a proof of concept.** The protocol uses established primitives (X25519,
  libsodium secretstream, HKDF-SHA256) and is heavily tested, but it has not been
  independently audited. Every request runs its own key exchange, so a recording of
  your traffic stays unreadable even if the pre-shared key is stolen later.
- **It protects content in transit, nothing more.** A network observer still sees the
  gateway's hostname, traffic timing and sizes, and that the payload is encrypted.
- **It carries API requests only.** A tool's own update checks or telemetry do not go
  through the gateway. `bin/cgw claude` turns Claude Code's off; other tools may still
  contact their makers directly.
- **It does not replace upstream.** If a provider is down, or your account loses
  access, the gateway cannot help.
- **It depends on [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI),** a
  community project that is not an official endpoint. You need your own subscription
  for each provider you use, and each provider's terms still apply. This project adds
  no entitlement and bypasses no quota.

The full list is in [the protocol notes](docs/protocol.md#what-the-protocol-provides-and-what-it-does-not).

## Requirements

| For | You need |
|---|---|
| Any machine that uses a gateway | macOS or Linux, [uv](https://docs.astral.sh/uv/), the tools you want to use, and a config file from the gateway's admin |
| A gateway on your own host | A Linux host with Docker and Docker Compose, a hostname that points at it, and ports 80 and 443 open to the internet |
| A gateway on Railway | A [Railway](https://railway.com) account on the Hobby plan and the Railway CLI |
| Signing the gateway in to a subscription | Docker and a browser, on any machine |

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
it holds this machine's key. This machine needs no account with the gateway's host.
Then:

```
bin/cgw setup
```

`setup` does four things:

1. installs the Python environment into `.venv` from the lock file;
2. makes the configuration file readable by you only;
3. writes the Codex profile `~/.codex/gateway.config.toml`, which holds no secret;
4. starts the local bridge and sends one small request through the whole path.

It ends with `PASS` when everything works.

## Use your tools

| To do this | Run |
|---|---|
| Use Codex | `bin/cgw codex` (arguments go to Codex, e.g. `bin/cgw codex exec "..."`) |
| Use Claude Code | `bin/cgw claude` (arguments go to Claude Code) |
| Use Gemini CLI | `bin/cgw gemini` (arguments go to Gemini CLI) |
| Use any other tool | `bin/cgw run <command> [arguments]` |
| See the model names the gateway serves | `bin/cgw models` |
| Check the whole path | `bin/cgw smoke` (add `--format` and `--model` for other formats) |
| See what a tool needs to reach the gateway | `bin/cgw env` |
| See the gateway address and bridge state | `bin/cgw status` |
| Stop the local bridge | `bin/cgw stop` |

`bin/codex-gateway`, from earlier versions, still works: it is `bin/cgw` with Codex as
the tool.

**Claude Code.** `bin/cgw claude` sets `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`
for that run and switches off Claude Code's traffic that would go around the gateway
(telemetry, error reports, update checks). Choose a model the gateway serves with
`--model`.

**Gemini CLI.** `bin/cgw gemini` sets `GOOGLE_GEMINI_BASE_URL` and `GEMINI_API_KEY`,
and gives gateway runs their own settings folder, `~/.cli-gateway/gemini`, which selects
key-based access. Your normal Gemini CLI setup is untouched. Gemini CLI asks you to
trust a folder before it works in it; run headless with `-p`, it needs a folder you have
already trusted, or `--skip-trust`. Pass the model with `-m` exactly as `bin/cgw models`
lists it: Gemini CLI rewrites some short names, such as `gemini-3-flash`, into names the
gateway may not serve.

**Other tools.** `bin/cgw run <command>` starts any tool with these variables set:
`OPENAI_BASE_URL` (`http://127.0.0.1:8318/v1`) and `OPENAI_API_KEY`;
`ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`; `GOOGLE_GEMINI_BASE_URL` and
`GEMINI_API_KEY`. The key is the local key, which opens only the local bridge on this
machine. For a tool configured by file, refer to the variables rather than copying the
key. For opencode, in its `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "gateway": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Gateway",
      "options": {"baseURL": "{env:OPENAI_BASE_URL}", "apiKey": "{env:OPENAI_API_KEY}"},
      "models": {"gpt-6-astra": {"name": "gpt-6-astra"}}
    }
  },
  "model": "gateway/gpt-6-astra"
}
```

List the models you want from `bin/cgw models`, then run `bin/cgw run opencode`.

The local bridge starts on demand. After setup nothing is downloaded at run time.

Before the launcher sends your key or a prompt to the local port, it makes whatever is
listening there prove that it is the bridge. If another program has taken the port, the
launcher says so and sends it nothing.

If your network needs an outbound proxy, with or without a password, or uses its own TLS
certificate authority, see [Proxy and CA](docs/runbook.md#proxy-and-ca). PAC files and
Windows-integrated proxy login (NTLM, Kerberos) are not supported.

## Deploy your own gateway

Done once. Choose a host: your own Docker host, or Railway. Both run the same image,
built from `deploy/Dockerfile`.

### Any Docker host (recommended)

`deploy/docker/compose.yaml` runs the gateway behind [Caddy](https://caddyserver.com),
which obtains and renews the TLS certificate for your hostname by itself. The gateway's
secrets are kept in `deploy/docker/gateway.env` on the host, readable by its owner
only. Git ignores that file, and it is never copied into the image.

This recipe was run on one machine with Caddy's own certificate authority, not yet with
a public certificate, so expect to adjust a step.

**1. Prepare the host.** Install Docker with Docker Compose, git and
[uv](https://docs.astral.sh/uv/). Point a hostname at the host, for example
`gateway.example.com`, with a DNS A or AAAA record, and open ports 80 and 443. Caddy
needs both to obtain the certificate.

**2. Get the code and name the host.** On the host:

```
git clone https://github.com/cyberian-hacksy/cli-gateway.git
cd cli-gateway
uv sync
echo "CGW_DOMAIN=gateway.example.com" > deploy/docker/.env
```

**3. Generate the keys.** This makes your own machine the gateway's first client, under
a name you choose, such as `work-laptop`. It writes the gateway's half into the env file
and your machine's config into `~/.cli-gateway/clients/` on the host. Keys are never
printed.

```
.venv/bin/python -m cgw bootstrap --remote-url https://gateway.example.com \
    --env-file deploy/docker/gateway.env --config ~/.cli-gateway/clients/<name>.json \
    --client-name <name> --set-cliproxy-key
```

**4. Start it.**

```
docker compose -f deploy/docker/compose.yaml up -d --build
```

`curl https://gateway.example.com/healthz` should return `{"status":"ok"}` once Caddy
has its certificate, usually within a minute.

**5. Sign the gateway in to your subscriptions.** Follow
[Signing in a subscription](docs/runbook.md#signing-in-a-subscription), once for each
subscription.

**6. Finish on your machine.** Copy `~/.cli-gateway/clients/<name>.json` from the host
to your machine as `~/.cli-gateway/config.json`, over a channel you trust, delete it on
the host, and then, in your clone of the repository:

```
bin/cgw setup
```

**7. Add other machines.** Each gets its own key and its own config file, and can be
removed on its own later. See
[Adding and removing machines](docs/runbook.md#adding-and-removing-machines).

### Railway

It creates one Railway service with one volume, costing a little over $1 a month in
usage, which the Hobby plan's included $5 covers. These commands were each used to build
a working deployment, but not as one uninterrupted sequence, so expect to adjust a step.

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

**6. Sign the gateway in to your subscriptions.** Follow
[Signing in a subscription](docs/runbook.md#signing-in-a-subscription), once for each
subscription.

**7. Finish on this machine.**

```
bin/cgw setup
```

**8. Add other machines.** See
[Adding and removing machines](docs/runbook.md#adding-and-removing-machines).

For day-to-day operation, troubleshooting, key rotation and updates, see the
[runbook](docs/runbook.md).

## Keeping secrets out of the repository

Nothing secret is stored in this repository, and nothing deployment-specific either.

| What | Where it lives |
|---|---|
| This machine's key, local bearer key, gateway address | `~/.cli-gateway/config.json`, readable by you only |
| Config files made for other machines, until handed over | `~/.cli-gateway/clients/`, readable by you only |
| Gateway-side keys, on a Docker host | `deploy/docker/gateway.env` on the host, readable by its owner only, one `CGW_CLIENT_<NAME>` per machine |
| Gateway-side keys, on Railway | Railway service variables, one `CGW_CLIENT_<NAME>` per machine |
| The gateway's hostname, on a Docker host | `deploy/docker/.env` on the host |
| Railway SSH key | `~/.cli-gateway/railway_ed25519` |
| Subscription logins, held by CLIProxyAPI | The gateway's volume |

Git ignores `*.env` and `.env` files, `.dockerignore` keeps them out of the image's
build context, and `.railwayignore` keeps them out of Railway uploads.
`tests/test_repo_hygiene.py` scans every file git would track for key material, tokens,
real hostnames, account identifiers, email addresses, home-directory paths and env
files. Turn on the pre-commit hook so it runs before every commit:

```
git config core.hooksPath .githooks
```

## Development

```
uv sync                # runtime and test dependencies
uv run pytest          # the whole suite, about two and a half minutes
```

The bridge tests start real servers on loopback sockets and run the full path, in every
API format, through a hostile proxy that drops, flips, reorders and injects records.

| Path | Contents |
|---|---|
| `bin/cgw` | Launcher: setup, run a tool, smoke test, models, status, stop |
| `bin/codex-gateway` | The same launcher with Codex as the tool, kept for existing setups |
| `src/cgw/protocol.py` | Wire protocol: envelope, key derivation, record framing |
| `src/cgw/local_bridge.py` | The endpoint tools talk to on loopback |
| `src/cgw/remote_bridge.py` | The gateway's only public surface |
| `src/cgw/sse.py` | Releases stream events one behind, the last only once the stream has verified |
| `src/cgw/policy.py` | Routes, query rules and header rules, shared by both bridges |
| `src/cgw/config.py`, `cli.py` | Configuration loading and the `python -m cgw` commands |
| `deploy/` | Container image for the gateway |
| `deploy/docker/` | Docker Compose recipe with Caddy, for any Docker host |
| `probe/` | A small streaming probe for diagnosing a network path |
| `tests/` | Test suite, an independent reference for the wire format, frozen vectors |

## Documentation

- [Runbook](docs/runbook.md): everyday use, troubleshooting, adding machines, signing
  in subscriptions, key rotation, updating, cost.
- [Wire protocol](docs/protocol.md): the envelope, the record stream, the routes and
  header rules, limits, and what the protocol does and does not provide.
- [Design and verification record](docs/design.md): the decisions behind the design and
  the results of each test stage.

## Licence

MIT. See [LICENSE](LICENSE).
