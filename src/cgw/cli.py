"""Command-line entry points: `python -m cgw <command>`."""
import argparse
import asyncio
import base64
import contextlib
import getpass
import hmac
import json
import logging
import os
import stat
import subprocess
import secrets
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

import httpx
import uvicorn

from cgw import admin, admin_page, config, local_bridge, policy, protocol, remote_bridge, server

DEFAULT_LOCAL_CONFIG = Path.home() / ".cli-gateway" / "config.json"
# Where add-client leaves a new machine's config until it has been handed over.
DEFAULT_CLIENTS_DIR = Path.home() / ".cli-gateway" / "clients"

# No access log and no Server banner: logs carry our own lines only, and nothing names the stack.
_SERVER_OPTIONS = {"log_level": "warning", "access_log": False, "server_header": False,
                   "timeout_graceful_shutdown": 10}


def _fail(message):
    print("error: " + message, file=sys.stderr)
    return 1


def _remote(args, env, serve, run):
    try:
        loaded = config.load_remote(env)
    except config.ConfigError as error:
        return _fail(str(error))
    retired = [name for name in config.RETIRED_VARIABLES if name in env]
    if retired:
        print("note: %s are no longer read and admit no one; delete them" % " and ".join(retired), file=sys.stderr)
    # The public listener caps open connections so they cannot pile up without bound, and
    # closes any connection that does not deliver a request head within ten seconds, so
    # idle connections cannot sit on the cap.
    serve(remote_bridge.create_app(loaded.settings), host="0.0.0.0", port=loaded.port,
          http=server.HeadTimeoutProtocol, limit_concurrency=1024, **_SERVER_OPTIONS)
    return 0


def _local(args, env, serve, run):
    try:
        loaded = config.load_local(args.config)
    except config.ConfigError as error:
        return _fail(str(error))
    serve(local_bridge.create_app(loaded.settings), host=loaded.host, port=loaded.port, **_SERVER_OPTIONS)
    return 0


class _StoreError(Exception):
    """The place that holds the gateway's variables refused. The message says what was and was not done."""


class _RailwayStore:
    """The gateway's variables as Railway service variables, changed through the Railway CLI."""

    def __init__(self, run, service):
        self.run, self.service = run, service
        self.description = "Railway service %s" % service
        self.restart_command = "railway redeploy --service %s --yes" % service

    def names(self):
        """Names of the service's variables. Their values are read by the Railway CLI but never kept."""
        completed = self.run(["railway", "variable", "list", "--service", self.service, "--json"],
                             capture_output=True, text=True)
        if completed.returncode != 0:
            raise _StoreError("railway could not list the variables of service %s; nothing was changed" % self.service)
        try:
            listed = json.loads(completed.stdout)
        except ValueError:
            listed = None
        if type(listed) is not dict:
            raise _StoreError("railway listed the variables of service %s in a form this does not understand; "
                              "nothing was changed" % self.service)
        return set(listed)

    def set(self, name, value):
        # The value travels on stdin so it never appears in a process list or shell history.
        completed = self.run(["railway", "variable", "set", name, "--stdin", "--service", self.service,
                              "--skip-deploys"], input=value, text=True, capture_output=True)
        if completed.returncode != 0:
            raise _StoreError("railway refused to set %s" % name)

    def delete(self, name):
        completed = self.run(["railway", "variable", "delete", name, "--service", self.service],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True)
        if completed.returncode != 0:
            raise _StoreError("railway refused to delete %s" % name)

    def restart(self):
        """Restart the gateway so it reads the variables again. False if that was refused."""
        completed = self.run(["railway", "redeploy", "--service", self.service, "--yes"],
                             capture_output=True, text=True)
        return completed.returncode == 0


class _EnvFileStore:
    """The gateway's variables as an owner-only KEY=VALUE file, as Docker Compose's env_file
    and most hosts read it. Restarting the gateway is left to whoever runs it."""

    def __init__(self, path):
        self.path = Path(path)
        self.description = "env file %s" % self.path
        self.restart_command = None

    def _read(self):
        if not self.path.exists():
            return []
        if stat.S_IMODE(self.path.stat().st_mode) & 0o077:
            raise _StoreError("%s can be read by others; run: chmod 600 %s" % (self.path, self.path))
        return self.path.read_text().splitlines()

    def _write(self, lines):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A new, randomly named file created exclusively and owner-only: nothing planted at a
        # predictable name, file or symlink, can receive the keys or loosen their permissions.
        descriptor, temporary = tempfile.mkstemp(dir=self.path.parent, prefix="." + self.path.name + ".")
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write("".join(line + "\n" for line in lines))
            os.replace(temporary, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise

    @staticmethod
    def _name(line):
        name, separator, _ = line.partition("=")
        return name.strip() if separator and not line.lstrip().startswith("#") else None

    def names(self):
        return {name for name in map(self._name, self._read()) if name}

    def set(self, name, value):
        lines = [line for line in self._read() if self._name(line) != name]
        self._write(lines + ["%s=%s" % (name, value)])

    def delete(self, name):
        self._write([line for line in self._read() if self._name(line) != name])

    def restart(self):
        return False


def _store(args, run):
    """Where the gateway's variables live, as named on the command line, or None."""
    if getattr(args, "railway_service", None):
        return _RailwayStore(run, args.railway_service)
    if getattr(args, "env_file", None):
        return _EnvFileStore(args.env_file)
    return None


def _restart_note(store, what):
    """Restart the gateway if the store can; otherwise say how. Returns an exit code."""
    if store.restart_command is None:
        print("next: restart the gateway so it reads %s; %s (with Docker Compose: docker compose up -d)"
              % (store.path, what))
        return 0
    if not store.restart():
        return _fail("%s, but the restart was refused; run: %s" % (what, store.restart_command))
    print("the gateway is restarting; this takes about two minutes")
    return 0


def _issue(name, remote_url, path, proxy=None, ca_bundle=None):
    """Write a new client's config file, owner-only. Returns (path, secrets)."""
    generated = config.generate_secrets(kid=name)
    local_bridge.Settings(remote_url=remote_url, kid=generated.kid, psk=config.decode_psk(generated.psk),
                          local_key=generated.local_key, proxy=proxy, ca_bundle=ca_bundle)
    return config.write_local(path, remote_url, generated, proxy=proxy, ca_bundle=ca_bundle), generated


def _bootstrap(args, env, serve, run):
    """A new gateway's first client: this machine's config, and the gateway's half in its store."""
    store = _store(args, run)
    if store is None:
        return _fail("name where the gateway's variables live: --env-file <path> or --railway-service <name>")
    try:
        variable = config.client_variable(args.client_name)
        additions = [variable]
        if not args.no_admin:
            additions.append(config.admin_variable(args.client_name))
        config.check_key_capacity(store.names(), additions)
        path, generated = _issue(args.client_name, args.remote_url, args.config, args.proxy, args.ca_bundle)
    except (ValueError, config.ConfigError, _StoreError) as error:
        return _fail(str(error))

    variables = {variable: generated.psk}
    if args.set_cliproxy_key:
        variables["CGW_CLIPROXY_KEY"] = generated.cliproxy_key
    written = [path]
    if not args.no_admin:
        try:
            admin_path, admin_variables = _new_admin_key(args, args.client_name, args.remote_url)
        except (admin.AdminError, _PassphraseError) as error:
            path.unlink()
            return _fail("%s; the local config was removed, nothing is half-configured" % error)
        written.append(admin_path)
        variables.update(admin_variables)
    for name, value in variables.items():
        try:
            store.set(name, value)
        except _StoreError as error:
            for local_file in written:
                local_file.unlink()
            return _fail("%s; the local files were removed, nothing is half-configured" % error)

    print("wrote %s (owner-only)" % path)
    if not args.no_admin:
        print("wrote %s (the admin key, encrypted with your passphrase)" % written[1])
    print("set in %s: %s" % (store.description, ", ".join(variables)))
    if store.restart_command:
        print("next: deploy the gateway, or redeploy it so it uses the new keys: %s" % store.restart_command)
    else:
        print("next: start the gateway with this env file, or restart it so it reads it "
              "(with Docker Compose: docker compose up -d)")
    return 0


def _add_client(args, env, serve, run):
    """A key for one more machine: a config file to hand over, and the matching variable on the gateway."""
    try:
        variable = config.client_variable(args.name)
    except config.ConfigError as error:
        return _fail(str(error))
    remote_url = args.remote_url
    if remote_url is None:
        try:
            remote_url = config.load_local(args.config).settings.remote_url
        except config.ConfigError:
            return _fail("pass --remote-url <gateway-url>: there is no working config at %s to take it from"
                         % args.config)
    path = Path(args.out) if args.out else DEFAULT_CLIENTS_DIR / (args.name + ".json")
    store = _store(args, run)

    if store is not None:
        try:
            existing = store.names()
        except _StoreError as error:
            return _fail(str(error))
        if variable in existing and not args.replace:
            return _fail("client %s already exists; pass --replace to issue it a new key, "
                         "after which its current config stops working" % args.name)
        try:
            config.check_key_capacity(existing, [variable])
        except config.ConfigError as error:
            return _fail(str(error))
    try:
        path, generated = _issue(args.name, remote_url, path, args.proxy, args.ca_bundle)
    except (ValueError, config.ConfigError) as error:
        return _fail(str(error))

    print("wrote %s (owner-only)" % path)
    if store is None:
        print("next: on the gateway, add a variable named %s whose value is the \"psk\" in that file, "
              "then restart the gateway" % variable)
        print("check that the gateway will have at most 64 client and admin keys combined")
    else:
        try:
            store.set(variable, generated.psk)
        except _StoreError as error:
            path.unlink()
            return _fail("%s; the new config was removed, nothing is half-configured" % error)
        print("set in %s: %s" % (store.description, variable))
        code = _restart_note(store, "the gateway does not know %s until then" % args.name)
        if code:
            return code
    print("then: copy the file to the new machine as ~/.cli-gateway/config.json over a channel you trust, "
          "run bin/cgw setup there, and delete the copy here")
    return 0


def _remove_client(args, env, serve, run):
    """Shut one client out: delete its variable and restart the gateway without it."""
    store = _store(args, run)
    if store is None:
        return _fail("name where the gateway's variables live: --env-file <path> or --railway-service <name>")
    try:
        variable = config.client_variable(args.name)
        existing = store.names()
    except (config.ConfigError, _StoreError) as error:
        return _fail(str(error))
    if variable not in existing:
        return _fail("%s has no client named %s" % (store.description, args.name))
    if {name for name in existing if name.startswith(config.CLIENT_PREFIX)} == {variable}:
        return _fail("%s is the only client, and the gateway refuses to start without one; "
                     "add another client first" % args.name)
    try:
        store.delete(variable)
        if config.admin_variable(args.name) in existing:
            store.delete(config.admin_variable(args.name))
    except _StoreError as error:
        return _fail("%s; the client still works" % error)
    print("removed %s from %s" % (variable, store.description))
    return _restart_note(store, "the running gateway still admits %s until then" % args.name)


def _list_clients(args, env, serve, run):
    """The clients the gateway admits, by name. Never prints a key."""
    store = _store(args, run)
    if store is None:
        return _fail("name where the gateway's variables live: --env-file <path> or --railway-service <name>")
    try:
        existing = store.names()
    except _StoreError as error:
        return _fail(str(error))
    names, malformed = [], []
    for variable in sorted(name for name in existing if name.startswith(config.CLIENT_PREFIX)):
        try:
            names.append(config.client_name(variable))
        except config.ConfigError:
            malformed.append(variable)
    admins = set()
    for variable in (name for name in existing if name.startswith(config.ADMIN_PREFIX)):
        with contextlib.suppress(config.ConfigError):
            admins.add(config.client_name(variable, config.ADMIN_PREFIX))
    for name in sorted(names):
        print(name + (" (admin)" if name in admins else ""))
    for name in sorted(admins - set(names)):
        print(name + " (admin key only)")
    if not names:
        print("no clients: the gateway refuses to start until one is added")
    for variable in malformed:
        print("not a valid client variable, so the gateway refuses to start: %s" % variable)
    retired = [name for name in config.RETIRED_VARIABLES if name in existing]
    if retired:
        print("no longer read, safe to delete: %s" % ", ".join(retired))
    return 0


class _PassphraseError(Exception):
    """The passphrase was refused. The message never repeats it."""


def _asking(ask):
    """`ask`, refusing in one line where there is no terminal to type a passphrase into."""
    def asked(prompt):
        try:
            return ask(prompt)
        except EOFError:
            # With no terminal, getpass falls back to standard input; this is that, empty too.
            raise admin.AdminError("no passphrase could be read: run this command in a terminal") from None
    return asked


def _new_passphrase(ask):
    first = ask("Passphrase for the admin key (at least %d characters): " % admin.MIN_PASSPHRASE_CHARS)
    if len(first) < admin.MIN_PASSPHRASE_CHARS:
        raise _PassphraseError("the passphrase must be at least %d characters" % admin.MIN_PASSPHRASE_CHARS)
    if ask("The same passphrase again: ") != first:
        raise _PassphraseError("the two passphrases differ")
    return first


def _admin_key_path(args):
    return Path(args.admin_key) if getattr(args, "admin_key", None) else Path(args.config).parent / "admin.json"


def _new_admin_key(args, name, remote_url):
    """Write a new, encrypted admin key file. Returns (path, the gateway variables to set)."""
    psk = secrets.token_bytes(32)
    key = admin.AdminKey(name=name, remote_url=remote_url, kid=config.ADMIN_KID_PREFIX + name, psk=psk)
    path = admin.write_admin_key(_admin_key_path(args), key, _new_passphrase(args.ask))
    variables = {config.admin_variable(name): base64.urlsafe_b64encode(psk).rstrip(b"=").decode()}
    variables[config.MANAGEMENT_KEY_VARIABLE] = secrets.token_urlsafe(32)
    return path, variables


def _grant_admin(args, env, serve, run):
    """Make a machine an admin: a second, passphrase-encrypted key that can manage sign-ins."""
    store = _store(args, run)
    if store is None:
        return _fail("name where the gateway's variables live: --env-file <path> or --railway-service <name>")
    try:
        variable = config.admin_variable(args.name)
        existing = store.names()
        config.check_key_capacity(existing, [variable])
    except (config.ConfigError, _StoreError) as error:
        return _fail(str(error))
    if variable in existing and not args.replace:
        return _fail("%s is already an admin; pass --replace to give it a new admin key" % args.name)
    remote_url = args.remote_url
    if remote_url is None:
        try:
            remote_url = config.load_local(args.config).settings.remote_url
        except config.ConfigError:
            return _fail("pass --remote-url <gateway-url>: there is no working config at %s to take it from" % args.config)
    try:
        path, variables = _new_admin_key(args, args.name, remote_url)
    except (admin.AdminError, _PassphraseError) as error:
        return _fail(str(error))
    if config.MANAGEMENT_KEY_VARIABLE in existing:
        del variables[config.MANAGEMENT_KEY_VARIABLE]  # keep the one the gateway already has
    for name, value in variables.items():
        try:
            store.set(name, value)
        except _StoreError as error:
            path.unlink()
            return _fail("%s; the admin key file was removed" % error)
    print("wrote %s (the admin key, encrypted with your passphrase)" % path)
    print("set in %s: %s" % (store.description, ", ".join(variables)))
    return _restart_note(store, "%s cannot manage sign-ins until then" % args.name)


def _revoke_admin(args, env, serve, run):
    """Take a machine's admin key away. Its everyday key keeps working."""
    store = _store(args, run)
    if store is None:
        return _fail("name where the gateway's variables live: --env-file <path> or --railway-service <name>")
    try:
        variable = config.admin_variable(args.name)
        if variable not in store.names():
            return _fail("%s is not an admin of %s" % (args.name, store.description))
        store.delete(variable)
    except (config.ConfigError, _StoreError) as error:
        return _fail(str(error))
    print("removed %s from %s; the admin key file on that machine is now useless and can be deleted"
          % (variable, store.description))
    return _restart_note(store, "the running gateway still accepts that admin key until then")


def _run_admin(args, work):
    """Decrypt the admin key, then run `work(client)` against the gateway. Returns an exit code."""
    try:
        key = admin.load_admin_key(_admin_key_path(args), args.ask("Admin passphrase: "))
    except admin.AdminError as error:
        return _fail(str(error))
    proxy = ca_bundle = None
    with contextlib.suppress(config.ConfigError):
        local = config.load_local(args.config).settings
        proxy, ca_bundle = local.proxy, local.ca_bundle

    async def main():
        async with admin.AdminClient(key, proxy=proxy, ca_bundle=ca_bundle) as client:
            await work(client)

    try:
        asyncio.run(main())
    except admin.AdminError as error:
        return _fail(str(error))
    return 0


def _sign_in(args, env, serve, run):
    """Sign the gateway in to a subscription: the browser signs in, the tokens land on the gateway."""
    try:
        provider = admin.provider_id(args.provider)
    except admin.AdminError as error:
        return _fail(str(error))

    async def work(client):
        def open_browser(url):
            print("Sign in to %s in your browser. If no tab opens, open this address:\n  %s"
                  % (admin.PROVIDERS[provider], url))
            if not args.no_browser:
                args.browse(url)

        async def pasted():
            return await asyncio.to_thread(input, "After signing in, paste the address the browser ended up on: ")

        name = await admin.run_sign_in(client, provider, open_browser, pasted=pasted)
        print("signed in: %s; the tokens are on the gateway" % name)

    return _run_admin(args, work)


def _subscriptions(args, env, serve, run):
    """The subscriptions the gateway is signed in to. Never shows a token."""
    async def work(client):
        files = await client.sign_ins()
        if not files:
            print("the gateway is not signed in to any subscription")
        for entry in files:
            print("%-12s %-32s %-10s %s" % (entry.get("provider") or entry.get("type", ""), entry.get("email", ""),
                                             "disabled" if entry.get("disabled") else entry.get("status", ""),
                                             entry.get("name", "")))
    return _run_admin(args, work)


def _sign_out(args, env, serve, run):
    """Remove one sign-in from the gateway, by its file name (see: subscriptions)."""
    async def work(client):
        await client.sign_out(args.name)
        print("removed %s from the gateway" % args.name)
    return _run_admin(args, work)


def _admin(args, env, serve, run):
    """The local sign-in page, at a one-time address on this machine's loopback."""
    try:
        key = admin.load_admin_key(_admin_key_path(args), args.ask("Admin passphrase: "))
    except admin.AdminError as error:
        return _fail(str(error))
    proxy = ca_bundle = None
    with contextlib.suppress(config.ConfigError):
        local = config.load_local(args.config).settings
        proxy, ca_bundle = local.proxy, local.ca_bundle
    token = secrets.token_urlsafe(24)
    address = "http://127.0.0.1:%d/?token=%s" % (args.port, token)
    app = admin_page.create_app(admin.AdminClient(key, proxy=proxy, ca_bundle=ca_bundle), args.port, token, args.browse)
    print("Sign-in page (this link works once): %s" % address)
    print("Stop with Ctrl-C.")
    if not args.no_browser:
        threading.Timer(1.0, args.browse, [address]).start()
    serve(app, host="127.0.0.1", port=args.port, **_SERVER_OPTIONS)
    return 0


PROFILE_TEMPLATE = """\
# Codex profile for the encrypted gateway. Written by: python -m cgw install-profile
# Select with: codex --profile gateway   (bin/codex-gateway does this and starts the bridge)
model = "{model}"
model_provider = "encrypted_gateway"

[model_providers.encrypted_gateway]
name = "Encrypted gateway"
base_url = "http://127.0.0.1:{port}/v1"
env_key = "CGW_LOCAL_API_KEY"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
# Retries stay off: each attempt uses a new request ID, and a silent retry could spend quota twice.
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = 300000
"""


def _install_profile(args, env, serve, run):
    """Write the Codex profile that points Codex at the local bridge. Holds no secret."""
    try:
        loaded = config.load_local(args.config)
    except config.ConfigError as error:
        return _fail(str(error))
    codex_home = Path(env.get("CODEX_HOME") or Path.home() / ".codex")
    path = codex_home / "gateway.config.toml"
    text = PROFILE_TEMPLATE.format(model=args.model, port=loaded.port)
    if path.exists():
        if path.read_text() == text:
            print("Codex profile already installed at %s" % path)
            return 0
        return _fail("%s exists and differs from what would be written; move it away or edit it by hand" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print("wrote Codex profile %s" % path)
    return 0


def _bridge_state(base, local_key, client):
    """Who is listening on the bridge's port, decided without sending anything secret.

    "verified": it proved it holds the local key. "absent": nothing is listening.
    "outdated": it proved the key, but does not speak the current protocol.
    "impostor": something else holds the port and must not be sent a key or a prompt.
    """
    nonce = os.urandom(32)
    try:
        response = client.get(base + "/cgw/identity", params={"nonce": nonce.hex()})
    except httpx.ConnectError:
        return "absent"
    except httpx.HTTPError:
        return "impostor"
    try:
        payload = response.json()
        proof = payload["proof"]
    except (ValueError, KeyError, TypeError):
        return "impostor"
    expected = local_bridge.identity_proof(local_key, nonce)
    genuine = (response.status_code == 200 and isinstance(proof, str) and proof.isascii()
               and hmac.compare_digest(proof, expected))
    if not genuine:
        return "impostor"
    version = payload.get("protocol")
    return "verified" if type(version) is int and version == protocol.VERSION else "outdated"


_OUTDATED = "the local bridge uses another protocol; run bin/cgw smoke to replace it and check the gateway"

_IMPOSTOR = "port %d on this machine is held by a program that is not this gateway's local bridge; nothing was sent to it"


def _verify_bridge(args, env, serve, run):
    """Exit 0 for current, 3 for absent, 4 for authenticated outdated, 1 for unverified."""
    try:
        loaded = config.load_local(args.config)
    except config.ConfigError as error:
        return _fail(str(error))
    base = "http://%s:%d" % (loaded.host, loaded.port)
    with httpx.Client(timeout=5, trust_env=False) as client:
        state = _bridge_state(base, loaded.settings.local_key, client)
    if state == "verified":
        print("local bridge verified on %s" % base)
        return 0
    if state == "outdated":
        print(_OUTDATED)
        return 4
    if state == "absent":
        print("local bridge is not running on %s" % base)
        return 3
    return _fail(_IMPOSTOR % loaded.port)


def _describe(response):
    """A short reason for a failed response, using only the gateway's own error codes."""
    try:
        code = response.json()["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return "HTTP %d" % response.status_code
    return "%s (HTTP %d)" % (code, response.status_code)


_SMOKE_PROMPT = "Reply with exactly: gateway smoke test ok"
# Per API format: the model used when none is given, and the marker of a completed stream.
_SMOKE_DEFAULT_MODELS = {"responses": "gpt-6-astra", "chat": "gpt-6-astra"}
_SMOKE_MARKERS = {"responses": b"response.completed", "chat": b"[DONE]", "messages": b"message_stop",
                  "gemini": b"finishReason"}


def _smoke_request(fmt, model):
    """(path with query, extra headers, body) of one small streamed request in the given format."""
    if fmt == "responses":
        return "/v1/responses", {}, {"model": model, "stream": True, "reasoning": {"effort": "low"},
                                     "input": [{"role": "user", "content": _SMOKE_PROMPT}]}
    if fmt == "chat":
        return "/v1/chat/completions", {}, {"model": model, "stream": True,
                                            "messages": [{"role": "user", "content": _SMOKE_PROMPT}]}
    if fmt == "messages":
        return "/v1/messages", {"anthropic-version": "2023-06-01"}, {
            "model": model, "max_tokens": 64, "stream": True, "messages": [{"role": "user", "content": _SMOKE_PROMPT}]}
    return "/v1beta/models/%s:streamGenerateContent?alt=sse" % model, {}, {
        "contents": [{"role": "user", "parts": [{"text": _SMOKE_PROMPT}]}]}


def _smoke(args, env, serve, run):
    """One small request through the whole path, in one API format: local bridge, gateway, upstream."""
    try:
        loaded = config.load_local(args.config)
    except config.ConfigError as error:
        return _fail(str(error))
    model = args.model or _SMOKE_DEFAULT_MODELS.get(args.format)
    if model is None:
        return _fail("the %s format has no default model; pass --model (python -m cgw models lists them)" % args.format)
    path, extra_headers, body = _smoke_request(args.format, model)
    if not policy.route_allowed("POST", path.split("?")[0]):
        return _fail("%r is not a plain model name" % model)
    base = "http://%s:%d" % (loaded.host, loaded.port)
    headers = {"Authorization": "Bearer " + loaded.settings.local_key, **extra_headers}
    marker = _SMOKE_MARKERS[args.format]

    def failed(reason):
        print("FAIL: " + reason)
        return 1

    started = time.monotonic()
    try:
        with httpx.Client(timeout=httpx.Timeout(120, connect=5), trust_env=False) as client:
            # Nothing that carries the key or a prompt is sent until the listener has proved itself.
            state = _bridge_state(base, loaded.settings.local_key, client)
            if state == "absent":
                return failed("the local bridge is not running on %s; start it with: python -m cgw local" % base)
            if state == "outdated":
                return failed(_OUTDATED)
            if state == "impostor":
                return failed(_IMPOSTOR % loaded.port)
            models = client.get(base + "/v1/models", headers=headers)
            if models.status_code != 200:
                return failed("listing models: " + _describe(models))
            served = len(models.json().get("data", []))
            if served == 0:
                return failed("the gateway answered but serves no models; the upstream login may have lapsed")
            print("models: %d served (%.2fs)" % (served, time.monotonic() - started))

            started, first_byte, received = time.monotonic(), None, b""
            with client.stream("POST", base + path, json=body, headers=headers) as response:
                if response.status_code != 200:
                    response.read()
                    return failed("model request: " + _describe(response))
                for chunk in response.iter_raw():
                    first_byte = first_byte or time.monotonic() - started
                    received += chunk
    except httpx.ConnectError:
        return failed("the local bridge is not running on %s; start it with: python -m cgw local" % base)
    except httpx.HTTPError as error:
        return failed("the stream broke before it completed (%s)" % type(error).__name__)
    if marker not in received:
        return failed("the stream ended without %s" % marker.decode())
    print("model request (%s format, %s): %d bytes, first byte after %.2fs, %s after %.2fs"
          % (args.format, model, len(received), first_byte, marker.decode(), time.monotonic() - started))
    print("PASS")
    return 0


def _models(args, env, serve, run):
    """The model names the gateway serves, one per line, for choosing --model or a tool's model."""
    try:
        loaded = config.load_local(args.config)
    except config.ConfigError as error:
        return _fail(str(error))
    base = "http://%s:%d" % (loaded.host, loaded.port)
    try:
        with httpx.Client(timeout=httpx.Timeout(30, connect=5), trust_env=False) as client:
            state = _bridge_state(base, loaded.settings.local_key, client)
            if state == "absent":
                return _fail("the local bridge is not running on %s; start it with: python -m cgw local" % base)
            if state == "outdated":
                return _fail(_OUTDATED)
            if state == "impostor":
                return _fail(_IMPOSTOR % loaded.port)
            response = client.get(base + "/v1/models", headers={"Authorization": "Bearer " + loaded.settings.local_key})
    except httpx.HTTPError:
        return _fail("the local bridge did not answer on %s" % base)
    if response.status_code != 200:
        return _fail("listing models: " + _describe(response))
    for name in sorted({str(entry.get("id")) for entry in response.json().get("data", []) if isinstance(entry, dict)}):
        print(name)
    return 0


def _store_options(parser, note=""):
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--env-file", help="the gateway's variables are in this KEY=VALUE file (Docker Compose, "
                                          "any host)" + note)
    where.add_argument("--railway-service", help="the gateway's variables are on this Railway service, "
                                                 "changed with the Railway CLI")


def main(argv=None, env=None, serve=None, run=None, ask=None, browse=None):
    env = os.environ if env is None else env
    serve = serve or uvicorn.run
    run = run or subprocess.run

    parser = argparse.ArgumentParser(prog="cgw", description="Encrypted gateway for command-line AI tools")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("remote", help="run the remote bridge (inside the gateway container)").set_defaults(
        handler=_remote)

    local = commands.add_parser("local", help="run the local bridge on loopback")
    local.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    local.set_defaults(handler=_local)

    bootstrap = commands.add_parser("bootstrap", help="a new gateway's first client, on this machine")
    bootstrap.add_argument("--remote-url", required=True)
    bootstrap.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    _store_options(bootstrap)
    bootstrap.add_argument("--client-name", required=True, help="this machine's name, such as work-laptop")
    bootstrap.add_argument("--no-admin", action="store_true",
                           help="do not make this machine an admin (no passphrase-protected admin key)")
    bootstrap.add_argument("--admin-key", help="where to write the admin key (default: next to --config)")
    bootstrap.add_argument("--set-cliproxy-key", action="store_true",
                           help="also replace the internal CLIProxyAPI key")
    bootstrap.add_argument("--proxy")
    bootstrap.add_argument("--ca-bundle")
    bootstrap.set_defaults(handler=_bootstrap)

    add = commands.add_parser("add-client", help="issue a key and a config file for one more machine")
    add.add_argument("name", help="the new machine's name, such as work-laptop")
    _store_options(add, note="; without either, only the file is written and the variable to add is named")
    add.add_argument("--remote-url", help="the gateway address; by default taken from --config")
    add.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG), help="this machine's own config")
    add.add_argument("--out", help="where to write the new config (default: %s/<name>.json)" % DEFAULT_CLIENTS_DIR)
    add.add_argument("--replace", action="store_true", help="issue a new key for a client that already exists")
    add.add_argument("--proxy")
    add.add_argument("--ca-bundle")
    add.set_defaults(handler=_add_client)

    remove = commands.add_parser("remove-client", help="shut one machine out and redeploy the gateway")
    remove.add_argument("name")
    _store_options(remove)
    remove.set_defaults(handler=_remove_client)

    listing = commands.add_parser("list-clients", help="name the machines the gateway admits")
    _store_options(listing)
    listing.set_defaults(handler=_list_clients)

    grant = commands.add_parser("grant-admin", help="give a machine a passphrase-protected admin key for sign-ins")
    grant.add_argument("name", help="the machine's name, such as work-laptop")
    _store_options(grant)
    grant.add_argument("--remote-url", help="the gateway address; by default taken from --config")
    grant.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG), help="this machine's own config")
    grant.add_argument("--admin-key", help="where to write the admin key (default: next to --config)")
    grant.add_argument("--replace", action="store_true", help="give an existing admin a new admin key")
    grant.set_defaults(handler=_grant_admin)

    revoke = commands.add_parser("revoke-admin", help="take a machine's admin key away")
    revoke.add_argument("name")
    _store_options(revoke)
    revoke.set_defaults(handler=_revoke_admin)

    def admin_command(name, handler, help_text):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
        command.add_argument("--admin-key", help="this machine's admin key (default: next to --config)")
        command.set_defaults(handler=handler)
        return command

    sign_in = admin_command("sign-in", _sign_in, "sign the gateway in to a subscription, in your browser")
    sign_in.add_argument("provider", help="claude, codex, google (Antigravity, for Gemini models), xai, kimi, meta, devin")
    sign_in.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")
    admin_command("subscriptions", _subscriptions, "list the subscriptions the gateway is signed in to")
    sign_out = admin_command("sign-out", _sign_out, "remove one sign-in from the gateway")
    sign_out.add_argument("name", help="its file name, as subscriptions lists it")
    page = admin_command("admin", _admin, "open the local sign-in page")
    page.add_argument("--port", type=int, default=8319)
    page.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")

    smoke = commands.add_parser("smoke", help="send one small request through the whole path")
    smoke.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    smoke.add_argument("--format", choices=sorted(_SMOKE_MARKERS), default="responses",
                       help="API format: responses (Codex), chat (OpenAI-style tools), messages (Claude Code), gemini")
    smoke.add_argument("--model", help="model to ask; needed for messages and gemini (see: python -m cgw models)")
    smoke.set_defaults(handler=_smoke)

    models = commands.add_parser("models", help="list the model names the gateway serves")
    models.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    models.set_defaults(handler=_models)

    profile = commands.add_parser("install-profile", help="write the Codex profile for the gateway")
    profile.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    profile.add_argument("--model", default="gpt-6-astra")
    profile.set_defaults(handler=_install_profile)

    verify = commands.add_parser("verify-bridge", help="check that the listener on the bridge's port is genuine")
    verify.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    verify.set_defaults(handler=_verify_bridge)

    args = parser.parse_args(argv)
    # Prompts and the browser are injected, so the commands can be driven without a terminal.
    args.ask = _asking(ask or getpass.getpass)
    args.browse = browse or webbrowser.open
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    # The bridges log their own one-line summaries; the HTTP client's per-request lines stay out.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return args.handler(args, env, serve, run)
