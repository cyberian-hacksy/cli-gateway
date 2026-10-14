"""Command-line entry points: `python -m cgw <command>`."""
import argparse
import hmac
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn

from cgw import config, local_bridge, remote_bridge, server

DEFAULT_LOCAL_CONFIG = Path.home() / ".cli-gateway" / "config.json"

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


def _bootstrap(args, env, serve, run):
    """Generate a fresh key set, store the local half, and hand the remote half to Railway."""
    generated = config.generate_secrets()
    try:
        local_bridge.Settings(remote_url=args.remote_url, kid=generated.kid,
                              psk=config.decode_psk(generated.psk), local_key=generated.local_key)
        path = config.write_local(args.config, args.remote_url, generated, proxy=args.proxy, ca_bundle=args.ca_bundle)
    except (ValueError, config.ConfigError) as error:
        return _fail(str(error))

    variables = {"CGW_KID": generated.kid, "CGW_PSK": generated.psk}
    if args.set_cliproxy_key:
        variables["CGW_CLIPROXY_KEY"] = generated.cliproxy_key
    for name, value in variables.items():
        # The value travels on stdin so it never appears in a process list or shell history.
        completed = run(["railway", "variable", "set", name, "--stdin", "--service", args.railway_service,
                         "--skip-deploys"], input=value, text=True, capture_output=True)
        if completed.returncode != 0:
            path.unlink()
            return _fail("railway refused to set %s; the local config was removed, nothing is half-configured" % name)

    print("wrote %s (owner-only)" % path)
    print("set on Railway service %s: %s" % (args.railway_service, ", ".join(variables)))
    print("next: redeploy the gateway so it uses the new keys: railway redeploy --service %s --yes"
          % args.railway_service)
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
        proof = response.json()["proof"]
    except (ValueError, KeyError, TypeError):
        return "impostor"
    expected = local_bridge.identity_proof(local_key, nonce)
    genuine = isinstance(proof, str) and hmac.compare_digest(proof, expected)
    return "verified" if genuine else "impostor"


_IMPOSTOR = "port %d on this machine is held by a program that is not this gateway's local bridge; nothing was sent to it"


def _verify_bridge(args, env, serve, run):
    """Exit 0 if the local bridge is running and genuine, 3 if nothing is listening, 1 otherwise."""
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


def _smoke(args, env, serve, run):
    """One small request through the whole path: local bridge, gateway, upstream."""
    try:
        loaded = config.load_local(args.config)
    except config.ConfigError as error:
        return _fail(str(error))
    base = "http://%s:%d" % (loaded.host, loaded.port)
    headers = {"Authorization": "Bearer " + loaded.settings.local_key}

    def failed(reason):
        print("FAIL: " + reason)
        return 1

    body = {"model": args.model, "stream": True, "reasoning": {"effort": "low"},
            "input": [{"role": "user", "content": "Reply with exactly: gateway smoke test ok"}]}
    started = time.monotonic()
    try:
        with httpx.Client(timeout=httpx.Timeout(120, connect=5), trust_env=False) as client:
            # Nothing that carries the key or a prompt is sent until the listener has proved itself.
            state = _bridge_state(base, loaded.settings.local_key, client)
            if state == "absent":
                return failed("the local bridge is not running on %s; start it with: python -m cgw local" % base)
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
            with client.stream("POST", base + "/v1/responses", json=body, headers=headers) as response:
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
    if b"response.completed" not in received:
        return failed("the stream ended without response.completed")
    print("model request: %d bytes, first byte after %.2fs, response.completed after %.2fs"
          % (len(received), first_byte, time.monotonic() - started))
    print("PASS")
    return 0


def main(argv=None, env=None, serve=None, run=None):
    env = os.environ if env is None else env
    serve = serve or uvicorn.run
    run = run or subprocess.run

    parser = argparse.ArgumentParser(prog="cgw", description="Encrypted Codex gateway")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("remote", help="run the remote bridge (inside the gateway container)").set_defaults(
        handler=_remote)

    local = commands.add_parser("local", help="run the local bridge on loopback")
    local.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    local.set_defaults(handler=_local)

    bootstrap = commands.add_parser("bootstrap", help="generate keys; store them locally and on Railway")
    bootstrap.add_argument("--remote-url", required=True)
    bootstrap.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    bootstrap.add_argument("--railway-service", required=True)
    bootstrap.add_argument("--set-cliproxy-key", action="store_true",
                           help="also replace the internal CLIProxyAPI key")
    bootstrap.add_argument("--proxy")
    bootstrap.add_argument("--ca-bundle")
    bootstrap.set_defaults(handler=_bootstrap)

    smoke = commands.add_parser("smoke", help="send one small request through the whole path")
    smoke.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    smoke.add_argument("--model", default="gpt-6-astra")
    smoke.set_defaults(handler=_smoke)

    profile = commands.add_parser("install-profile", help="write the Codex profile for the gateway")
    profile.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    profile.add_argument("--model", default="gpt-6-astra")
    profile.set_defaults(handler=_install_profile)

    verify = commands.add_parser("verify-bridge", help="check that the listener on the bridge's port is genuine")
    verify.add_argument("--config", default=str(DEFAULT_LOCAL_CONFIG))
    verify.set_defaults(handler=_verify_bridge)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    # The bridges log their own one-line summaries; the HTTP client's per-request lines stay out.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return args.handler(args, env, serve, run)
