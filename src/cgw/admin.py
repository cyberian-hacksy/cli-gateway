"""Admin tools: signing the gateway in to subscriptions, from this machine.

An admin key is a second key, separate from the machine's everyday key. It lives in an
owner-only file, encrypted with a passphrase (Argon2id, then libsodium's secretbox), and is
decrypted only in memory while an admin command runs. The gateway accepts it for the
sign-in routes in policy.py and for nothing else, and presents CLIProxyAPI's management
key on its behalf: this machine never sees that key, nor any subscription token.

A sign-in: the gateway asks CLIProxyAPI for the provider's sign-in address, the browser
opens it, the provider redirects the browser to a loopback address on this machine, a
short-lived listener here catches that redirect and hands it back to the gateway, and
CLIProxyAPI turns it into tokens on the gateway. The code in the redirect is useless
without the verifier CLIProxyAPI keeps on the gateway (for providers that use PKCE).
"""
import asyncio
import base64
import contextlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import nacl.utils

from cgw import local_bridge, policy

KEY_FILE_VERSION = 1
MIN_PASSPHRASE_CHARS = 10
# Argon2id at libsodium's "moderate" level: about a second and 256 MiB per attempt.
OPSLIMIT = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
MEMLIMIT = nacl.pwhash.argon2id.MEMLIMIT_MODERATE

# Friendly names, and the words people use for each provider.
PROVIDERS = {
    "anthropic": "Claude", "codex": "Codex (OpenAI)", "antigravity": "Google, through Antigravity (Gemini models)",
    "xai": "xAI", "kimi": "Kimi", "kimi-ai": "Kimi.ai", "meta": "Meta", "devin": "Devin",
}
ALIASES = {"claude": "anthropic", "openai": "codex", "google": "antigravity", "gemini": "antigravity", "grok": "xai"}
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


class AdminError(Exception):
    """An admin operation failed. The message is safe to show and never contains a secret."""


@dataclass(frozen=True)
class AdminKey:
    name: str
    remote_url: str
    kid: str
    psk: bytes


def provider_id(name):
    """The provider's identifier in CLIProxyAPI, from a name or an alias. Raises AdminError."""
    provider = ALIASES.get(name.lower(), name.lower())
    if provider not in policy.SIGN_IN_PROVIDERS:
        raise AdminError("unknown provider %r; choose one of: %s" % (name, ", ".join(
            sorted(set(policy.SIGN_IN_PROVIDERS) | set(ALIASES)))))
    return provider


# --- the admin key file ---------------------------------------------------------------

def _derive(passphrase, salt, opslimit, memlimit):
    return nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, passphrase.encode(), salt,
                                    opslimit=opslimit, memlimit=memlimit)


def write_admin_key(path, key, passphrase, opslimit=None, memlimit=None):
    """Encrypt the admin key under the passphrase and write it, owner-only. Refuses to replace a file."""
    if len(passphrase) < MIN_PASSPHRASE_CHARS:
        raise AdminError("the passphrase must be at least %d characters" % MIN_PASSPHRASE_CHARS)
    opslimit, memlimit = opslimit or OPSLIMIT, memlimit or MEMLIMIT
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    payload = json.dumps({"remote_url": key.remote_url, "kid": key.kid,
                          "psk": base64.urlsafe_b64encode(key.psk).decode()}).encode()
    box = nacl.secret.SecretBox(_derive(passphrase, salt, opslimit, memlimit)).encrypt(payload)
    content = {"v": KEY_FILE_VERSION, "name": key.name,
               "kdf": {"alg": "argon2id", "opslimit": opslimit, "memlimit": memlimit,
                       "salt": base64.urlsafe_b64encode(salt).decode()},
               "box": base64.urlsafe_b64encode(bytes(box)).decode()}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise AdminError("%s already exists; move it away first" % path) from None
    with os.fdopen(descriptor, "w") as handle:
        json.dump(content, handle, indent=2)
        handle.write("\n")
    return path


def load_admin_key(path, passphrase):
    """Decrypt the admin key. Raises AdminError for a missing or unsafe file or a wrong passphrase."""
    path = Path(path)
    if not path.is_file():
        raise AdminError("no admin key at %s; an admin key is created with python -m cgw grant-admin" % path)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AdminError("%s can be read by others; run: chmod 600 %s" % (path, path))
    try:
        content = json.loads(path.read_text())
        kdf = content["kdf"]
        if content.get("v") != KEY_FILE_VERSION or kdf.get("alg") != "argon2id":
            raise AdminError("%s is not an admin key file this version understands" % path)
        salt = base64.urlsafe_b64decode(kdf["salt"])
        box = base64.urlsafe_b64decode(content["box"])
        opslimit, memlimit = int(kdf["opslimit"]), int(kdf["memlimit"])
    except (ValueError, KeyError, TypeError, AttributeError):
        raise AdminError("%s is not a valid admin key file" % path) from None
    try:
        payload = nacl.secret.SecretBox(_derive(passphrase, salt, opslimit, memlimit)).decrypt(box)
    except nacl.exceptions.CryptoError:
        raise AdminError("wrong passphrase, or the admin key file was altered") from None
    fields = json.loads(payload)
    return AdminKey(name=str(content.get("name", "")), remote_url=fields["remote_url"], kid=fields["kid"],
                    psk=base64.urlsafe_b64decode(fields["psk"]))


# --- talking to the gateway with the admin key ----------------------------------------

class AdminClient:
    """Sign-in requests through the gateway, verified exactly like a tool's requests."""

    def __init__(self, key, proxy=None, ca_bundle=None):
        self._settings = local_bridge.Settings(remote_url=key.remote_url, kid=key.kid, psk=key.psk,
                                               local_key=secrets.token_urlsafe(32), proxy=proxy, ca_bundle=ca_bundle)
        self._exchanger = local_bridge.Exchanger(self._settings)
        self._client = None

    async def __aenter__(self):
        self._client = local_bridge.build_client(self._settings)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_info):
        await self._client.__aexit__(*exc_info)

    async def request(self, method, path, query="", body=None):
        """(status, parsed JSON body). Raises AdminError when the gateway itself refused."""
        content = json.dumps(body).encode() if body is not None else b""
        headers = {"content-type": "application/json"} if body is not None else {}
        response = await self._exchanger.exchange(self._client, method, path, query, headers, content)
        try:
            parsed = json.loads(response.body)
        except (ValueError, AttributeError):
            parsed = None
        if response.status_code == 502 and isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
            code = parsed["error"].get("code", "bad_gateway_response")
            hint = " (is this machine an admin? see: python -m cgw grant-admin)" if code == "rejected" else ""
            raise AdminError("the gateway refused: %s%s" % (code, hint))
        return response.status_code, parsed

    async def start_sign_in(self, provider):
        status, answer = await self.request("GET", "%s%s-auth-url" % (policy.MANAGEMENT_PREFIX, provider))
        if status != 200 or not isinstance(answer, dict) or not answer.get("url") or not answer.get("state"):
            raise AdminError("the gateway could not start a %s sign-in (HTTP %d)" % (PROVIDERS[provider], status))
        return answer["url"], answer["state"]

    async def hand_back(self, provider, redirect_url):
        status, answer = await self.request("POST", policy.MANAGEMENT_PREFIX + "oauth-callback",
                                            body={"provider": provider, "redirect_url": redirect_url})
        if status != 200:
            message = answer.get("error") if isinstance(answer, dict) else None
            raise AdminError("the gateway did not accept the sign-in: %s" % (message or "HTTP %d" % status))

    async def status(self, state):
        _, answer = await self.request("GET", policy.MANAGEMENT_PREFIX + "get-auth-status",
                                       query=urlencode({"state": state}))
        return answer if isinstance(answer, dict) else {"status": "error", "error": "unreadable answer"}

    async def sign_ins(self):
        status, answer = await self.request("GET", policy.SIGN_INS_PATH)
        if status != 200 or not isinstance(answer, dict):
            raise AdminError("the gateway could not list its sign-ins (HTTP %d)" % status)
        return answer.get("files", [])

    async def sign_out(self, name):
        status, answer = await self.request("DELETE", policy.SIGN_INS_PATH, query=urlencode({"name": name}))
        if status != 200:
            raise AdminError("the gateway could not remove %s (HTTP %d)" % (name, status))


# --- catching the provider's redirect on this machine ---------------------------------

class CallbackCatcher:
    """Listens on the loopback port and path the provider redirects the browser to.

    Only the expected path counts. The redirect is answered with a short page that says the
    browser tab can be closed, and its full address is handed to whoever waits on `caught`.
    """

    PAGE = (b"<!doctype html><meta charset=utf-8><title>Signed in</title>"
            b"<p style='font:16px system-ui;margin:3em'>Sign-in received. You can close this tab.</p>")

    def __init__(self, redirect_uri):
        parts = urlsplit(redirect_uri)
        if parts.scheme != "http" or parts.hostname not in _LOOPBACK or not parts.port:
            raise AdminError("the provider redirects to %s, which is not a loopback address" % redirect_uri)
        self.redirect_uri, self.port, self.path = redirect_uri, parts.port, parts.path or "/"
        self.caught = asyncio.get_running_loop().create_future()
        self._servers = []

    async def start(self):
        """Raises OSError if the port is taken; the caller then falls back to pasting the address."""
        self._servers.append(await asyncio.start_server(self._handle, "127.0.0.1", self.port))
        with contextlib.suppress(OSError):  # browsers may try ::1 first for "localhost"
            self._servers.append(await asyncio.start_server(self._handle, "::1", self.port))

    async def close(self):
        for server in self._servers:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            method, target, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
            if method == "GET" and urlsplit(target).path == self.path and len(target) < 8192:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n"
                             b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(self.PAGE) + self.PAGE)
                if not self.caught.done():
                    base = urlsplit(self.redirect_uri)
                    self.caught.set_result("%s://%s%s" % (base.scheme, base.netloc, target))
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, OSError):
            pass
        finally:
            writer.close()


def redirect_uri_of(url):
    """The redirect_uri a provider's sign-in address names, or None (device-code sign-ins have none)."""
    values = parse_qs(urlsplit(url).query).get("redirect_uri")
    return values[0] if values else None


async def run_sign_in(client, provider, open_browser, pasted=None, paste_alongside=False, report=print,
                      timeout=300.0, poll_seconds=1.0):
    """One whole sign-in. Returns the provider's friendly name on success; raises AdminError otherwise.

    `pasted()` returns an awaitable for the address the browser ended up on, typed or pasted
    by the person signing in. It is used when the redirect cannot be caught here (its port is
    taken), and also alongside the catcher when `paste_alongside` is set.
    """
    url, state = await client.start_sign_in(provider)
    redirect_uri, catcher = redirect_uri_of(url), None
    if redirect_uri:
        catcher = CallbackCatcher(redirect_uri)
        try:
            await catcher.start()
        except OSError:
            report("port %d on this machine is taken, so the redirect cannot be caught automatically" % catcher.port)
            await catcher.close()
            catcher = None
    try:
        open_browser(url)
        if redirect_uri:
            waiting = [catcher.caught] if catcher is not None else []
            if pasted is not None and (catcher is None or paste_alongside):
                waiting.append(asyncio.ensure_future(pasted()))
            if not waiting:
                raise AdminError("the redirect cannot be caught on this machine and there is no way to paste it")
            done, pending = await asyncio.wait(waiting, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            if not done:
                raise AdminError("no sign-in arrived within %d seconds" % timeout)
            await client.hand_back(provider, str(done.pop().result()).strip())
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            answer = await client.status(state)
            if answer.get("status") == "ok":
                return PROVIDERS[provider]
            if answer.get("status") == "error":
                raise AdminError("the sign-in failed: %s" % answer.get("error", "unknown error"))
            await asyncio.sleep(poll_seconds)
        raise AdminError("the sign-in did not finish within %d seconds" % timeout)
    finally:
        if catcher is not None:
            await catcher.close()
