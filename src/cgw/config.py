"""Configuration for both bridges.

The remote bridge reads environment variables (deployment secrets), one per client:
CGW_CLIENT_<NAME> holds that client's pre-shared key. The local bridge reads one
owner-only JSON file. Errors name the setting at fault and never its value.
"""
import base64
import binascii
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from cgw import local_bridge, remote_bridge

DEFAULT_UPSTREAM_URL = "http://127.0.0.1:8317"
DEFAULT_REMOTE_PORT = 8080
DEFAULT_LOCAL_PORT = 8318
LOCAL_HOST = "127.0.0.1"

_KEY = re.compile(r"[A-Za-z0-9_-]{32,128}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_LOCAL_REQUIRED = ("remote_url", "kid", "psk", "local_key")

# A client is named in lowercase words joined by hyphens, and its gateway variable spells
# the same name in uppercase words joined by underscores, so each maps to exactly one other.
CLIENT_PREFIX = "CGW_CLIENT_"
MAX_CLIENT_NAME = 40
_CLIENT_NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_CLIENT_SUFFIX = re.compile(r"[A-Z0-9]+(_[A-Z0-9]+)*")
# Earlier versions held a single key in these. They are never read now, so they admit no one.
RETIRED_VARIABLES = ("CGW_KID", "CGW_PSK")
_LOCAL_OPTIONAL = ("proxy", "ca_bundle", "port")


class ConfigError(Exception):
    """A setting is missing or invalid. The message names the setting, never its value."""


@dataclass(frozen=True)
class RemoteConfig:
    settings: remote_bridge.Settings
    port: int


@dataclass(frozen=True)
class LocalConfig:
    settings: local_bridge.Settings
    host: str
    port: int


@dataclass(frozen=True)
class Secrets:
    kid: str
    psk: str            # base64url text of 32 random bytes
    local_key: str      # bearer key Codex presents to the local bridge
    cliproxy_key: str   # key the remote bridge presents to CLIProxyAPI


def decode_psk(text):
    """32 bytes from canonical unpadded base64url. Raises ValueError without echoing the input."""
    if not isinstance(text, str) or not _BASE64URL.fullmatch(text):
        raise ValueError("not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("not base64url") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise ValueError("not canonical base64url")
    if len(raw) != 32 or raw == bytes(32):
        raise ValueError("not a 32-byte key")
    return raw


def client_variable(name):
    """The gateway variable that holds the key of the client called `name`."""
    if not isinstance(name, str) or len(name) > MAX_CLIENT_NAME or not _CLIENT_NAME.fullmatch(name):
        raise ConfigError("a client name is 1-%d characters: lowercase letters and digits, "
                          "in words joined by single hyphens, such as work-laptop" % MAX_CLIENT_NAME)
    return CLIENT_PREFIX + name.upper().replace("-", "_")


def client_name(variable):
    """The client a CGW_CLIENT_ variable belongs to. Raises ConfigError if the name is malformed."""
    suffix = variable[len(CLIENT_PREFIX):] if variable.startswith(CLIENT_PREFIX) else ""
    if len(suffix) > MAX_CLIENT_NAME or not _CLIENT_SUFFIX.fullmatch(suffix):
        raise ConfigError("%s is not a valid client variable: after %s use 1-%d uppercase letters and digits, "
                          "in words joined by single underscores" % (variable, CLIENT_PREFIX, MAX_CLIENT_NAME))
    return suffix.lower().replace("_", "-")


def _port(value, name):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ConfigError("%s must be a port number between 1 and 65535" % name)
    return value


def load_remote(env):
    def required(name):
        value = env.get(name, "")
        if not value:
            raise ConfigError("%s is not set" % name)
        return value

    keys, holders = {}, {}
    for variable in sorted(name for name in env if name.startswith(CLIENT_PREFIX)):
        kid = client_name(variable)
        try:
            psk = decode_psk(env[variable])
        except ValueError:
            raise ConfigError("%s must be 32 random bytes as unpadded base64url" % variable) from None
        if psk in holders:
            # Removing one of them would not shut out whoever holds the key.
            raise ConfigError("%s and %s hold the same key; every client needs its own" % (holders[psk], variable))
        keys[kid], holders[psk] = psk, variable
    if not keys:
        raise ConfigError("no client is configured: set at least one %s<NAME> variable "
                          "(python -m cgw add-client does this)" % CLIENT_PREFIX)
    upstream_key = required("CGW_CLIPROXY_KEY")
    if not _KEY.fullmatch(upstream_key):
        raise ConfigError("CGW_CLIPROXY_KEY must be 32-128 characters of [A-Za-z0-9_-]")

    upstream_url = env.get("CGW_UPSTREAM_URL") or DEFAULT_UPSTREAM_URL
    parsed = urlsplit(upstream_url)
    if parsed.scheme != "http" or parsed.hostname not in _LOOPBACK_HOSTS:
        raise ConfigError("CGW_UPSTREAM_URL must be a plain http loopback address")
    port_text = env.get("PORT") or str(DEFAULT_REMOTE_PORT)
    if not port_text.isdigit():
        raise ConfigError("PORT must be a port number between 1 and 65535")

    return RemoteConfig(
        settings=remote_bridge.Settings(keys=keys, upstream_url=upstream_url, upstream_key=upstream_key),
        port=_port(int(port_text), "PORT"),
    )


def load_local(path):
    path = Path(path)
    if not path.is_file():
        raise ConfigError("config file not found: %s" % path)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigError("config file permissions are too open; run: chmod 600 %s" % path)
    try:
        content = json.loads(path.read_text())
    except ValueError:
        raise ConfigError("config file is not valid JSON") from None
    if type(content) is not dict:
        raise ConfigError("config file must contain a JSON object")
    unknown = sorted(set(content) - set(_LOCAL_REQUIRED) - set(_LOCAL_OPTIONAL))
    if unknown:
        raise ConfigError("unknown setting(s): %s" % ", ".join(unknown))
    for name in _LOCAL_REQUIRED:
        if not isinstance(content.get(name), str) or not content[name]:
            raise ConfigError("%s is missing or not a string" % name)
    for name in ("proxy", "ca_bundle"):
        if content.get(name) is not None and not isinstance(content[name], str):
            raise ConfigError("%s must be a string" % name)
    try:
        psk = decode_psk(content["psk"])
    except ValueError:
        raise ConfigError("psk must be 32 random bytes as unpadded base64url") from None
    try:
        settings = local_bridge.Settings(
            remote_url=content["remote_url"], kid=content["kid"], psk=psk, local_key=content["local_key"],
            proxy=content.get("proxy"), ca_bundle=content.get("ca_bundle"))
    except ValueError as error:
        raise ConfigError(str(error)) from None
    return LocalConfig(settings=settings, host=LOCAL_HOST, port=_port(content.get("port", DEFAULT_LOCAL_PORT), "port"))


def generate_secrets(kid=None):
    """A fresh key set for one client. Never derived from a password."""
    return Secrets(
        kid=kid or "poc-" + secrets.token_hex(4),
        psk=base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii"),
        local_key=secrets.token_urlsafe(32),
        cliproxy_key=secrets.token_urlsafe(32),
    )


def write_local(path, remote_url, generated, proxy=None, ca_bundle=None):
    """Write the local bridge's config file, owner-only. Refuses to replace an existing file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = {"remote_url": remote_url, "kid": generated.kid, "psk": generated.psk,
               "local_key": generated.local_key}
    if proxy:
        content["proxy"] = proxy
    if ca_bundle:
        content["ca_bundle"] = ca_bundle
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ConfigError("%s already exists; move it away before generating new secrets" % path) from None
    with os.fdopen(descriptor, "w") as handle:
        json.dump(content, handle, indent=2)
        handle.write("\n")
    return path
