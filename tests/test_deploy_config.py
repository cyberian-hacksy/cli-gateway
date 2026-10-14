"""The CLIProxyAPI configuration shipped in the image: the settings the gateway relies on."""
import re
from pathlib import Path

from cgw import protocol

CONFIG = (Path(__file__).resolve().parent.parent / "deploy" / "cliproxy.yaml").read_text()


def setting(name):
    match = re.search(r"^\s*%s:\s*(\S+)" % re.escape(name), CONFIG, re.MULTILINE)
    assert match, name
    return match.group(1).strip('"')


def test_cliproxyapi_listens_on_container_loopback_only():
    assert setting("host") == "127.0.0.1"


def test_the_management_api_is_disabled():
    assert setting("secret-key") == "" and setting("allow-remote") == "false"


def test_retries_are_off():
    assert setting("request-retry") == "0"


def test_decompressed_request_bodies_are_bounded_above_the_gateways_own_limit():
    limit = int(setting("max-request-body-bytes"))
    assert protocol.MAX_BODY_BYTES <= limit <= 64 * 1024 * 1024
