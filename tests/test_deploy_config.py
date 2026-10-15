"""The CLIProxyAPI configuration shipped in the image: the settings the gateway relies on."""
import importlib.util
import re
from pathlib import Path

import pytest

from cgw import protocol

ROOT = Path(__file__).resolve().parent.parent
CONFIG = (ROOT / "deploy" / "cliproxy.yaml").read_text()


def setting(name):
    match = re.search(r"^\s*%s:\s*(\S+)" % re.escape(name), CONFIG, re.MULTILINE)
    assert match, name
    return match.group(1).strip('"')


def test_cliproxyapi_listens_on_container_loopback_only():
    assert setting("host") == "127.0.0.1"


def test_the_management_api_is_loopback_only_and_has_no_control_panel():
    assert setting("allow-remote") == "false" and setting("disable-control-panel") == "true"


def entrypoint():
    spec = importlib.util.spec_from_file_location("entrypoint", ROOT / "deploy" / "entrypoint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KEY, MANAGEMENT_KEY = "k" * 40, "m" * 40


def test_without_a_management_key_the_management_api_stays_off():
    text = entrypoint().rendered(CONFIG, {"CGW_CLIPROXY_KEY": KEY})
    assert re.search(r'secret-key: ""', text) and KEY in text


def test_the_management_key_is_rendered_only_into_the_secret_key():
    text = entrypoint().rendered(CONFIG, {"CGW_CLIPROXY_KEY": KEY, "CGW_CLIPROXY_MANAGEMENT_KEY": MANAGEMENT_KEY})
    assert text.count(MANAGEMENT_KEY) == 1 and 'secret-key: "%s"' % MANAGEMENT_KEY in text
    assert "__CGW_" not in text


@pytest.mark.parametrize("env", [{"CGW_CLIPROXY_KEY": "short"},
                                 {"CGW_CLIPROXY_KEY": KEY, "CGW_CLIPROXY_MANAGEMENT_KEY": "bad key"}])
def test_a_malformed_key_stops_the_container(env):
    with pytest.raises(SystemExit):
        entrypoint().rendered(CONFIG, env)


def test_retries_are_off():
    assert setting("request-retry") == "0"


def test_decompressed_request_bodies_are_bounded_above_the_gateways_own_limit():
    limit = int(setting("max-request-body-bytes"))
    assert protocol.MAX_BODY_BYTES <= limit <= 64 * 1024 * 1024
