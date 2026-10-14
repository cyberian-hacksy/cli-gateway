"""The smoke command: one small request through the whole path, with a clear verdict."""
import json
import os

import pytest

from cgw import cli, local_bridge, remote_bridge
from harness import ServerThread
from synthetic_upstream import INTERNAL_KEY, Upstream

PSK = bytes(range(32))
KID = "poc-1"
LOCAL_KEY = "local-bearer-key-0123456789abcdef"


class running_gateway:
    """Upstream, remote bridge and local bridge on loopback, plus a config file pointing at them."""

    def __init__(self, tmp_path, upstream=None, upstream_url=None):
        self.tmp_path, self.upstream, self.upstream_url, self.servers = tmp_path, upstream or Upstream(), upstream_url, []

    def _serve(self, app):
        server = ServerThread(app).__enter__()
        self.servers.append(server)
        return server.url

    def __enter__(self):
        upstream_url = self._serve(self.upstream.app)
        remote_url = self._serve(remote_bridge.create_app(remote_bridge.Settings(
            keys={KID: PSK}, upstream_url=self.upstream_url or upstream_url, upstream_key=INTERNAL_KEY)))
        local_url = self._serve(local_bridge.create_app(local_bridge.Settings(
            remote_url=remote_url, kid=KID, psk=PSK, local_key=LOCAL_KEY)))
        return write_config(self.tmp_path, remote_url, int(local_url.rsplit(":", 1)[1]))

    def __exit__(self, *exc_info):
        for server in reversed(self.servers):
            server.__exit__(*exc_info)


def write_config(tmp_path, remote_url, port):
    import base64
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "remote_url": remote_url, "kid": KID, "local_key": LOCAL_KEY, "port": port,
        "psk": base64.urlsafe_b64encode(PSK).rstrip(b"=").decode()}))
    os.chmod(path, 0o600)
    return path


def smoke(config_path):
    return cli.main(["smoke", "--config", str(config_path)], env={})


def test_smoke_passes_through_a_healthy_gateway(tmp_path, capsys):
    with running_gateway(tmp_path) as config_path:
        assert smoke(config_path) == 0
    output = capsys.readouterr().out
    assert "PASS" in output and "models" in output and "response.completed" in output


def test_smoke_sends_exactly_one_model_request(tmp_path):
    upstream = Upstream()
    with running_gateway(tmp_path, upstream=upstream) as config_path:
        smoke(config_path)
    assert len(upstream.response_calls) == 1
    assert json.loads(upstream.response_calls[0]["body"])["stream"] is True


def test_smoke_fails_with_a_hint_when_the_local_bridge_is_not_running(tmp_path, capsys):
    config_path = write_config(tmp_path, "https://gateway.example.com", 9)
    assert smoke(config_path) == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.out and "local bridge is not running" in captured.out


def test_smoke_fails_and_names_the_gateway_error_when_upstream_is_unreachable(tmp_path, capsys):
    with running_gateway(tmp_path, upstream_url="http://127.0.0.1:9") as config_path:
        assert smoke(config_path) == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.out and "upstream_unreachable" in captured.out


def test_smoke_fails_when_the_stream_ends_without_a_completion(tmp_path, capsys):
    with running_gateway(tmp_path, upstream=Upstream(default_scenario="no_terminal")) as config_path:
        assert smoke(config_path) == 1
    assert "FAIL" in capsys.readouterr().out


def test_smoke_fails_when_no_models_are_served(tmp_path, capsys):
    with running_gateway(tmp_path, upstream=Upstream(internal_key="another-internal-key-0000000000000000")) as config_path:
        assert smoke(config_path) == 1
    assert "FAIL" in capsys.readouterr().out


def test_smoke_never_prints_the_local_key(tmp_path, capsys):
    with running_gateway(tmp_path) as config_path:
        smoke(config_path)
    captured = capsys.readouterr()
    assert LOCAL_KEY not in captured.out + captured.err


def test_smoke_fails_cleanly_without_a_config(tmp_path, capsys):
    assert smoke(tmp_path / "absent.json") == 1
    assert "not found" in capsys.readouterr().err


# --- every API format -----------------------------------------------------------------

@pytest.mark.parametrize("fmt,model,path,marker", [
    ("chat", "gpt-6-astra", "/v1/chat/completions", "[DONE]"),
    ("messages", "claude-test", "/v1/messages", "message_stop"),
    ("gemini", "gemini-test", "/v1beta/models/gemini-test:streamGenerateContent", "finishReason"),
])
def test_smoke_passes_in_each_api_format(tmp_path, capsys, fmt, model, path, marker):
    upstream = Upstream()
    with running_gateway(tmp_path, upstream=upstream) as config_path:
        assert cli.main(["smoke", "--config", str(config_path), "--format", fmt, "--model", model], env={}) == 0
    call = upstream.calls[-1]
    assert call["path"] == path
    assert json.loads(call["body"]).get("stream", True) is True
    if fmt == "gemini":
        assert call["query"] == "alt=sse"
    if fmt == "messages":
        assert call["headers"]["anthropic-version"] == "2023-06-01"
    output = capsys.readouterr().out
    assert "PASS" in output and marker in output


@pytest.mark.parametrize("fmt", ["messages", "gemini"])
def test_smoke_needs_a_model_for_formats_with_no_default(tmp_path, capsys, fmt):
    with running_gateway(tmp_path) as config_path:
        assert cli.main(["smoke", "--config", str(config_path), "--format", fmt], env={}) == 1
    output = capsys.readouterr()
    assert "--model" in output.out + output.err


def test_smoke_refuses_a_model_name_that_is_not_a_plain_name(tmp_path, capsys):
    upstream = Upstream()
    with running_gateway(tmp_path, upstream=upstream) as config_path:
        code = cli.main(["smoke", "--config", str(config_path), "--format", "gemini", "--model", "../../v0/x"], env={})
    assert code == 1 and upstream.calls == []


# --- models ---------------------------------------------------------------------------

def test_models_lists_what_the_gateway_serves(tmp_path, capsys):
    with running_gateway(tmp_path) as config_path:
        assert cli.main(["models", "--config", str(config_path)], env={}) == 0
    assert capsys.readouterr().out.split() == ["gpt-6-astra"]


def test_models_fails_with_a_hint_when_the_local_bridge_is_not_running(tmp_path, capsys):
    config_path = write_config(tmp_path, "https://gateway.example.com", 9)
    assert cli.main(["models", "--config", str(config_path)], env={}) == 1
    assert "not running" in capsys.readouterr().err
