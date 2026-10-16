"""Version negotiation never substitutes for the local identity challenge."""
import json

import httpx
import pytest

from cgw import cli, local_bridge
from test_verify_bridge import LOCAL_KEY, write_config


@pytest.mark.parametrize("version,want", [(None, "outdated"), (2, "outdated"), (3, "verified"),
                                          ("3", "outdated"), (True, "outdated"), ({}, "outdated")])
def test_identity_proof_is_verified_before_protocol(version, want):
    def handler(request):
        assert "authorization" not in request.headers and LOCAL_KEY not in str(request.url)
        nonce = bytes.fromhex(request.url.params["nonce"])
        payload = {"proof": local_bridge.identity_proof(LOCAL_KEY, nonce)}
        if version is not None:
            payload["protocol"] = version
        return httpx.Response(200, json=payload)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert cli._bridge_state("http://127.0.0.1:8318", LOCAL_KEY, client) == want


@pytest.mark.parametrize("payload", [{"proof": "0" * 64, "protocol": 3}, {"proof": "☃" * 64, "protocol": 3},
                                     [], {}, None])
def test_claimed_version_with_bad_identity_is_an_impostor(payload):
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        assert cli._bridge_state("http://127.0.0.1:8318", LOCAL_KEY, client) == "impostor"


def test_failed_identity_http_status_is_not_verified():
    def handler(request):
        nonce = bytes.fromhex(request.url.params["nonce"])
        return httpx.Response(500, json={"proof": local_bridge.identity_proof(LOCAL_KEY, nonce), "protocol": 3})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert cli._bridge_state("http://127.0.0.1:8318", LOCAL_KEY, client) == "impostor"


@pytest.mark.parametrize("command", ["smoke", "models", "verify-bridge"])
def test_cli_sends_only_a_challenge_to_an_outdated_bridge(tmp_path, monkeypatch, command):
    requests = []
    def handler(request):
        requests.append(request)
        nonce = bytes.fromhex(request.url.params["nonce"])
        return httpx.Response(200, json={"proof": local_bridge.identity_proof(LOCAL_KEY, nonce)})
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    assert cli.main([command, "--config", str(write_config(tmp_path, 8318))], env={}) == (4 if command == "verify-bridge" else 1)
    assert len(requests) == 1
    assert requests[0].url.path == "/cgw/identity"
    assert "authorization" not in requests[0].headers
