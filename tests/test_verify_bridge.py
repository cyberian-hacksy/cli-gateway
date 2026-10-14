"""The launcher must not hand the local key or a prompt to whatever happens to hold the port.

The local bridge starts on demand, so its port is normally free and any local process,
including another user's, can bind it first. These tests put such an impostor on the
port and check that it is recognised and is sent nothing of value.
"""
import json
import os

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from cgw import cli, local_bridge
from harness import ServerThread

PSK = bytes(range(32))
KID = "poc-1"
LOCAL_KEY = "local-bearer-key-0123456789abcdef"


class Impostor:
    """Holds the port and answers everything plausibly, recording all it receives."""

    def __init__(self):
        self.received = []
        self.app = Starlette(routes=[Route("/{path:path}", self._handle, methods=["GET", "POST"])])

    async def _handle(self, request):
        body = await request.body()
        self.received.append(json.dumps(dict(request.headers)) + str(request.url) + body.decode("utf-8", "replace"))
        return JSONResponse({"proof": "00" * 32, "object": "list", "data": [{"id": "gpt-6-astra"}]})

    @property
    def paths(self):
        return [entry.split("http://", 1)[1].split("/", 1)[1].split("?")[0] for entry in self.received]


def write_config(tmp_path, port):
    import base64
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "remote_url": "https://gateway.example.com", "kid": KID, "local_key": LOCAL_KEY, "port": port,
        "psk": base64.urlsafe_b64encode(PSK).rstrip(b"=").decode()}))
    os.chmod(path, 0o600)
    return path


def port_of(server):
    return int(server.url.rsplit(":", 1)[1])


def real_bridge():
    return ServerThread(local_bridge.create_app(local_bridge.Settings(
        remote_url="https://gateway.example.com", kid=KID, psk=PSK, local_key=LOCAL_KEY)))


def run(command, config_path):
    return cli.main([command, "--config", str(config_path)], env={})


def test_verify_bridge_accepts_the_real_bridge(tmp_path):
    with real_bridge() as bridge:
        assert run("verify-bridge", write_config(tmp_path, port_of(bridge))) == 0


def test_verify_bridge_reports_a_free_port_distinctly(tmp_path, capsys):
    assert run("verify-bridge", write_config(tmp_path, 9)) == 3
    assert "not running" in capsys.readouterr().out


def test_verify_bridge_rejects_an_impostor_on_the_port(tmp_path, capsys):
    impostor = Impostor()
    with ServerThread(impostor.app) as server:
        assert run("verify-bridge", write_config(tmp_path, port_of(server))) == 1
    assert "not this gateway" in capsys.readouterr().err


def test_verify_bridge_rejects_a_bridge_that_holds_a_different_key(tmp_path):
    other = ServerThread(local_bridge.create_app(local_bridge.Settings(
        remote_url="https://gateway.example.com", kid=KID, psk=PSK, local_key="another-local-key-0123456789abcdefgh")))
    with other as bridge:
        assert run("verify-bridge", write_config(tmp_path, port_of(bridge))) == 1


def test_an_impostor_is_never_sent_the_local_key_by_verify_bridge(tmp_path):
    impostor = Impostor()
    with ServerThread(impostor.app) as server:
        run("verify-bridge", write_config(tmp_path, port_of(server)))
    assert impostor.received, "the impostor should at least have been probed"
    assert all(LOCAL_KEY not in entry and "authorization" not in entry.lower() for entry in impostor.received)


def test_smoke_refuses_an_impostor_and_sends_it_neither_key_nor_prompt(tmp_path, capsys):
    impostor = Impostor()
    with ServerThread(impostor.app) as server:
        assert run("smoke", write_config(tmp_path, port_of(server))) == 1
    assert "FAIL" in capsys.readouterr().out
    assert impostor.paths == ["cgw/identity"]
    assert all(LOCAL_KEY not in entry and "authorization" not in entry.lower() for entry in impostor.received)


def test_verify_bridge_never_prints_the_local_key(tmp_path, capsys):
    impostor = Impostor()
    with ServerThread(impostor.app) as server:
        run("verify-bridge", write_config(tmp_path, port_of(server)))
    with real_bridge() as bridge:
        run("verify-bridge", write_config(tmp_path, port_of(bridge)))
    captured = capsys.readouterr()
    assert LOCAL_KEY not in captured.out + captured.err
