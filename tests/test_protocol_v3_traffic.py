"""Observable v3 traffic, with explicit limits on size indistinguishability."""
import asyncio
from contextlib import ExitStack, contextmanager
import json

import httpx
import pytest

from cgw import local_bridge, protocol, remote_bridge
from harness import ServerThread
from synthetic_upstream import FORMAT_EVENTS, FORMAT_PATHS, INTERNAL_KEY, MANAGEMENT_KEY, Upstream, expected_stream
from tamper_proxy import TamperProxy
from test_relay import collect
import wire_reference as ref

CLIENT = "private-machine-name-never-on-the-wire"
ADMIN = "admin_private-administrator-name-never-on-the-wire"
PSK, ADMIN_PSK = bytes(range(32)), bytes(range(1, 33))
LOCAL_KEY = "traffic-test-local-key-0123456789abcdef"
PROMPT = "PROMPT-CANARY-v3-contents-must-stay-encrypted"


@contextmanager
def traffic_stack():
    with ExitStack() as stack:
        upstream = Upstream()
        upstream_url = stack.enter_context(ServerThread(upstream.app)).url
        remote = stack.enter_context(ServerThread(remote_bridge.create_app(remote_bridge.Settings(
            keys={CLIENT: PSK, ADMIN: ADMIN_PSK}, admins=frozenset({ADMIN}), management_key=MANAGEMENT_KEY,
            upstream_url=upstream_url, upstream_key=INTERNAL_KEY))))
        proxy = TamperProxy(remote.url)
        proxy_url = stack.enter_context(ServerThread(proxy.app)).url
        local = stack.enter_context(ServerThread(local_bridge.create_app(local_bridge.Settings(
            remote_url=proxy_url, kid=CLIENT, psk=PSK, local_key=LOCAL_KEY))))
        yield local.url, proxy_url, proxy


def assert_outer(proxy):
    assert len(proxy.requests) == 2
    for (headers, body), fields in zip(proxy.requests, (
            {"v", "hid", "ts", "epk", "mac"}, {"v", "hid", "rid", "ts", "header", "data"})):
        assert set(json.loads(body)) == fields
        assert json.loads(body)["v"] == 3
        assert len(headers[protocol.ADMISSION_HEADER].split(".")) == 4
        assert not {"authorization", "cookie"} & headers.keys()
    for secret in (CLIENT, ADMIN, PROMPT, LOCAL_KEY, ref.b64(PSK), ref.b64(ADMIN_PSK)):
        assert secret.encode() not in proxy.captured
    assert [r["path"] for r in proxy.responses] == ["/poc/v3/handshake", "/poc/v3/exchange"]
    response = proxy.responses[-1]
    assert len(response["lines"]) >= 4
    assert response["times"] == sorted(response["times"])
    for line in response["lines"][1:]:
        length = len(ref.unb64(json.loads(line)["data"]))
        assert (length - 17) % 512 == 0


@pytest.mark.parametrize("fmt", ["responses", "chat", "messages", "gemini"])
def test_every_format_round_trips_without_wire_names(fmt):
    with traffic_stack() as (local, _, proxy):
        path = "/v1/responses" if fmt == "responses" else FORMAT_PATHS[fmt]
        response = httpx.post(local + path, json={"scenario": "stream", "events": 3, "input": PROMPT},
                              headers={"Authorization": "Bearer " + LOCAL_KEY}, timeout=10)
        assert response.status_code == 200
        expected = expected_stream(3) if fmt == "responses" else b"".join(FORMAT_EVENTS[fmt])
        assert response.content == expected
        assert_outer(proxy)


def test_admin_call_uses_the_same_anonymous_outer_format():
    with traffic_stack() as (_, proxy_url, proxy):
        async def request():
            settings = local_bridge.Settings(proxy_url, ADMIN, ADMIN_PSK, LOCAL_KEY)
            async with local_bridge.build_client(settings) as client:
                response = await local_bridge.Exchanger(settings).exchange(
                    client, "GET", "/v0/management/auth-files", "", {}, b"")
                assert response.status_code == 200
                assert "files" in json.loads(response.body)
        asyncio.run(request())
        assert_outer(proxy)


def trace(text):
    session = protocol.Session(CLIENT, b"h" * 32, PSK + b"x" * 32)
    sealer = protocol.ResponseSealer(session, b"r" * 32, 1800000000)
    batches, _ = collect([(.001, ("meta", 200, {})), (.02, ("data", text)), (.03, ("end",))])
    lines = [sealer.header_line()]
    for _, batch in batches:
        for item in batch:
            lines.append(getattr(sealer, item[0])(*item[1:]))
    opener = protocol.ResponseOpener(session, b"r" * 32, 1800000000)
    opener.open_header(lines[0])
    records = [opener.open_record(line) for line in lines[1:]]
    assert opener.finished
    assert b"".join(r.payload for r in records if r.type == protocol.DATA) == text
    return [len(line) for line in lines]


def test_different_token_lengths_in_the_same_buckets_have_identical_line_sizes():
    assert trace(b"short") == trace(b"much longer output" * 20)
    assert trace(b"x" * 510) != trace(b"x" * 511)


def test_handshake_lengths_are_independent_of_client_and_admin_names():
    lengths = [len(protocol.ClientHandshake(psk, kid, 1800000000).message())
               for kid, psk in (("a", PSK), (CLIENT, PSK), (ADMIN, ADMIN_PSK))]
    assert len(set(lengths)) == 1
