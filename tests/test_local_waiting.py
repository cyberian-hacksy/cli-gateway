"""The local bridge waits for a place at the gateway instead of passing `busy` on."""
import asyncio
import json
import time

import httpx
import pytest

import wire_reference as ref
from cgw import local_bridge, protocol

PSK = bytes(range(32))
KID = "poc-1"
LOCAL_KEY = "synthetic-local-test-key-0123456789abcdef"


def reply(status, content_type, body):
    # Streamed, as the real gateway's answers are read.
    return httpx.Response(status, headers={"content-type": content_type}, stream=httpx.ByteStream(body))


class FakeGateway:
    """Answers handshakes for real and seals real responses. It can refuse as busy, refuse
    for good, or hold exchanges open while counting how many it holds at once."""

    def __init__(self, busy_handshakes=0, busy_exchanges=0, refuse=None, stream=False):
        self.busy = {"handshake": busy_handshakes, "exchange": busy_exchanges}
        self.refuse, self.stream = refuse, stream
        self.sessions, self.calls, self.ids = {}, [], []
        self.open = self.most_open = 0
        self.hold = None

    async def __call__(self, request):
        kind = request.url.path.rsplit("/", 1)[1]
        body = await request.aread()
        self.calls.append(kind)
        if self.refuse:
            return reply(400, "application/json", json.dumps({"error": self.refuse}).encode())
        if self.busy[kind] is True or self.busy[kind] > 0:
            if self.busy[kind] is not True:
                self.busy[kind] -= 1
            return reply(429, "application/json", b'{"error":"busy"}')
        if kind == "handshake":
            answered = protocol.answer_handshake(body, KID, PSK)
            self.sessions[answered.session.hid] = answered.session
            return reply(200, "application/json", answered.reply)
        fields = json.loads(body)
        hid, rid = ref.unb64(fields["hid"]), ref.unb64(fields["rid"])
        self.ids.append((hid, rid))
        self.open += 1
        self.most_open = max(self.most_open, self.open)
        try:
            if self.hold is not None:
                await self.hold.wait()
        finally:
            self.open -= 1
        sealer = protocol.ResponseSealer(self.sessions[hid], rid, fields["ts"])
        kind_of_body = "text/event-stream" if self.stream else "application/json"
        payload = b"data: pong\n\n" if self.stream else b'{"ok":true}'
        lines = [sealer.header_line(), sealer.meta(200, {"content-type": kind_of_body}),
                 sealer.data(payload), sealer.end()]
        return reply(200, "application/x-ndjson", b"".join(lines))


def exchanger(**overrides):
    settings = local_bridge.Settings("https://gateway.example.com", KID, PSK, LOCAL_KEY, **overrides)
    return local_bridge.Exchanger(settings)


def send(bridge, client):
    return bridge.exchange(client, "GET", "/v1/models", "", {}, b"")


async def run_stream(response):
    """Plays a streaming response the way the web server would, to its end."""
    sent = []

    async def receive():
        await asyncio.Event().wait()

    async def write(message):
        sent.append(message)

    await response({"type": "http"}, receive, write)
    return b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")


def run(gateway, work):
    async def main():
        async with httpx.AsyncClient(transport=httpx.MockTransport(gateway)) as client:
            return await work(client)
    return asyncio.run(main())


def test_a_busy_exchange_is_sent_again_with_a_fresh_handshake_and_request_id():
    gateway = FakeGateway(busy_exchanges=2)
    response = run(gateway, lambda client: send(exchanger(), client))
    assert (response.status_code, response.body) == (200, b'{"ok":true}')
    assert gateway.calls == ["handshake", "exchange"] * 3
    # The refused attempts used up their handshakes, so each attempt has its own.
    assert len(gateway.sessions) == 3 and len(gateway.ids) == 1


def test_a_busy_handshake_is_sent_again():
    gateway = FakeGateway(busy_handshakes=2)
    response = run(gateway, lambda client: send(exchanger(), client))
    assert response.status_code == 200
    assert gateway.calls == ["handshake", "handshake", "handshake", "exchange"]


@pytest.mark.parametrize("code", ["rejected", "stale_timestamp", "replayed"])
def test_other_refusals_are_not_sent_again(code):
    gateway = FakeGateway(refuse=code)
    response = run(gateway, lambda client: send(exchanger(), client))
    assert response.status_code == 502 and json.loads(response.body)["error"]["code"] == code
    assert gateway.calls == ["handshake"]


def test_a_gateway_that_stays_busy_is_reported_busy_once_the_wait_is_over():
    gateway = FakeGateway(busy_exchanges=True)
    started = time.monotonic()
    response = run(gateway, lambda client: send(exchanger(place_wait_seconds=.5), client))
    assert response.status_code == 502 and json.loads(response.body)["error"]["code"] == "busy"
    assert .3 < time.monotonic() - started < 1.5
    assert 2 <= gateway.calls.count("exchange") <= 8


def test_no_more_requests_go_to_the_gateway_at_once_than_it_has_places():
    gateway = FakeGateway()

    async def work(client):
        gateway.hold = asyncio.Event()
        bridge = exchanger()
        tasks = [asyncio.create_task(send(bridge, client)) for _ in range(protocol.MAX_IN_FLIGHT + 2)]
        while gateway.open < protocol.MAX_IN_FLIGHT:
            await asyncio.sleep(.01)
        await asyncio.sleep(.1)
        # The others wait on this machine: they have not even made a handshake.
        assert gateway.calls.count("handshake") == protocol.MAX_IN_FLIGHT
        gateway.hold.set()
        return await asyncio.gather(*tasks)

    responses = run(gateway, work)
    assert [response.status_code for response in responses] == [200] * (protocol.MAX_IN_FLIGHT + 2)
    assert gateway.most_open == protocol.MAX_IN_FLIGHT


def test_an_event_stream_keeps_its_place_until_it_ends(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_IN_FLIGHT", 1)
    gateway = FakeGateway(stream=True)

    async def work(client):
        bridge = exchanger()
        stream = await send(bridge, client)
        queued = asyncio.create_task(send(bridge, client))
        await asyncio.sleep(.1)
        assert gateway.calls == ["handshake", "exchange"]
        assert await run_stream(stream) == b"data: pong\n\n"
        second = await queued
        assert await run_stream(second) == b"data: pong\n\n"
        return gateway.calls

    assert run(gateway, work) == ["handshake", "exchange"] * 2


def test_a_request_whose_tool_leaves_while_it_waits_gives_its_turn_back(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_IN_FLIGHT", 1)
    gateway = FakeGateway()

    async def work(client):
        gateway.hold = asyncio.Event()
        bridge = exchanger()
        first = asyncio.create_task(send(bridge, client))
        while gateway.open < 1:
            await asyncio.sleep(.01)
        leaving = asyncio.create_task(send(bridge, client))
        await asyncio.sleep(.05)
        leaving.cancel()
        with pytest.raises(asyncio.CancelledError):
            await leaving
        gateway.hold.set()
        assert (await first).status_code == 200
        return (await send(bridge, client)).status_code

    assert run(gateway, work) == 200
    assert gateway.calls == ["handshake", "exchange"] * 2


def test_a_request_that_waits_too_long_for_its_turn_is_reported_busy(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_IN_FLIGHT", 1)
    gateway = FakeGateway()

    async def work(client):
        gateway.hold = asyncio.Event()
        bridge = exchanger(place_wait_seconds=.2)
        first = asyncio.create_task(send(bridge, client))
        while gateway.open < 1:
            await asyncio.sleep(.01)
        waiting = await send(bridge, client)
        gateway.hold.set()
        await first
        return waiting

    response = run(gateway, work)
    assert response.status_code == 502 and json.loads(response.body)["error"]["code"] == "busy"
    assert gateway.calls == ["handshake", "exchange"]


@pytest.mark.parametrize("seconds", [0, -1, float("nan")])
def test_the_wait_must_be_positive(seconds):
    with pytest.raises(ValueError, match="place_wait_seconds"):
        exchanger(place_wait_seconds=seconds)
