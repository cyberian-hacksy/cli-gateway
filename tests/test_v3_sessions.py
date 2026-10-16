"""Admission identity cannot consume or replace another pending session."""
import asyncio
import json
import time

import httpx
import pytest

from cgw import local_bridge, protocol, remote_bridge
from test_remote_bridge import (ADMIN_KID, ADMIN_PSK, GET_MODELS, KID, PSK, admin_stack,
                                admission_for, post_envelope, seal, start_handshake)


def test_pending_sessions_belong_to_the_key_that_made_them():
    sessions = remote_bridge._PendingSessions()
    owner = protocol.Session("owner", b"h" * 32, b"k" * 64)
    other = protocol.Session("other", owner.hid, b"x" * 64)
    assert sessions.add(owner, 100) == "added"
    # Another key naming the same handshake neither collides with it nor reaches it.
    assert sessions.add(other, 100) == "added"
    assert sessions.find("owner", owner.hid) == owner
    assert sessions.find("other", owner.hid) == other
    assert sessions.find("nobody", owner.hid) is None
    assert not sessions.discard("nobody", owner.hid, ts=100)
    assert not sessions.discard("owner", owner.hid, ts=101)
    assert sessions.discard("owner", owner.hid, ts=100)
    assert not sessions.discard("owner", owner.hid, ts=100)
    assert sessions.find("other", owner.hid) == other


def test_a_live_duplicate_is_refused_without_replacing_the_session():
    sessions = remote_bridge._PendingSessions()
    owner = protocol.Session("owner", b"h" * 32, b"k" * 64)
    assert sessions.add(owner, 100) == "added"
    assert sessions.add(protocol.Session("owner", owner.hid, b"z" * 64), 100) == "duplicate"
    assert sessions.find("owner", owner.hid) == owner


def test_expiry_between_lookup_and_consumption_is_checked(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(remote_bridge.time, "monotonic", lambda: now[0])
    sessions = remote_bridge._PendingSessions()
    owner = protocol.Session("owner", b"h" * 32, b"k" * 64)
    assert sessions.add(owner, 100) == "added"
    assert sessions.find("owner", owner.hid) == owner
    now[0] = 31.0
    assert not sessions.discard("owner", owner.hid, ts=100)


def test_another_key_naming_a_pending_handshake_gets_its_own_session():
    with admin_stack() as gateway:
        ts = int(time.time())
        first = protocol.ClientHandshake(PSK, KID, ts)
        second = protocol.ClientHandshake(ADMIN_PSK, ADMIN_KID, ts, hid=first.hid)
        replies = []
        for hello, psk in ((first, PSK), (second, ADMIN_PSK)):
            message = hello.message()
            tag = protocol.seal_admission(protocol.derive_admission_key(psk), hello.hid, ts, len(message))
            response = httpx.post(gateway.remote.url + "/poc/v3/handshake", content=message,
                                  headers={protocol.ADMISSION_HEADER: tag})
            assert response.status_code == 200, response.text
            replies.append(response.content)
        envelope, rid, ts = seal(gateway.remote.url, metadata=GET_MODELS, session=first.complete(replies[0]), ts=ts)
        assert post_envelope(gateway.remote.url, envelope, rid, ts).finished


def test_another_admitted_key_cannot_burn_a_captured_envelope():
    with admin_stack() as gateway:
        hello, response = start_handshake(gateway.remote.url)
        session = hello.complete(response.content)
        envelope, rid, ts = seal(gateway.remote.url, metadata=GET_MODELS, session=session, ts=hello.ts)
        foreign_tag = admission_for(envelope, rid, ts, psk=ADMIN_PSK)
        result = post_envelope(gateway.remote.url, envelope, rid, ts, admission=foreign_tag)
        assert result.status == 400
        assert gateway.upstream.calls == []
        assert post_envelope(gateway.remote.url, envelope, rid, ts).finished


def test_handshake_mac_must_use_the_admitted_key():
    with admin_stack() as gateway:
        hello = protocol.ClientHandshake(PSK, KID, int(time.time()))
        message = hello.message()
        tag = protocol.seal_admission(protocol.derive_admission_key(ADMIN_PSK), hello.hid, hello.ts, len(message))
        response = httpx.post(gateway.remote.url + "/poc/v3/handshake", content=message,
                              headers={protocol.ADMISSION_HEADER: tag})
        assert (response.status_code, response.json()) == (400, {"error": "rejected"})


def test_wrong_exchange_timestamp_does_not_consume_the_session():
    with admin_stack() as gateway:
        hello, response = start_handshake(gateway.remote.url)
        session = hello.complete(response.content)
        bad, rid, ts = seal(gateway.remote.url, metadata=GET_MODELS, session=session, ts=hello.ts + 1)
        assert post_envelope(gateway.remote.url, bad, rid, ts).status == 400
        good, rid, ts = seal(gateway.remote.url, metadata=GET_MODELS, session=session, ts=hello.ts)
        assert post_envelope(gateway.remote.url, good, rid, ts).finished


def test_concurrent_envelopes_use_a_session_only_once():
    from concurrent.futures import ThreadPoolExecutor
    with admin_stack() as gateway:
        hello, response = start_handshake(gateway.remote.url)
        session = hello.complete(response.content)
        envelopes = [seal(gateway.remote.url, metadata=GET_MODELS, session=session, ts=hello.ts) for _ in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: post_envelope(gateway.remote.url, *args), envelopes))
        assert sorted(result.status for result in results) == [200, 400]
        assert len(gateway.upstream.calls) == 1


@pytest.mark.parametrize("body", [b"", b"<h1>proxy text</h1>", b'{"error":"busy"}'])
def test_outer_404_is_a_fixed_protocol_mismatch(body):
    assert local_bridge.outer_error_code(404, body) == "protocol_mismatch"
    response = local_bridge._gateway_error("protocol_mismatch")
    message = json.loads(response.body)["error"]["message"]
    # A 404 can come from an older gateway, or from whatever answers at a wrong address.
    assert "remote_url" in message and "proxy" in message and "older" in message
    assert b"proxy text" not in response.body


@pytest.mark.parametrize("missing", ["handshake", "exchange", "upstream"])
def test_mismatch_mapping_at_both_endpoints_preserves_an_encrypted_upstream_404(missing):
    answers, paths = [], []
    upstream_body = b'{"error":"upstream route not found"}'

    def response(status, content_type, body):
        return httpx.Response(status, headers={"content-type": content_type}, stream=httpx.ByteStream(body))

    def gateway(request):
        paths.append(request.url.path)
        if request.url.path.endswith("/" + missing):
            return response(404, "text/html", b"UNTRUSTED-OUTER-ERROR")
        if request.url.path.endswith("/handshake"):
            answered = protocol.answer_handshake(request.content, KID, PSK)
            answers.append(answered)
            return response(200, "application/json", answered.reply)
        fields = json.loads(request.content)
        # A valid encrypted upstream failure, carried in a successful outer exchange.
        from wire_reference import unb64
        sealer = protocol.ResponseSealer(answers[0].session, unb64(fields["rid"]), fields["ts"])
        lines = [sealer.header_line(), sealer.meta(404, {"content-type": "application/json"}),
                 sealer.data(upstream_body), sealer.end()]
        return response(200, "application/x-ndjson", b"".join(lines))

    async def work():
        settings = local_bridge.Settings("https://gateway.example.com", KID, PSK, "synthetic-local-test-key-0123456789abcdef")
        async with httpx.AsyncClient(transport=httpx.MockTransport(gateway)) as client:
            result = await local_bridge.Exchanger(settings).exchange(client, "GET", "/v1/models", "", {}, b"")
        if missing == "upstream":
            assert result.status_code == 404 and result.body == upstream_body
        else:
            assert result.status_code == 502
            assert json.loads(result.body)["error"]["code"] == "protocol_mismatch"
            assert b"UNTRUSTED" not in result.body
        assert paths == (["/poc/v3/handshake"] if missing == "handshake" else
                         ["/poc/v3/handshake", "/poc/v3/exchange"])

    asyncio.run(work())
