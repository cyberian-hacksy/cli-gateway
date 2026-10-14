"""Remote bridge against a synthetic upstream, over real loopback sockets."""
import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field

import httpx
import pytest

import wire_reference as ref
from cgw import protocol, remote_bridge
from harness import ServerThread, wait_until
from synthetic_upstream import INTERNAL_KEY, MODELS, Upstream, expected_stream

PSK = bytes(range(32))
OTHER_PSK = bytes(range(1, 33))
KID = "poc-1"
POST_RESPONSES = {"method": "POST", "path": "/v1/responses", "headers": {"content-type": "application/json"}}
GET_MODELS = {"method": "GET", "path": "/v1/models", "headers": {}}


@dataclass
class Stack:
    upstream: Upstream
    remote_url: str


@dataclass
class Result:
    status: int
    outer_headers: dict
    outer_error: dict | None = None
    records: list = field(default_factory=list)      # verified protocol.Record objects
    arrivals: list = field(default_factory=list)     # seconds since the request started
    finished: bool = False

    @property
    def meta(self):
        return next(record.value for record in self.records if record.type == protocol.META)

    @property
    def body(self):
        return b"".join(record.payload for record in self.records if record.type == protocol.DATA)

    @property
    def types(self):
        return [record.type for record in self.records]


def start_stack(tmp_path, upstream=None, upstream_url=None, **overrides):
    """Context manager yielding a running upstream + remote bridge."""
    upstream = upstream or Upstream()

    class Running:
        def __enter__(self):
            self.upstream_server = ServerThread(upstream.app).__enter__()
            settings = remote_bridge.Settings(
                keys={KID: PSK}, upstream_url=upstream_url or self.upstream_server.url,
                upstream_key=INTERNAL_KEY, **overrides)
            self.remote_server = ServerThread(remote_bridge.create_app(settings)).__enter__()
            return Stack(upstream=upstream, remote_url=self.remote_server.url)

        def __exit__(self, *exc_info):
            self.remote_server.__exit__(*exc_info)
            self.upstream_server.__exit__(*exc_info)

    return Running()


@pytest.fixture
def stack(tmp_path):
    with start_stack(tmp_path) as running:
        yield running


def start_handshake(remote_url, psk=PSK, kid=KID, ts=None, admission=None, message=None):
    """Send a handshake; returns (the client's handshake, the HTTP response)."""
    ts = int(time.time()) if ts is None else ts
    hello = protocol.ClientHandshake(psk, kid, ts)
    message = hello.message() if message is None else message
    tag = admission if admission is not None else protocol.seal_admission(psk, kid, hello.hid, ts, len(message))
    response = httpx.post(remote_url + "/poc/v2/handshake", content=message, timeout=20,
                          headers={"Content-Type": "application/json", protocol.ADMISSION_HEADER: tag})
    return hello, response


def handshake(remote_url, ts=None):
    hello, response = start_handshake(remote_url, ts=ts)
    assert response.status_code == 200, response.text
    return hello.complete(response.content)


SESSIONS = {}  # rid -> the session its envelope was sealed under, for reading the response


def seal(remote_url, body=None, metadata=POST_RESPONSES, rid=None, ts=None, session=None):
    """An envelope for the gateway at remote_url, on a fresh handshake unless a session is given."""
    rid = rid or os.urandom(32)
    ts = int(time.time()) if ts is None else ts
    session = session or handshake(remote_url, ts=ts)
    SESSIONS[rid] = session
    raw = b"" if body is None else json.dumps(body).encode()
    return protocol.seal_request(session, rid, ts, metadata, raw), rid, ts


def forged_session(remote_url):
    """A real handshake whose key material is then replaced, as someone without the keys would have."""
    real = handshake(remote_url)
    return protocol.Session(kid=real.kid, hid=real.hid, ikm=OTHER_PSK + bytes(32))


def admission_for(envelope, rid, ts, psk=PSK, kid=KID):
    return protocol.seal_admission(psk, kid, rid, ts, len(envelope))


def post_envelope(remote_url, envelope, rid, ts, headers=None, stop_after=None, admission=None):
    """Send an envelope with its admission tag and verify the encrypted response stream record by record."""
    started = time.monotonic()
    tag = admission if admission is not None else admission_for(envelope, rid, ts)
    send_headers = {"Content-Type": "application/json", protocol.ADMISSION_HEADER: tag, **(headers or {})}
    with httpx.stream("POST", remote_url + "/poc/v2/exchange", content=envelope,
                      headers=send_headers, timeout=20) as response:
        result = Result(status=response.status_code, outer_headers=dict(response.headers))
        if response.status_code != 200:
            response.read()
            try:
                result.outer_error = response.json()
            except ValueError:
                result.outer_error = None
            return result
        opener = protocol.ResponseOpener(SESSIONS[rid], rid, ts)
        lines = response.iter_lines()
        opener.open_header(next(lines).encode())
        for line in lines:
            result.records.append(opener.open_record(line.encode()))
            result.arrivals.append(time.monotonic() - started)
            if stop_after is not None and len(result.records) >= stop_after:
                break
        result.finished = opener.finished
        return result


def open_upload(remote_url, head, sent=b""):
    """A raw connection that sends the given request head and body bytes, then stays open."""
    host, port = remote_url.removeprefix("http://").split(":")
    connection = socket.create_connection((host, int(port)), timeout=5)
    connection.sendall(b"POST /poc/v2/exchange HTTP/1.1\r\nHost: gateway\r\n" + head + b"\r\n" + sent)
    return connection


def stalled_upload(remote_url, declared, admitted=True, psk=PSK):
    """Declares a body of `declared` bytes, sends ten of them, and then says nothing more.

    With `admitted`, it carries a valid admission tag, as a key holder (or someone replaying a
    fresh captured tag once) would; without, it is an anonymous client.
    """
    head = b"Content-Length: %d\r\n" % declared
    if admitted:
        tag = protocol.seal_admission(psk, KID, os.urandom(32), int(time.time()), declared)
        head += b"%s: %s\r\n" % (protocol.ADMISSION_HEADER.encode(), tag.encode())
    return open_upload(remote_url, head, b"x" * 10)


def answer(connection, timeout=3.0):
    """The HTTP status the server sends on this connection, or None if it stays silent."""
    connection.settimeout(timeout)
    try:
        data = connection.recv(4096)
    except (socket.timeout, TimeoutError):
        return None
    return int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/1.1 ") else None


def call(remote_url, body=None, metadata=POST_RESPONSES, **kwargs):
    envelope, rid, ts = seal(remote_url, body, metadata)
    return post_envelope(remote_url, envelope, rid, ts, **kwargs)


# --- the happy path -------------------------------------------------------------------

def test_streamed_response_arrives_encrypted_complete_and_byte_exact(stack):
    result = call(stack.remote_url, {"scenario": "stream", "events": 5})
    assert result.status == 200
    assert result.meta["status"] == 200
    assert result.body == expected_stream(5)
    assert result.types[0] == protocol.META and result.types[-1] == protocol.END
    assert result.finished


def test_outer_response_is_uncached_ndjson(stack):
    result = call(stack.remote_url, {"scenario": "stream"})
    assert result.outer_headers["content-type"].startswith("application/x-ndjson")
    assert result.outer_headers["cache-control"] == "no-store"
    assert "content-encoding" not in result.outer_headers


def test_first_output_arrives_before_upstream_finishes(stack):
    result = call(stack.remote_url, {"scenario": "stream", "events": 6, "delay": 0.1})
    first_data = next(at for at, kind in zip(result.arrivals, result.types) if kind == protocol.DATA)
    assert first_data < 0.3
    assert result.arrivals[-1] > 0.55


def test_models_request_is_relayed(stack):
    result = call(stack.remote_url, None, metadata=GET_MODELS)
    assert result.meta["status"] == 200
    assert json.loads(result.body) == MODELS


def test_non_streamed_json_response_is_relayed(stack):
    result = call(stack.remote_url, {"scenario": "json", "text": "pong ✓"})
    assert json.loads(result.body) == {"id": "resp_1", "output_text": "pong ✓"}
    assert result.meta["headers"]["content-type"].startswith("application/json")


@pytest.mark.parametrize("status", [400, 401, 429, 500, 503])
def test_upstream_error_status_and_body_are_preserved_inside_the_encryption(stack, status):
    result = call(stack.remote_url, {"scenario": "error", "status": status})
    assert result.status == 200
    assert result.meta["status"] == status
    assert json.loads(result.body)["error"]["message"] == "bad request from upstream"
    assert result.finished


def test_large_response_is_split_into_bounded_records(stack):
    result = call(stack.remote_url, {"scenario": "stream", "events": 3, "text": "x" * 40000})
    assert result.body == expected_stream(3, "x" * 40000)
    assert all(len(record.payload) <= 16 * 1024 for record in result.records)


# --- what reaches upstream ------------------------------------------------------------

def test_only_content_type_from_upstream_is_passed_back(stack):
    result = call(stack.remote_url, {"scenario": "stream"})
    assert list(result.meta["headers"]) == ["content-type"]


def test_internal_key_is_injected_and_client_credentials_are_not_forwarded(stack):
    metadata = {"method": "POST", "path": "/v1/responses", "headers": {
        "content-type": "application/json", "authorization": "Bearer client-local-key",
        "cookie": "session=1", "x-forwarded-for": "10.0.0.1", "connection": "keep-alive",
        "session-id": "abc-123", "x-codex-turn-metadata": '{"session_id":"abc-123"}',
        "x-not-on-the-list": "nope"}}
    result = call(stack.remote_url, {"scenario": "echo"}, metadata=metadata)
    seen = json.loads(result.body)["headers"]
    assert seen["authorization"] == "Bearer " + INTERNAL_KEY
    assert seen["session-id"] == "abc-123"
    assert seen["x-codex-turn-metadata"] == '{"session_id":"abc-123"}'
    for forbidden in ("cookie", "x-forwarded-for", "x-not-on-the-list"):
        assert forbidden not in seen
    assert seen["accept-encoding"] == "identity"


def test_request_body_reaches_upstream_unchanged(stack):
    body = {"scenario": "echo", "input": "héllo ✓ " * 500}
    call(stack.remote_url, body)
    assert stack.upstream.response_calls[0]["body"] == json.dumps(body).encode()


# --- authentication: nothing invalid reaches upstream ---------------------------------

def assert_rejected_without_upstream_call(stack, result, status=400, error="rejected"):
    assert result.status == status
    assert result.outer_error == {"error": error}
    assert stack.upstream.calls == []


def test_handshake_with_the_wrong_key_is_rejected_before_any_upstream_call(stack):
    _, response = start_handshake(stack.remote_url, psk=OTHER_PSK)
    assert (response.status_code, response.json()) == (400, {"error": "rejected"})
    assert stack.upstream.calls == []


def test_handshake_with_an_unknown_kid_is_rejected_like_a_wrong_key(stack):
    _, response = start_handshake(stack.remote_url, kid="someone-else")
    assert (response.status_code, response.json()) == (400, {"error": "rejected"})


def test_envelope_sealed_without_the_session_keys_is_rejected_before_any_upstream_call(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, session=forged_session(stack.remote_url))
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, envelope, rid, ts))


def test_tampered_ciphertext_is_rejected_before_any_upstream_call(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
    fields = json.loads(envelope)
    raw = bytearray(ref.unb64(fields["data"]))
    raw[10] ^= 0x01
    fields["data"] = ref.b64(bytes(raw))
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, ref.dump(fields), rid, ts))


@pytest.mark.parametrize("raw", [b"", b"not json", b"{}", b'{"v":1}'])
def test_malformed_envelope_is_rejected(stack, raw):
    result = post_envelope(stack.remote_url, raw, os.urandom(32), int(time.time()))
    assert_rejected_without_upstream_call(stack, result)


@pytest.mark.parametrize("metadata", [
    {"method": "POST", "path": "/v1/chat/completions", "headers": {}},
    {"method": "POST", "path": "/v1/responses?debug=1", "headers": {}},
    {"method": "GET", "path": "/v1/responses", "headers": {}},
    {"method": "POST", "path": "/v1/models", "headers": {}},
    {"method": "DELETE", "path": "/v1/models", "headers": {}},
    {"method": "POST", "path": "http://169.254.169.254/latest", "headers": {}},
    {"method": "POST", "path": "/v1/responses", "headers": {}, "url": "http://evil.example"},
    {"method": "POST", "path": "/v1/responses", "headers": "nope"},
    {"method": "POST", "path": "/v1/responses", "headers": {"content-type": 5}},
    {"path": "/v1/responses", "headers": {}},
    {"method": "POST", "path": "/v1/responses", "headers": {"session-id": "abc\r\nX-Injected: 1"}},
    {"method": "POST", "path": "/v1/responses", "headers": {"session-id": "abc\nAuthorization: Bearer x"}},
    {"method": "POST", "path": "/v1/responses", "headers": {"session-id": "abc\x00def"}},
    {"method": "POST", "path": "/v1/responses", "headers": {"bad name": "x"}},
    {"method": "POST", "path": "/v1/responses", "headers": {"x-injected:\r\nevil": "x"}},
])
def test_authenticated_request_outside_the_allowlist_is_rejected(stack, metadata):
    result = call(stack.remote_url, {"scenario": "stream"}, metadata=metadata)
    assert_rejected_without_upstream_call(stack, result)


def test_oversized_outer_request_is_rejected(stack):
    response = httpx.post(stack.remote_url + "/poc/v2/exchange", content=b" " * (12 * 1024 * 1024 + 1), timeout=30)
    assert response.status_code == 413
    assert stack.upstream.calls == []


def test_request_declaring_an_oversized_body_is_rejected_before_the_body_is_read(stack):
    # Only the headers are sent. The bridge must answer from the declared length alone.
    host, port = stack.remote_url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as connection:
        connection.sendall(b"POST /poc/v2/exchange HTTP/1.1\r\nHost: gateway\r\n"
                           b"Content-Type: application/json\r\nContent-Length: 999999999\r\n\r\n")
        connection.settimeout(3)
        answer = connection.recv(4096)
    assert answer.startswith(b"HTTP/1.1 413")
    assert stack.upstream.calls == []


def asgi_post(app, path, body, headers):
    """Drive one POST through the app in-process, bypassing any web server. Returns (status, body)."""
    import asyncio

    sent = []

    async def drive():
        messages = iter([{"type": "http.request", "body": body, "more_body": False}])

        async def receive():
            return next(messages, {"type": "http.disconnect"})

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
                 "server": ("gateway", 80), "client": ("127.0.0.1", 1), "headers": headers}
        await app(scope, receive, send)

    asyncio.run(drive())
    start = next(message for message in sent if message["type"] == "http.response.start")
    return start["status"], b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")


def test_body_longer_than_its_declared_length_is_rejected(tmp_path):
    # The memory budget is charged at the declared length, so the bridge must hold a body to
    # it even if the web server in front did not. Driven in-process to bypass that server.
    # The body is a perfectly valid envelope on a real session: only its length is wrong.
    app = remote_bridge.create_app(remote_bridge.Settings(
        keys={KID: PSK}, upstream_url="http://127.0.0.1:9", upstream_key=INTERNAL_KEY))
    ts = int(time.time())
    hello = protocol.ClientHandshake(PSK, KID, ts)
    message = hello.message()
    status, reply = asgi_post(app, "/poc/v2/handshake", message, [
        (b"content-length", str(len(message)).encode()),
        (protocol.ADMISSION_HEADER.encode(), protocol.seal_admission(PSK, KID, hello.hid, ts, len(message)).encode())])
    assert status == 200
    session, rid = hello.complete(reply), os.urandom(32)
    envelope = protocol.seal_request(session, rid, ts, POST_RESPONSES, b'{"scenario":"stream"}')
    status, body = asgi_post(app, "/poc/v2/exchange", envelope, [
        (b"content-length", b"10"),
        (protocol.ADMISSION_HEADER.encode(), protocol.seal_admission(PSK, KID, rid, ts, 10).encode())])
    assert len(envelope) > 10
    assert (status, body) == (400, b'{"error":"rejected"}')


def test_request_without_a_declared_length_is_refused_before_any_body_is_read(stack):
    # Memory for unauthenticated uploads is budgeted from the declared length, so one is required.
    with open_upload(stack.remote_url, b"Transfer-Encoding: chunked\r\n") as connection:
        assert answer(connection) == 411
    assert stack.upstream.calls == []


# --- several clients, each with its own key --------------------------------------------

LAPTOP_PSK = bytes(range(2, 34))


def call_as(remote_url, kid, psk, body=None):
    """One whole exchange as the client `kid` holding `psk`. Returns the result, or the refusal status."""
    hello, response = start_handshake(remote_url, psk=psk, kid=kid)
    if response.status_code != 200:
        return response.status_code
    session = hello.complete(response.content)
    envelope, rid, ts = seal(remote_url, body or {"scenario": "stream"}, session=session)
    return post_envelope(remote_url, envelope, rid, ts, admission=admission_for(envelope, rid, ts, psk=psk, kid=kid))


def test_each_configured_client_is_served_with_its_own_key(tmp_path):
    upstream = Upstream()
    with ServerThread(upstream.app) as upstream_server:
        settings = remote_bridge.Settings(keys={KID: PSK, "laptop-2": LAPTOP_PSK},
                                          upstream_url=upstream_server.url, upstream_key=INTERNAL_KEY)
        with ServerThread(remote_bridge.create_app(settings)) as remote:
            assert call_as(remote.url, KID, PSK).finished
            assert call_as(remote.url, "laptop-2", LAPTOP_PSK).finished
            # A client's name with another client's key, or a name the gateway does not know, gets nothing.
            assert call_as(remote.url, "laptop-2", PSK) == 400
            assert call_as(remote.url, "laptop-3", LAPTOP_PSK) == 400
    assert len(upstream.response_calls) == 2


def test_a_removed_client_is_refused_once_the_gateway_restarts_without_it(tmp_path):
    upstream = Upstream()
    with ServerThread(upstream.app) as upstream_server:
        outcomes = []
        for keys in ({KID: PSK, "laptop-2": LAPTOP_PSK}, {KID: PSK}):
            settings = remote_bridge.Settings(keys=keys, upstream_url=upstream_server.url, upstream_key=INTERNAL_KEY)
            with ServerThread(remote_bridge.create_app(settings)) as remote:
                result = call_as(remote.url, "laptop-2", LAPTOP_PSK)
                outcomes.append(result if isinstance(result, int) else result.status)
                assert call_as(remote.url, KID, PSK).finished
    assert outcomes == [200, 400]


def test_the_exchange_log_names_the_client(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="cgw.remote")
    upstream = Upstream()
    with ServerThread(upstream.app) as upstream_server:
        settings = remote_bridge.Settings(keys={KID: PSK, "laptop-2": LAPTOP_PSK},
                                          upstream_url=upstream_server.url, upstream_key=INTERNAL_KEY)
        with ServerThread(remote_bridge.create_app(settings)) as remote:
            assert call_as(remote.url, "laptop-2", LAPTOP_PSK).finished
            wait_until(lambda: any(r.getMessage().startswith("exchange ") for r in caplog.records))
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("exchange "))
    assert "client=laptop-2" in line


# --- the per-request key exchange ------------------------------------------------------

def test_handshake_completes_to_a_session(stack):
    session = handshake(stack.remote_url)
    assert session.kid == KID


def test_handshake_reply_is_not_cached(stack):
    hello, response = start_handshake(stack.remote_url)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("application/json")


def test_handshake_without_an_admission_tag_is_refused(stack):
    message = protocol.ClientHandshake(PSK, KID, int(time.time())).message()
    response = httpx.post(stack.remote_url + "/poc/v2/handshake", content=message)
    assert (response.status_code, response.json()) == (400, {"error": "rejected"})


def test_handshake_with_a_tampered_message_is_refused(stack):
    hello = protocol.ClientHandshake(PSK, KID, int(time.time()))
    fields = json.loads(hello.message())
    fields["epk"] = ref.b64(ref.x25519_public(bytes(range(9, 41))))
    message = ref.dump(fields)
    tag = protocol.seal_admission(PSK, KID, hello.hid, fields["ts"], len(message))
    _, response = start_handshake(stack.remote_url, admission=tag, message=message)
    assert (response.status_code, response.json()) == (400, {"error": "rejected"})


def test_handshake_must_match_its_admission_tag(stack):
    hello = protocol.ClientHandshake(PSK, KID, int(time.time()))
    message = hello.message()
    tag = protocol.seal_admission(PSK, KID, os.urandom(32), hello.ts, len(message))
    _, response = start_handshake(stack.remote_url, admission=tag, message=message)
    assert (response.status_code, response.json()) == (400, {"error": "rejected"})


def test_oversized_handshake_is_refused_before_it_is_read(stack):
    message = b" " * (protocol.MAX_HANDSHAKE_BYTES + 1)
    tag = protocol.seal_admission(PSK, KID, os.urandom(32), int(time.time()), len(message))
    _, response = start_handshake(stack.remote_url, admission=tag, message=message)
    assert response.status_code == 413


def test_a_session_serves_exactly_one_exchange(stack):
    session = handshake(stack.remote_url)
    first, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, session=session)
    second, rid2, ts2 = seal(stack.remote_url, {"scenario": "stream"}, session=session)
    assert post_envelope(stack.remote_url, first, rid, ts).finished
    assert_result = post_envelope(stack.remote_url, second, rid2, ts2)
    assert (assert_result.status, assert_result.outer_error) == (400, {"error": "rejected"})
    assert len(stack.upstream.response_calls) == 1


def test_a_session_expires_if_unused(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_bridge, "_SESSION_SECONDS", 0.3)
    with start_stack(tmp_path) as stack:
        session = handshake(stack.remote_url)
        time.sleep(0.5)
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, session=session)
        result = post_envelope(stack.remote_url, envelope, rid, ts)
        assert_rejected_without_upstream_call(stack, result)


def test_pending_sessions_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_bridge, "_MAX_PENDING_SESSIONS", 1)
    with start_stack(tmp_path) as stack:
        handshake(stack.remote_url)
        _, response = start_handshake(stack.remote_url)
        assert (response.status_code, response.json()) == (429, {"error": "busy"})


def test_a_completed_exchange_frees_its_place_among_pending_sessions(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_bridge, "_MAX_PENDING_SESSIONS", 1)
    with start_stack(tmp_path) as stack:
        for _ in range(3):
            assert call(stack.remote_url, {"scenario": "json"}).status == 200


def test_a_forged_envelope_naming_a_pending_handshake_does_not_spoil_it(stack):
    session = handshake(stack.remote_url)
    forged = protocol.Session(kid=session.kid, hid=session.hid, ikm=OTHER_PSK + bytes(32))
    bad, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, session=forged)
    assert post_envelope(stack.remote_url, bad, rid, ts).status == 400
    good, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, session=session)
    assert post_envelope(stack.remote_url, good, rid, ts).finished


# --- the admission tag: nothing is committed to a client without the key ----------------

def test_request_without_an_admission_tag_is_refused_before_its_body_is_read(stack):
    with stalled_upload(stack.remote_url, declared=1000, admitted=False) as connection:
        assert answer(connection, timeout=1.0) == 400
    assert stack.upstream.calls == []


def test_admission_tag_made_with_the_wrong_key_is_refused_before_the_body_is_read(stack):
    with stalled_upload(stack.remote_url, declared=1000, psk=OTHER_PSK) as connection:
        assert answer(connection, timeout=1.0) == 400


def test_anonymous_clients_cannot_occupy_the_admission_places(tmp_path):
    # The lockout this prevents: stalled anonymous uploads holding every place.
    with start_stack(tmp_path, max_pre_auth=1, receive_seconds=10) as stack:
        anonymous = [stalled_upload(stack.remote_url, declared=1000, admitted=False) for _ in range(20)]
        try:
            assert all(answer(connection, timeout=1.0) == 400 for connection in anonymous)
            started = time.monotonic()
            assert call(stack.remote_url, {"scenario": "stream"}).finished
            assert time.monotonic() - started < 1.0
        finally:
            for connection in anonymous:
                connection.close()


def test_admission_tag_cannot_be_used_twice(tmp_path):
    with start_stack(tmp_path, max_pre_auth=1, receive_seconds=10) as stack:
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
        tag = admission_for(envelope, rid, ts)
        assert post_envelope(stack.remote_url, envelope, rid, ts, admission=tag).finished
        head = b"Content-Length: %d\r\n%s: %s\r\n" % (len(envelope), protocol.ADMISSION_HEADER.encode(), tag.encode())
        with open_upload(stack.remote_url, head, b"x") as replay:
            assert answer(replay, timeout=1.0) == 409
        assert call(stack.remote_url, {"scenario": "stream"}).finished


def test_stale_admission_tag_is_refused_before_the_body_is_read(stack):
    tag = protocol.seal_admission(PSK, KID, os.urandom(32), int(time.time()) - 600, 1000)
    head = b"Content-Length: 1000\r\n%s: %s\r\n" % (protocol.ADMISSION_HEADER.encode(), tag.encode())
    with open_upload(stack.remote_url, head) as connection:
        assert answer(connection, timeout=1.0) == 400


def test_admission_tag_for_another_length_is_refused(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
    tag = protocol.seal_admission(PSK, KID, rid, ts, len(envelope) + 1)
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, envelope, rid, ts, admission=tag))


def test_envelope_must_match_its_admission_tag(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
    tag = protocol.seal_admission(PSK, KID, os.urandom(32), ts, len(envelope))
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, envelope, rid, ts, admission=tag))


def test_the_record_of_used_tags_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_bridge, "_MAX_REMEMBERED_ADMISSIONS", 4)  # two tags per request
    with start_stack(tmp_path) as stack:
        assert call(stack.remote_url, {"scenario": "json"}).status == 200
        assert call(stack.remote_url, {"scenario": "json"}).status == 200
        _, refused = start_handshake(stack.remote_url)  # the third request is turned away at its handshake
    assert (refused.status_code, refused.json()) == (429, {"error": "busy"})


def test_used_tags_are_forgotten_once_they_could_no_longer_be_fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_bridge, "_MAX_REMEMBERED_ADMISSIONS", 4)  # two tags per request
    monkeypatch.setattr(remote_bridge, "_ADMISSION_MEMORY_SECONDS", 0.3)
    with start_stack(tmp_path) as stack:
        assert call(stack.remote_url, {"scenario": "json"}).status == 200
        assert call(stack.remote_url, {"scenario": "json"}).status == 200
        time.sleep(0.4)
        assert call(stack.remote_url, {"scenario": "json"}).status == 200


# --- unauthenticated work is bounded before it starts ----------------------------------

def test_stalled_upload_is_cut_off_and_frees_its_place(tmp_path):
    with start_stack(tmp_path, max_pre_auth=1, receive_seconds=0.5) as stack:
        started = time.monotonic()
        with stalled_upload(stack.remote_url, declared=1000) as stalled:
            assert answer(stalled) == 408
        assert time.monotonic() - started < 2.5
        assert call(stack.remote_url, {"scenario": "stream"}).finished


def test_unauthenticated_uploads_beyond_the_limit_are_refused_at_once(tmp_path):
    with start_stack(tmp_path, max_pre_auth=2, receive_seconds=10) as stack:
        held = [stalled_upload(stack.remote_url, declared=1000) for _ in range(2)]
        time.sleep(0.3)
        started = time.monotonic()
        refused = call(stack.remote_url, {"scenario": "stream"})
        assert (refused.status, refused.outer_error) == (429, {"error": "busy"})
        assert time.monotonic() - started < 1.0
        assert stack.upstream.calls == []
        for connection in held:
            connection.close()
        wait_until(lambda: call(stack.remote_url, {"scenario": "stream"}).status == 200, timeout=3)


def test_stalled_uploads_within_the_limit_do_not_block_real_requests(stack):
    held = [stalled_upload(stack.remote_url, declared=1000) for _ in range(4)]
    time.sleep(0.3)
    try:
        assert call(stack.remote_url, {"scenario": "stream"}).finished
    finally:
        for connection in held:
            connection.close()


def test_memory_for_unauthenticated_uploads_is_budgeted_from_declared_lengths(tmp_path):
    with start_stack(tmp_path, pre_auth_bytes=1_000_000, receive_seconds=10) as stack:
        big = stalled_upload(stack.remote_url, declared=900_000)
        time.sleep(0.3)
        assert call(stack.remote_url, {"scenario": "stream"}).finished       # a small request still fits
        with stalled_upload(stack.remote_url, declared=200_000) as over_budget:
            assert answer(over_budget) == 429
        big.close()

        def admitted_again():
            with stalled_upload(stack.remote_url, declared=900_000) as retry:
                return answer(retry, timeout=0.4) is None    # silence: it was admitted and is being read

        wait_until(admitted_again, timeout=3)


def test_a_disconnected_upload_releases_its_budget(tmp_path):
    with start_stack(tmp_path, max_pre_auth=1, receive_seconds=10) as stack:
        for _ in range(5):
            stalled_upload(stack.remote_url, declared=1000).close()
        wait_until(lambda: call(stack.remote_url, {"scenario": "stream"}).status == 200, timeout=3)


def test_browser_origin_request_is_rejected(stack):
    result = call(stack.remote_url, {"scenario": "stream"}, headers={"Origin": "https://example.com"})
    assert_rejected_without_upstream_call(stack, result, status=403, error="forbidden")


# --- replay and freshness -------------------------------------------------------------

def test_replayed_envelope_is_refused_and_upstream_is_called_once(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
    first = post_envelope(stack.remote_url, envelope, rid, ts)
    second = post_envelope(stack.remote_url, envelope, rid, ts)
    assert first.finished
    assert (second.status, second.outer_error) == (409, {"error": "replayed"})
    assert len(stack.upstream.response_calls) == 1


def test_concurrent_duplicates_reach_upstream_exactly_once(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream", "events": 2, "delay": 0.05})
    results, barrier = [], threading.Barrier(6)

    def attempt():
        barrier.wait()
        results.append(post_envelope(stack.remote_url, envelope, rid, ts).status)

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [200] + [409] * 5
    assert len(stack.upstream.response_calls) == 1


def test_the_gateway_keeps_nothing_on_disk(tmp_path, monkeypatch):
    # Replay protection lives in memory (single-use admission tags and sessions), so the
    # gateway needs no storage of its own and writes nothing while serving.
    monkeypatch.chdir(tmp_path)
    with start_stack(tmp_path) as stack:
        assert call(stack.remote_url, {"scenario": "stream"}).finished
    assert list(tmp_path.iterdir()) == []


def test_replay_is_refused_after_the_bridge_restarts(tmp_path):
    upstream = Upstream()
    with ServerThread(upstream.app) as upstream_server:
        statuses, envelope = [], None
        for _ in range(2):
            settings = remote_bridge.Settings(keys={KID: PSK}, upstream_url=upstream_server.url,
                                              upstream_key=INTERNAL_KEY)
            with ServerThread(remote_bridge.create_app(settings)) as remote:
                if envelope is None:
                    envelope, rid, ts = seal(remote.url, {"scenario": "stream"})
                statuses.append(post_envelope(remote.url, envelope, rid, ts).status)
    # After a restart the session it was sealed under no longer exists anywhere, and nothing
    # on disk could bring it back.
    assert statuses == [200, 400]
    assert len(upstream.response_calls) == 1


def test_request_id_stays_consumed_when_the_upstream_call_fails(tmp_path):
    with start_stack(tmp_path, upstream_url="http://127.0.0.1:9") as stack:
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
        first = post_envelope(stack.remote_url, envelope, rid, ts)
        second = post_envelope(stack.remote_url, envelope, rid, ts)
        assert first.types == [protocol.ERROR]
        assert second.status == 409


FIXED_NOW = 1_800_000_000


@pytest.mark.parametrize("offset", [-121, 121, -3600, 3600])
def test_stale_or_future_handshake_is_rejected(tmp_path, offset):
    with start_stack(tmp_path, clock=lambda: FIXED_NOW) as stack:
        _, response = start_handshake(stack.remote_url, ts=FIXED_NOW + offset)
        assert (response.status_code, response.json()) == (400, {"error": "stale_timestamp"})


@pytest.mark.parametrize("offset", [-121, 121, -3600, 3600])
def test_stale_or_future_exchange_is_rejected(tmp_path, offset):
    with start_stack(tmp_path, clock=lambda: FIXED_NOW) as stack:
        session = handshake(stack.remote_url, ts=FIXED_NOW)
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, ts=FIXED_NOW + offset, session=session)
        result = post_envelope(stack.remote_url, envelope, rid, ts)
        assert_rejected_without_upstream_call(stack, result, error="stale_timestamp")


@pytest.mark.parametrize("offset", [-120, 0, 120])
def test_timestamp_inside_the_window_is_accepted(tmp_path, offset):
    with start_stack(tmp_path, clock=lambda: FIXED_NOW) as stack:
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, ts=FIXED_NOW + offset)
        assert post_envelope(stack.remote_url, envelope, rid, ts).finished


# --- heartbeats, failures and cancellation --------------------------------------------

def test_heartbeats_cover_upstream_silence_without_changing_the_output(tmp_path):
    with start_stack(tmp_path, heartbeat_seconds=0.1) as stack:
        result = call(stack.remote_url, {"scenario": "gap", "events": 3, "wait": 0.5})
    assert result.types.count(protocol.HEARTBEAT) >= 3
    assert result.body == expected_stream(3)
    assert result.finished


def test_heartbeats_are_sent_while_upstream_has_not_answered_yet(tmp_path):
    with start_stack(tmp_path, heartbeat_seconds=0.1) as stack:
        result = call(stack.remote_url, {"scenario": "slow_start", "wait": 0.5, "events": 1})
    assert result.types[0] == protocol.HEARTBEAT
    assert protocol.META in result.types and result.finished


def test_unreachable_upstream_gives_an_encrypted_error_record(tmp_path):
    with start_stack(tmp_path, upstream_url="http://127.0.0.1:9") as stack:
        result = call(stack.remote_url, {"scenario": "stream"})
    assert result.status == 200
    assert result.types == [protocol.ERROR]
    assert result.records[0].value == {"code": "upstream_unreachable"}
    assert result.finished


def test_upstream_cut_mid_stream_ends_with_an_error_record_not_end(stack):
    result = call(stack.remote_url, {"scenario": "cut", "events": 5})
    assert result.types[0] == protocol.META
    assert result.types[-1] == protocol.ERROR
    assert protocol.END not in result.types
    assert result.records[-1].value == {"code": "upstream_failed"}


def test_upstream_idle_timeout_ends_with_an_error_record(tmp_path):
    with start_stack(tmp_path, heartbeat_seconds=0.1, upstream_idle_seconds=0.4) as stack:
        result = call(stack.remote_url, {"scenario": "gap", "events": 3, "wait": 5})
    assert result.types[-1] == protocol.ERROR
    assert result.records[-1].value == {"code": "upstream_timeout"}
    assert result.arrivals[-1] < 2.0


def test_overall_timeout_ends_with_an_error_record(tmp_path):
    with start_stack(tmp_path, overall_seconds=0.5) as stack:
        result = call(stack.remote_url, {"scenario": "hang"})
    assert result.types[-1] == protocol.ERROR
    assert result.records[-1].value == {"code": "upstream_timeout"}
    assert result.arrivals[-1] < 2.0


def test_client_disconnect_cancels_the_upstream_call_within_two_seconds(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "hang"})
    post_envelope(stack.remote_url, envelope, rid, ts, stop_after=4)
    disconnected = time.monotonic()
    assert wait_until(stack.upstream.disconnected.is_set, timeout=2.0) < 2.0
    assert stack.upstream.disconnected_at - disconnected < 2.0


def test_client_disconnect_during_upstream_silence_cancels_within_two_seconds(stack):
    # Default 15 s heartbeat: nothing is being written, so the bridge must notice by itself.
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "silent", "events": 1})
    post_envelope(stack.remote_url, envelope, rid, ts, stop_after=3)
    assert wait_until(stack.upstream.disconnected.is_set, timeout=2.0) < 2.0


def test_in_flight_slot_is_released_after_a_client_disconnect(tmp_path):
    with start_stack(tmp_path, max_in_flight=1) as stack:
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "silent", "events": 1})
        post_envelope(stack.remote_url, envelope, rid, ts, stop_after=3)
        wait_until(stack.upstream.disconnected.is_set, timeout=2.0)
        wait_until(lambda: call(stack.remote_url, {"scenario": "stream"}).status == 200, timeout=2.0)


def test_requests_beyond_the_in_flight_limit_are_refused_and_never_reach_upstream(tmp_path):
    with start_stack(tmp_path, max_in_flight=2) as stack:
        holders = []
        for _ in range(2):
            thread = threading.Thread(
                target=lambda: call(stack.remote_url, {"scenario": "stream", "events": 4, "delay": 0.2}))
            thread.start()
            holders.append(thread)
        wait_until(lambda: len(stack.upstream.response_calls) == 2)
        third = call(stack.remote_url, {"scenario": "stream"})
        for thread in holders:
            thread.join()
        assert (third.status, third.outer_error) == (429, {"error": "busy"})
        assert len(stack.upstream.response_calls) == 2
        assert call(stack.remote_url, {"scenario": "stream"}).finished


def test_replayed_envelopes_do_not_occupy_in_flight_slots(tmp_path):
    # A flood of duplicates must be answered "replayed" and must not make the bridge busy.
    with start_stack(tmp_path, max_in_flight=1) as stack:
        envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"})
        assert post_envelope(stack.remote_url, envelope, rid, ts).finished
        statuses, barrier = [], threading.Barrier(12)

        def replay():
            barrier.wait()
            statuses.append(post_envelope(stack.remote_url, envelope, rid, ts).status)

        threads = [threading.Thread(target=replay) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert statuses == [409] * 12
        assert len(stack.upstream.response_calls) == 1


# --- surface --------------------------------------------------------------------------

def test_health_reports_ok_and_nothing_else(stack):
    response = httpx.get(stack.remote_url + "/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_reports_unavailable_when_upstream_is_down(tmp_path):
    with start_stack(tmp_path, upstream_url="http://127.0.0.1:9") as stack:
        response = httpx.get(stack.remote_url + "/healthz")
    assert (response.status_code, response.json()) == (503, {"status": "unavailable"})


def test_health_reports_unavailable_when_upstream_refuses_the_internal_key(tmp_path):
    with start_stack(tmp_path, upstream=Upstream(internal_key="a-different-internal-key-000000000000")) as stack:
        response = httpx.get(stack.remote_url + "/healthz")
    assert (response.status_code, response.json()) == (503, {"status": "unavailable"})


def test_unhealthy_gateway_probes_upstream_at_most_once_per_interval(tmp_path):
    # Health is unauthenticated, so a flood of requests must not become a flood of upstream calls.
    # The slow upstream makes all twenty requests arrive while the first probe is still running.
    upstream = Upstream(internal_key="a-different-internal-key-000000000000", models_delay=0.4)
    with start_stack(tmp_path, upstream=upstream) as stack:
        statuses = []
        threads = [threading.Thread(target=lambda: statuses.append(httpx.get(stack.remote_url + "/healthz").status_code))
                   for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert statuses == [503] * 20
    assert len(upstream.calls) == 1


def test_healthy_gateway_probes_upstream_at_most_once_per_interval(stack):
    for _ in range(10):
        assert httpx.get(stack.remote_url + "/healthz").status_code == 200
    assert len(stack.upstream.calls) == 1


@pytest.mark.parametrize("method,path", [
    ("GET", "/"), ("GET", "/v1/models"), ("POST", "/v1/responses"), ("GET", "/poc/v2/exchange"),
    ("GET", "/poc/v2/handshake"), ("POST", "/poc/v1/exchange"),
    ("POST", "/healthz"), ("GET", "/v0/management/config"), ("GET", "/docs"), ("GET", "/openapi.json"),
])
def test_nothing_else_is_exposed(stack, method, path):
    response = httpx.request(method, stack.remote_url + path)
    assert response.status_code in (404, 405)
    assert stack.upstream.calls == []


def test_no_cors_headers_are_sent(stack):
    result = call(stack.remote_url, {"scenario": "stream"})
    health = httpx.get(stack.remote_url + "/healthz", headers={"Origin": "https://example.com"})
    for headers in (result.outer_headers, dict(health.headers)):
        assert not any(name.startswith("access-control-") for name in headers)


def test_error_responses_do_not_reveal_details(stack):
    envelope, rid, ts = seal(stack.remote_url, {"scenario": "stream"}, session=forged_session(stack.remote_url))
    response = httpx.post(stack.remote_url + "/poc/v2/exchange", content=envelope,
                          headers={protocol.ADMISSION_HEADER: admission_for(envelope, rid, ts)})
    assert response.text == '{"error":"rejected"}'
