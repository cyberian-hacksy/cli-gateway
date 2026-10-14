"""Remote bridge against a synthetic upstream, over real loopback sockets."""
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field

import httpx
import pytest

import wire_reference as ref
from cgw import ledger, protocol, remote_bridge
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
    book: ledger.Ledger


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
    ledger.Ledger.create(tmp_path / "replay.sqlite")
    book = ledger.Ledger(tmp_path / "replay.sqlite")

    class Running:
        def __enter__(self):
            self.upstream_server = ServerThread(upstream.app).__enter__()
            settings = remote_bridge.Settings(
                keys={KID: PSK}, upstream_url=upstream_url or self.upstream_server.url,
                upstream_key=INTERNAL_KEY, **overrides)
            self.remote_server = ServerThread(remote_bridge.create_app(settings, book)).__enter__()
            return Stack(upstream=upstream, remote_url=self.remote_server.url, book=book)

        def __exit__(self, *exc_info):
            self.remote_server.__exit__(*exc_info)
            self.upstream_server.__exit__(*exc_info)
            book.close()

    return Running()


@pytest.fixture
def stack(tmp_path):
    with start_stack(tmp_path) as running:
        yield running


def seal(body=None, metadata=POST_RESPONSES, rid=None, ts=None, psk=PSK, kid=KID):
    rid = rid or os.urandom(32)
    ts = int(time.time()) if ts is None else ts
    raw = b"" if body is None else json.dumps(body).encode()
    return protocol.seal_request(psk, kid, rid, ts, metadata, raw), rid, ts


def post_envelope(remote_url, envelope, rid, ts, psk=PSK, kid=KID, headers=None, stop_after=None):
    """Send an envelope and verify the encrypted response stream record by record."""
    started = time.monotonic()
    send_headers = {"Content-Type": "application/json", **(headers or {})}
    with httpx.stream("POST", remote_url + "/poc/v1/exchange", content=envelope,
                      headers=send_headers, timeout=20) as response:
        result = Result(status=response.status_code, outer_headers=dict(response.headers))
        if response.status_code != 200:
            response.read()
            try:
                result.outer_error = response.json()
            except ValueError:
                result.outer_error = None
            return result
        opener = protocol.ResponseOpener(psk, kid, rid, ts)
        lines = response.iter_lines()
        opener.open_header(next(lines).encode())
        for line in lines:
            result.records.append(opener.open_record(line.encode()))
            result.arrivals.append(time.monotonic() - started)
            if stop_after is not None and len(result.records) >= stop_after:
                break
        result.finished = opener.finished
        return result


def call(remote_url, body=None, metadata=POST_RESPONSES, **kwargs):
    envelope, rid, ts = seal(body, metadata)
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


def test_wrong_key_is_rejected_before_any_upstream_call(stack):
    envelope, rid, ts = seal({"scenario": "stream"}, psk=OTHER_PSK)
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, envelope, rid, ts))


def test_unknown_kid_is_rejected_like_a_wrong_key(stack):
    envelope, rid, ts = seal({"scenario": "stream"}, kid="someone-else")
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, envelope, rid, ts))


def test_tampered_ciphertext_is_rejected_before_any_upstream_call(stack):
    envelope, rid, ts = seal({"scenario": "stream"})
    fields = json.loads(envelope)
    raw = bytearray(ref.unb64(fields["data"]))
    raw[10] ^= 0x01
    fields["data"] = ref.b64(bytes(raw))
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, ref.dump(fields), rid, ts))


@pytest.mark.parametrize("raw", [b"", b"not json", b"{}", b'{"v":1}'])
def test_malformed_envelope_is_rejected(stack, raw):
    assert_rejected_without_upstream_call(stack, post_envelope(stack.remote_url, raw, bytes(32), 0))


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
    response = httpx.post(stack.remote_url + "/poc/v1/exchange", content=b" " * (12 * 1024 * 1024 + 1), timeout=30)
    assert response.status_code == 413
    assert stack.upstream.calls == []


def test_request_declaring_an_oversized_body_is_rejected_before_the_body_is_read(stack):
    # Only the headers are sent. The bridge must answer from the declared length alone.
    host, port = stack.remote_url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as connection:
        connection.sendall(b"POST /poc/v1/exchange HTTP/1.1\r\nHost: gateway\r\n"
                           b"Content-Type: application/json\r\nContent-Length: 999999999\r\n\r\n")
        connection.settimeout(3)
        answer = connection.recv(4096)
    assert answer.startswith(b"HTTP/1.1 413")
    assert stack.upstream.calls == []


def test_oversized_outer_request_without_a_declared_length_is_rejected(stack):
    def chunks():
        for _ in range(13):
            yield b" " * (1024 * 1024)

    response = httpx.post(stack.remote_url + "/poc/v1/exchange", content=chunks(), timeout=30)
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
    assert stack.upstream.calls == []


def test_browser_origin_request_is_rejected(stack):
    result = call(stack.remote_url, {"scenario": "stream"}, headers={"Origin": "https://example.com"})
    assert_rejected_without_upstream_call(stack, result, status=403, error="forbidden")


# --- replay and freshness -------------------------------------------------------------

def test_replayed_envelope_is_refused_and_upstream_is_called_once(stack):
    envelope, rid, ts = seal({"scenario": "stream"})
    first = post_envelope(stack.remote_url, envelope, rid, ts)
    second = post_envelope(stack.remote_url, envelope, rid, ts)
    assert first.finished
    assert (second.status, second.outer_error) == (409, {"error": "replayed"})
    assert len(stack.upstream.response_calls) == 1


def test_concurrent_duplicates_reach_upstream_exactly_once(stack):
    envelope, rid, ts = seal({"scenario": "stream", "events": 2, "delay": 0.05})
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


def test_replay_is_refused_after_the_bridge_restarts(tmp_path):
    upstream = Upstream()
    with ServerThread(upstream.app) as upstream_server:
        path = tmp_path / "replay.sqlite"
        ledger.Ledger.create(path)
        envelope, rid, ts = seal({"scenario": "stream"})
        statuses = []
        for _ in range(2):
            book = ledger.Ledger(path)
            settings = remote_bridge.Settings(keys={KID: PSK}, upstream_url=upstream_server.url,
                                              upstream_key=INTERNAL_KEY)
            with ServerThread(remote_bridge.create_app(settings, book)) as remote:
                statuses.append(post_envelope(remote.url, envelope, rid, ts).status)
            book.close()
    assert statuses == [200, 409]
    assert len(upstream.response_calls) == 1


def test_request_id_stays_consumed_when_the_upstream_call_fails(tmp_path):
    with start_stack(tmp_path, upstream_url="http://127.0.0.1:9") as stack:
        envelope, rid, ts = seal({"scenario": "stream"})
        first = post_envelope(stack.remote_url, envelope, rid, ts)
        second = post_envelope(stack.remote_url, envelope, rid, ts)
        assert first.types == [protocol.ERROR]
        assert second.status == 409


FIXED_NOW = 1_800_000_000


@pytest.mark.parametrize("offset", [-121, 121, -3600, 3600])
def test_stale_or_future_timestamp_is_rejected_and_does_not_consume_the_id(tmp_path, offset):
    with start_stack(tmp_path, clock=lambda: FIXED_NOW) as stack:
        envelope, rid, ts = seal({"scenario": "stream"}, ts=FIXED_NOW + offset)
        result = post_envelope(stack.remote_url, envelope, rid, ts)
        assert_rejected_without_upstream_call(stack, result, error="stale_timestamp")
        assert stack.book.count() == 0


@pytest.mark.parametrize("offset", [-120, 0, 120])
def test_timestamp_inside_the_window_is_accepted(tmp_path, offset):
    with start_stack(tmp_path, clock=lambda: FIXED_NOW) as stack:
        envelope, rid, ts = seal({"scenario": "stream"}, ts=FIXED_NOW + offset)
        assert post_envelope(stack.remote_url, envelope, rid, ts).finished


def test_rejected_envelope_does_not_consume_a_ledger_row(stack):
    envelope, rid, ts = seal({"scenario": "stream"}, psk=OTHER_PSK)
    post_envelope(stack.remote_url, envelope, rid, ts)
    assert stack.book.count() == 0


def test_unusable_ledger_fails_closed(stack):
    stack.book.close()
    result = call(stack.remote_url, {"scenario": "stream"})
    assert_rejected_without_upstream_call(stack, result, status=503, error="unavailable")


def test_full_ledger_fails_closed(tmp_path):
    upstream = Upstream()
    ledger.Ledger.create(tmp_path / "replay.sqlite")
    book = ledger.Ledger(tmp_path / "replay.sqlite", max_rows=1)
    with ServerThread(upstream.app) as upstream_server:
        settings = remote_bridge.Settings(keys={KID: PSK}, upstream_url=upstream_server.url,
                                          upstream_key=INTERNAL_KEY)
        with ServerThread(remote_bridge.create_app(settings, book)) as remote:
            assert call(remote.url, {"scenario": "stream"}).finished
            refused = call(remote.url, {"scenario": "stream"})
    assert (refused.status, refused.outer_error) == (503, {"error": "unavailable"})
    assert len(upstream.response_calls) == 1


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
    envelope, rid, ts = seal({"scenario": "hang"})
    post_envelope(stack.remote_url, envelope, rid, ts, stop_after=4)
    disconnected = time.monotonic()
    assert wait_until(stack.upstream.disconnected.is_set, timeout=2.0) < 2.0
    assert stack.upstream.disconnected_at - disconnected < 2.0


def test_client_disconnect_during_upstream_silence_cancels_within_two_seconds(stack):
    # Default 15 s heartbeat: nothing is being written, so the bridge must notice by itself.
    envelope, rid, ts = seal({"scenario": "silent", "events": 1})
    post_envelope(stack.remote_url, envelope, rid, ts, stop_after=3)
    assert wait_until(stack.upstream.disconnected.is_set, timeout=2.0) < 2.0


def test_in_flight_slot_is_released_after_a_client_disconnect(tmp_path):
    with start_stack(tmp_path, max_in_flight=1) as stack:
        envelope, rid, ts = seal({"scenario": "silent", "events": 1})
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
        envelope, rid, ts = seal({"scenario": "stream"})
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


def test_health_reports_unavailable_when_the_ledger_is_unusable(stack):
    stack.book.close()
    response = httpx.get(stack.remote_url + "/healthz")
    assert (response.status_code, response.json()) == (503, {"status": "unavailable"})


def test_health_reports_unavailable_when_upstream_is_down(tmp_path):
    with start_stack(tmp_path, upstream_url="http://127.0.0.1:9") as stack:
        response = httpx.get(stack.remote_url + "/healthz")
    assert (response.status_code, response.json()) == (503, {"status": "unavailable"})


def test_health_reports_unavailable_when_upstream_refuses_the_internal_key(tmp_path):
    with start_stack(tmp_path, upstream=Upstream(internal_key="a-different-internal-key-000000000000")) as stack:
        response = httpx.get(stack.remote_url + "/healthz")
    assert (response.status_code, response.json()) == (503, {"status": "unavailable"})


@pytest.mark.parametrize("method,path", [
    ("GET", "/"), ("GET", "/v1/models"), ("POST", "/v1/responses"), ("GET", "/poc/v1/exchange"),
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
    envelope, rid, ts = seal({"scenario": "stream"}, psk=OTHER_PSK)
    response = httpx.post(stack.remote_url + "/poc/v1/exchange", content=envelope)
    assert response.text == '{"error":"rejected"}'
