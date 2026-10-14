"""End to end over loopback sockets: client -> local bridge -> hostile proxy -> remote bridge -> upstream."""
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

import httpx
import pytest

from cgw import ledger, local_bridge, policy, protocol, remote_bridge
from harness import ServerThread, wait_until
from synthetic_upstream import COMPLETED, CREATED, INTERNAL_KEY, MODELS, Upstream, delta, expected_stream
from tamper_proxy import TamperProxy

PSK = bytes(range(32))
KID = "poc-1"
LOCAL_KEY = "local-bearer-key-0123456789abcdef"
AUTH = {"Authorization": "Bearer " + LOCAL_KEY}
JSON_HEADERS = {**AUTH, "Content-Type": "application/json"}


@dataclass
class Stack:
    upstream: Upstream
    proxy: TamperProxy
    local_url: str
    remote_url: str
    book: ledger.Ledger


class start_stack:
    """Runs upstream, remote bridge, tamper proxy and local bridge; yields their handles."""

    def __init__(self, tmp_path, mode="pass", through_proxy=True, upstream_url=None,
                 remote_overrides=None, local_overrides=None):
        self.tmp_path, self.mode, self.through_proxy = tmp_path, mode, through_proxy
        self.upstream_url = upstream_url
        self.remote_overrides, self.local_overrides = remote_overrides or {}, local_overrides or {}
        self.servers = []

    def _serve(self, app):
        server = ServerThread(app).__enter__()
        self.servers.append(server)
        return server.url

    def __enter__(self):
        upstream = Upstream()
        upstream_url = self._serve(upstream.app)
        ledger.Ledger.create(self.tmp_path / "replay.sqlite")
        self.book = ledger.Ledger(self.tmp_path / "replay.sqlite")
        remote_url = self._serve(remote_bridge.create_app(remote_bridge.Settings(
            keys={KID: PSK}, upstream_url=self.upstream_url or upstream_url, upstream_key=INTERNAL_KEY,
            **self.remote_overrides), self.book))
        proxy = TamperProxy(remote_url, self.mode)
        proxy_url = self._serve(proxy.app)
        local_settings = {"remote_url": proxy_url if self.through_proxy else remote_url,
                          "kid": KID, "psk": PSK, "local_key": LOCAL_KEY, **self.local_overrides}
        local_url = self._serve(local_bridge.create_app(local_bridge.Settings(**local_settings)))
        return Stack(upstream=upstream, proxy=proxy, local_url=local_url, remote_url=remote_url, book=self.book)

    def __exit__(self, *exc_info):
        for server in reversed(self.servers):
            server.__exit__(*exc_info)
        self.book.close()


@pytest.fixture
def stack(tmp_path):
    with start_stack(tmp_path) as running:
        yield running


def post_responses(stack, body, headers=JSON_HEADERS, **kwargs):
    return httpx.post(stack.local_url + "/v1/responses", content=json.dumps(body).encode(),
                      headers=headers, timeout=20, **kwargs)


def stream_responses(stack, body, stop_after_bytes=None):
    """Streams a request; returns (status, headers, received bytes, arrival times, error or None)."""
    started, received, arrivals, error = time.monotonic(), b"", [], None
    with httpx.stream("POST", stack.local_url + "/v1/responses", content=json.dumps(body).encode(),
                      headers=JSON_HEADERS, timeout=20) as response:
        try:
            for chunk in response.iter_raw():
                received += chunk
                arrivals.append(time.monotonic() - started)
                if stop_after_bytes is not None and len(received) >= stop_after_bytes:
                    break
        except httpx.HTTPError as failure:
            error = failure
        return response.status_code, dict(response.headers), received, arrivals, error


# --- the happy path -------------------------------------------------------------------

def test_streamed_response_reaches_the_client_byte_for_byte(stack):
    status, headers, received, _, error = stream_responses(stack, {"scenario": "stream", "events": 5})
    assert (status, error) == (200, None)
    assert headers["content-type"].startswith("text/event-stream")
    assert received == expected_stream(5)


def test_first_output_reaches_the_client_before_upstream_finishes(stack):
    _, _, received, arrivals, _ = stream_responses(stack, {"scenario": "stream", "events": 6, "delay": 0.1})
    assert received == expected_stream(6)
    assert arrivals[0] < 0.35
    assert arrivals[-1] > 0.55


def test_models_are_listed(stack):
    response = httpx.get(stack.local_url + "/v1/models", headers=AUTH, timeout=20)
    assert (response.status_code, response.json()) == (200, MODELS)


def test_non_streamed_json_response_is_delivered(stack):
    response = post_responses(stack, {"scenario": "json", "text": "pong ✓"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"id": "resp_1", "output_text": "pong ✓"}


@pytest.mark.parametrize("status", [400, 401, 429, 500, 503])
def test_upstream_error_status_and_body_reach_the_client(stack, status):
    response = post_responses(stack, {"scenario": "error", "status": status})
    assert response.status_code == status
    assert response.json()["error"]["message"] == "bad request from upstream"


def test_heartbeats_never_reach_the_client(tmp_path):
    with start_stack(tmp_path, remote_overrides={"heartbeat_seconds": 0.1}) as stack:
        _, _, received, _, error = stream_responses(stack, {"scenario": "gap", "events": 3, "wait": 0.5})
    assert error is None
    assert received == expected_stream(3)


def test_each_request_uses_a_fresh_id_so_identical_requests_both_succeed(stack):
    body = {"scenario": "json"}
    assert post_responses(stack, body).status_code == 200
    assert post_responses(stack, body).status_code == 200
    assert len(stack.upstream.response_calls) == 2


# --- what reaches upstream ------------------------------------------------------------

def test_request_body_and_allowed_headers_reach_upstream_and_nothing_else_does(stack):
    body = {"scenario": "echo", "input": "héllo ✓ " * 300}
    headers = {**JSON_HEADERS, "session-id": "sess-42", "x-codex-turn-metadata": '{"session_id":"sess-42"}',
               "originator": "codex_exec", "Cookie": "a=b", "X-Secret-Thing": "do-not-forward"}
    response = post_responses(stack, body, headers=headers)
    seen = response.json()["headers"]
    assert stack.upstream.response_calls[0]["body"] == json.dumps(body).encode()
    assert seen["authorization"] == "Bearer " + INTERNAL_KEY
    assert (seen["session-id"], seen["originator"]) == ("sess-42", "codex_exec")
    assert seen["x-codex-turn-metadata"] == '{"session_id":"sess-42"}'
    assert "cookie" not in seen and "x-secret-thing" not in seen


def test_local_key_and_unlisted_headers_do_not_leave_the_machine_even_encrypted(stack):
    headers = {**JSON_HEADERS, "Cookie": "a=b", "X-Secret-Thing": "do-not-forward", "session-id": "sess-42"}
    post_responses(stack, {"scenario": "json"}, headers=headers)
    _, envelope = stack.proxy.requests[0]
    sealed = protocol.open_request(envelope, {KID: PSK})
    assert sealed.metadata["method"] == "POST" and sealed.metadata["path"] == "/v1/responses"
    sent = set(sealed.metadata["headers"])
    assert {"content-type", "session-id"} <= sent <= policy.FORWARDED_REQUEST_HEADERS
    assert not sent & {"authorization", "cookie", "x-secret-thing", "host", "content-length"}
    assert LOCAL_KEY.encode() not in json.dumps(sealed.metadata).encode() + sealed.body


def test_only_content_type_is_returned_from_upstream_headers(stack):
    _, headers, _, _, _ = stream_responses(stack, {"scenario": "stream"})
    assert "x-cpa-trace-id" not in headers
    assert not any(name.startswith("access-control-") for name in headers)


# --- the local surface ----------------------------------------------------------------

@pytest.mark.parametrize("headers", [
    {}, {"Authorization": "Bearer wrong-key"}, {"Authorization": LOCAL_KEY},
    {"Authorization": "Basic " + LOCAL_KEY}, {"Authorization": "Bearer"},
    {"Authorization": "bearer " + LOCAL_KEY}, {"Authorization": "Bearer " + LOCAL_KEY + "x"},
])
def test_missing_or_wrong_local_key_is_refused_before_anything_leaves_the_machine(stack, headers):
    response = post_responses(stack, {"scenario": "stream"}, headers={**headers, "Content-Type": "application/json"})
    assert response.status_code == 401
    assert stack.proxy.requests == []


@pytest.mark.parametrize("method,path", [
    ("POST", "/v1/chat/completions"), ("GET", "/v1/responses"), ("POST", "/v1/models"),
    ("GET", "/"), ("GET", "/healthz"), ("POST", "/poc/v1/exchange"), ("DELETE", "/v1/models"),
])
def test_only_the_two_allowed_routes_exist(stack, method, path):
    response = httpx.request(method, stack.local_url + path, headers=AUTH, timeout=20)
    assert response.status_code in (404, 405)
    assert stack.proxy.requests == []


def test_query_parameters_are_refused(stack):
    response = httpx.get(stack.local_url + "/v1/models?debug=1", headers=AUTH, timeout=20)
    assert response.status_code == 400
    assert stack.proxy.requests == []


def test_browser_origin_request_is_refused(stack):
    response = post_responses(stack, {"scenario": "stream"}, headers={**JSON_HEADERS, "Origin": "https://example.com"})
    assert response.status_code == 403
    assert stack.proxy.requests == []


def test_request_body_over_8_mib_is_refused_locally(stack):
    response = httpx.post(stack.local_url + "/v1/responses", content=b"x" * (8 * 1024 * 1024 + 1),
                          headers=JSON_HEADERS, timeout=30)
    assert response.status_code == 413
    assert stack.proxy.requests == []


# --- proving identity before being trusted with anything -------------------------------

def expected_proof(nonce):
    """Independent of the implementation: HMAC-SHA256 under the local key, domain-separated."""
    return hmac.new(LOCAL_KEY.encode(), b"cgw-local-bridge-identity/v1\x00" + nonce, hashlib.sha256).hexdigest()


def test_bridge_proves_it_holds_the_local_key_without_being_sent_it(stack):
    nonce = os.urandom(32)
    response = httpx.get(stack.local_url + "/cgw/identity", params={"nonce": nonce.hex()}, timeout=10)
    assert response.status_code == 200
    assert response.json() == {"proof": expected_proof(nonce)}
    assert stack.proxy.requests == []


def test_identity_proof_is_bound_to_the_nonce(stack):
    proofs = {httpx.get(stack.local_url + "/cgw/identity", params={"nonce": os.urandom(32).hex()}).json()["proof"]
              for _ in range(3)}
    assert len(proofs) == 3


def test_identity_response_does_not_contain_the_local_key(stack):
    response = httpx.get(stack.local_url + "/cgw/identity", params={"nonce": "ab" * 32})
    assert response.status_code == 200
    assert LOCAL_KEY not in response.text and LOCAL_KEY not in str(response.headers)


@pytest.mark.parametrize("nonce", ["", "abc", "zz" * 32, "ab" * 15, "ab" * 65, "AB" * 32 + "g"])
def test_identity_request_with_a_malformed_nonce_is_refused(stack, nonce):
    assert httpx.get(stack.local_url + "/cgw/identity", params={"nonce": nonce}).status_code == 400


def test_identity_request_without_a_nonce_is_refused(stack):
    assert httpx.get(stack.local_url + "/cgw/identity").status_code == 400


def test_identity_request_from_a_browser_origin_is_refused(stack):
    response = httpx.get(stack.local_url + "/cgw/identity", params={"nonce": "ab" * 32},
                         headers={"Origin": "https://example.com"})
    assert response.status_code == 403


# --- confidentiality on the wire ------------------------------------------------------

def test_prompt_and_reply_are_absent_from_everything_the_network_sees(stack):
    prompt_canary, reply_canary = "PROMPT-CANARY-9c1f7e42", "REPLY-CANARY-5ab03d18"
    _, _, received, _, _ = stream_responses(
        stack, {"scenario": "stream", "events": 4, "text": reply_canary, "input": prompt_canary})
    captured = stack.proxy.captured
    assert reply_canary.encode() in received
    assert prompt_canary.encode() in stack.upstream.response_calls[0]["body"]
    assert len(captured) > 1000
    assert prompt_canary.encode() not in captured
    assert reply_canary.encode() not in captured


def test_secrets_and_client_headers_are_absent_from_everything_the_network_sees(stack):
    headers = {**JSON_HEADERS, "session-id": "SESSION-CANARY-77aa", "x-codex-turn-metadata": "META-CANARY-31bc"}
    post_responses(stack, {"scenario": "json"}, headers=headers)
    captured = stack.proxy.captured
    for secret in (LOCAL_KEY, INTERNAL_KEY, "SESSION-CANARY-77aa", "META-CANARY-31bc", "/v1/responses"):
        assert secret.encode() not in captured
    assert PSK not in captured and PSK.hex().encode() not in captured


def test_outer_request_is_a_bare_envelope_to_the_exchange_endpoint(stack):
    post_responses(stack, {"scenario": "json"})
    headers, body = stack.proxy.requests[0]
    assert set(json.loads(body)) == {"v", "kid", "rid", "ts", "header", "data"}
    assert "authorization" not in headers and "cookie" not in headers
    assert headers["accept-encoding"] == "identity"
    assert headers["content-type"] == "application/json"
    admitted = protocol.open_admission(headers[protocol.ADMISSION_HEADER], {KID: PSK}, len(body))
    sealed = protocol.open_request(body, {KID: PSK})
    assert (admitted.kid, admitted.rid, admitted.ts) == (sealed.kid, sealed.rid, sealed.ts)


# --- integrity: a hostile network cannot forge or truncate a completion ----------------

def assert_aborted_without_completion(result):
    status, _, received, _, error = result
    assert status == 200
    assert error is not None, "the stream must end with a transport error, not a clean finish"
    assert b"response.completed" not in received
    return received


def test_dropped_final_record_never_yields_a_completion(tmp_path):
    with start_stack(tmp_path, mode="drop_last") as stack:
        received = assert_aborted_without_completion(stream_responses(stack, {"scenario": "stream", "events": 5}))
    assert received == CREATED + b"".join(delta(i) for i in range(5))


def test_connection_cut_mid_stream_never_yields_a_completion(tmp_path):
    with start_stack(tmp_path, mode="cut_after:4") as stack:
        assert_aborted_without_completion(stream_responses(stack, {"scenario": "stream", "events": 8, "delay": 0.02}))


@pytest.mark.parametrize("mode", ["flip:3", "swap:2", "duplicate:3", "inject:3"])
def test_tampered_stream_is_aborted_and_releases_nothing_unauthenticated(tmp_path, mode):
    with start_stack(tmp_path, mode=mode) as stack:
        received = assert_aborted_without_completion(
            stream_responses(stack, {"scenario": "stream", "events": 6, "delay": 0.01}))
    assert b"INJECTED-PLAINTEXT" not in received
    assert expected_stream(6).startswith(received)


@pytest.mark.parametrize("mode", ["flip:1", "flip:0", "inject:1"])
def test_tampering_before_the_first_record_gives_a_gateway_error(tmp_path, mode):
    with start_stack(tmp_path, mode=mode) as stack:
        response = post_responses(stack, {"scenario": "stream"})
    assert response.status_code == 502
    assert response.json()["error"]["type"] == "gateway_error"
    assert b"INJECTED-PLAINTEXT" not in response.content


def test_tampered_buffered_response_gives_a_gateway_error_and_no_partial_body(tmp_path):
    with start_stack(tmp_path, mode="drop_last") as stack:
        response = post_responses(stack, {"scenario": "json"})
    assert response.status_code == 502
    assert b"resp_1" not in response.content


def test_upstream_cut_during_a_buffered_response_gives_a_gateway_error_and_no_partial_body(stack):
    response = post_responses(stack, {"scenario": "cut_json"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_failed"
    assert b"PARTIAL-BODY-MARKER" not in response.content


def test_upstream_cut_mid_stream_never_yields_a_completion(stack):
    assert_aborted_without_completion(stream_responses(stack, {"scenario": "cut", "events": 5}))


def test_upstream_stream_without_a_terminal_event_is_not_reported_as_success(stack):
    status, _, received, _, error = stream_responses(stack, {"scenario": "no_terminal", "events": 3})
    assert status == 200
    assert error is not None
    assert b"response.completed" not in received


# --- outer failures become generic gateway errors -------------------------------------

def test_html_error_page_from_the_network_is_never_passed_to_the_client(tmp_path):
    with start_stack(tmp_path, mode="html") as stack:
        response = post_responses(stack, {"scenario": "stream"})
    assert response.status_code == 502
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"error": {"type": "gateway_error", "code": "bad_gateway_response",
                                         "message": "Gateway error: bad_gateway_response"}}
    assert b"Blocked by policy" not in response.content and b"<html" not in response.content


def test_response_line_that_never_ends_is_cut_off_promptly(tmp_path):
    with start_stack(tmp_path, mode="endless_line") as stack:
        started = time.monotonic()
        response = post_responses(stack, {"scenario": "stream"})
        elapsed = time.monotonic() - started
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "bad_gateway_response"
    assert elapsed < 5.0


def test_clock_skew_is_reported_as_a_stale_timestamp(tmp_path):
    with start_stack(tmp_path, local_overrides={"clock": lambda: time.time() - 1000}) as stack:
        response = post_responses(stack, {"scenario": "stream"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "stale_timestamp"
    assert stack.upstream.calls == []


def test_unreachable_upstream_is_reported_as_a_gateway_error(tmp_path):
    with start_stack(tmp_path, upstream_url="http://127.0.0.1:9") as stack:
        response = post_responses(stack, {"scenario": "stream"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unreachable"


def test_unreachable_remote_bridge_is_reported_as_a_gateway_error(tmp_path):
    with start_stack(tmp_path, through_proxy=False, local_overrides={"remote_url": "http://127.0.0.1:9"}) as stack:
        response = post_responses(stack, {"scenario": "stream"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "gateway_unreachable"


def test_unknown_outer_error_code_is_not_echoed():
    # A network that answers with its own JSON cannot put arbitrary text in front of the user.
    assert local_bridge.outer_error_code(400, b'{"error":"<script>alert(1)</script>"}') == "bad_gateway_response"
    assert local_bridge.outer_error_code(400, b'{"error":"stale_timestamp"}') == "stale_timestamp"
    assert local_bridge.outer_error_code(502, b"<html>") == "bad_gateway_response"


# --- cancellation ---------------------------------------------------------------------

def test_client_disconnect_cancels_the_upstream_call_through_both_bridges(tmp_path):
    with start_stack(tmp_path, through_proxy=False) as stack:
        stream_responses(stack, {"scenario": "silent", "events": 1}, stop_after_bytes=len(CREATED))
        assert wait_until(stack.upstream.disconnected.is_set, timeout=2.0) < 2.0


def test_client_giving_up_before_any_header_cancels_the_upstream_call(tmp_path):
    with start_stack(tmp_path, through_proxy=False) as stack:
        with pytest.raises(httpx.ReadTimeout):
            httpx.post(stack.local_url + "/v1/responses", content=json.dumps({"scenario": "slow_start", "wait": 30}),
                       headers=JSON_HEADERS, timeout=0.5)
        assert wait_until(stack.upstream.disconnected.is_set, timeout=2.0) < 2.0


# --- settings -------------------------------------------------------------------------

def test_plain_http_to_a_non_loopback_remote_is_refused():
    with pytest.raises(ValueError):
        local_bridge.Settings(remote_url="http://gateway.example.com", kid=KID, psk=PSK, local_key=LOCAL_KEY)


@pytest.mark.parametrize("url", ["https://gateway.example.com", "http://127.0.0.1:8000", "http://localhost:8000"])
def test_https_or_loopback_remote_is_accepted(url):
    assert local_bridge.Settings(remote_url=url, kid=KID, psk=PSK, local_key=LOCAL_KEY).remote_url == url


@pytest.mark.parametrize("field,value", [("psk", bytes(31)), ("local_key", "short"), ("kid", "bad kid")])
def test_weak_or_malformed_secrets_are_refused(field, value):
    arguments = {"remote_url": "https://gateway.example.com", "kid": KID, "psk": PSK, "local_key": LOCAL_KEY}
    arguments[field] = value
    with pytest.raises(ValueError):
        local_bridge.Settings(**arguments)
