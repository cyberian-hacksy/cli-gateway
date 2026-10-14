"""Local bridge: the OpenAI-compatible endpoint Codex talks to on loopback.

Encrypts each request into an envelope for the remote bridge, verifies every record of
the encrypted response, and releases only verified plaintext to Codex. A stream that
cannot be verified to its final record is aborted, never completed.
"""
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from starlette.routing import Route

from cgw import policy, protocol, sse
from cgw.streaming import WatchedStreamingResponse, run_unless_client_leaves

log = logging.getLogger("cgw.local")

MAX_BUFFERED_RESPONSE_BYTES = 32 * 1024 * 1024
MIN_LOCAL_KEY_CHARS = 32

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_KID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
# Codes the local bridge will show the user. Anything else from the network is not echoed.
_OUTER_ERROR_CODES = frozenset({
    "rejected", "stale_timestamp", "replayed", "busy", "unavailable", "too_large", "forbidden",
    "too_slow", "length_required"})
_RECORD_ERROR_CODES = frozenset({"upstream_unreachable", "upstream_timeout", "upstream_failed"})
_OUTER_ERROR_PREVIEW_BYTES = 4096
_IDENTITY_CONTEXT = b"cgw-local-bridge-identity/v1\x00"
_NONCE_PATTERN = re.compile(r"(?:[0-9a-f]{2}){16,64}")


@dataclass(frozen=True)
class Settings:
    remote_url: str
    kid: str
    psk: bytes
    local_key: str
    proxy: str | None = None       # explicit outbound proxy, e.g. "http://proxy.corp:8080"
    ca_bundle: str | None = None   # CA file to trust for the outer TLS connection
    connect_seconds: float = 15.0
    # Silence allowed on the outer connection. Matches Codex's own 300 s stream idle timeout:
    # an inspecting proxy that buffers whole responses delivers nothing, heartbeats included,
    # until upstream finishes.
    idle_seconds: float = 300.0
    clock: Callable[[], float] = time.time

    def __post_init__(self):
        url = urlsplit(self.remote_url)
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOOPBACK_HOSTS):
            raise ValueError("remote_url must use https (plain http is allowed for loopback only)")
        if not isinstance(self.psk, bytes) or len(self.psk) != protocol.PSK_BYTES:
            raise ValueError("psk must be 32 bytes")
        if not isinstance(self.kid, str) or not _KID_PATTERN.fullmatch(self.kid):
            raise ValueError("kid must be 1-64 characters of [A-Za-z0-9_-]")
        if len(self.local_key) < MIN_LOCAL_KEY_CHARS:
            raise ValueError("local_key must be at least %d characters" % MIN_LOCAL_KEY_CHARS)


class StreamAborted(Exception):
    """The response cannot be completed truthfully; the client connection is dropped."""


def identity_proof(local_key, nonce):
    """Proof of holding the local key, bound to the caller's nonce. Reveals nothing about the key.

    The bridge starts on demand, so its port is normally free and any local process could
    bind it first. A caller checks this proof before sending the key or a prompt to
    whatever is listening.
    """
    return hmac.new(local_key.encode(), _IDENTITY_CONTEXT + nonce, hashlib.sha256).hexdigest()


def outer_error_code(status, body):
    """Map an unencrypted outer failure to a code from a fixed list. Network text is never echoed."""
    try:
        code = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return "bad_gateway_response"
    return code if isinstance(code, str) and code in _OUTER_ERROR_CODES else "bad_gateway_response"


def _error(status, error_type, code):
    payload = {"error": {"type": error_type, "code": code, "message": "Gateway error: " + code}}
    return Response(json.dumps(payload, separators=(",", ":")), status_code=status, media_type="application/json")


def _gateway_error(code):
    return _error(502, "gateway_error", code)


def build_client(settings):
    """Outer HTTP client. TLS verification is always on; proxy and CA are explicit settings."""
    verify = ssl.create_default_context(cafile=settings.ca_bundle) if settings.ca_bundle else True
    timeout = httpx.Timeout(connect=settings.connect_seconds, read=settings.idle_seconds,
                            write=settings.idle_seconds, pool=settings.connect_seconds)
    return httpx.AsyncClient(proxy=settings.proxy, verify=verify, timeout=timeout,
                             follow_redirects=False, trust_env=False)


async def _lines(outer):
    """Newline-terminated lines of the outer body, each bounded in size."""
    pending = b""
    async for chunk in outer.aiter_raw():
        pending += chunk
        while True:
            index = pending.find(b"\n")
            if index < 0:
                break
            yield pending[:index + 1]
            pending = pending[index + 1:]
        if len(pending) > protocol.MAX_RESPONSE_LINE_BYTES:
            raise protocol.ProtocolError("line too long")


async def _records(outer, opener):
    """Verified records in order, heartbeats removed. Raises unless the final record arrives."""
    lines = _lines(outer)
    try:
        opener.open_header(await anext(lines))
    except StopAsyncIteration:
        raise protocol.ProtocolError("empty response") from None
    async for line in lines:
        record = opener.open_record(line)
        if record.type != protocol.HEARTBEAT:
            yield record
        if opener.finished:
            return
    raise protocol.ProtocolError("stream truncated")


def _record_error_code(record):
    code = record.value.get("code")
    return code if code in _RECORD_ERROR_CODES else "bad_gateway_response"


def create_app(settings):
    state = {"client": None}
    local_key = settings.local_key.encode()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with build_client(settings) as client:
            state["client"] = client
            yield

    def authorized(request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        return scheme == "Bearer" and hmac.compare_digest(token.encode(), local_key)

    async def release_sse(records, outer):
        """Releases verified SSE bytes; the terminal event only after the final record verifies."""
        gate = sse.SseGate()
        try:
            async for record in records:
                if record.type == protocol.DATA:
                    released = gate.feed(record.payload)
                    if released:
                        yield released
                elif record.type == protocol.END:
                    yield gate.finish()
                    return
                else:
                    raise StreamAborted(_record_error_code(record))
        finally:
            await outer.aclose()

    async def exchange(method, path, forwarded, body):
        rid = os.urandom(protocol.RID_BYTES)
        ts = int(settings.clock())
        try:
            envelope = protocol.seal_request(
                settings.psk, settings.kid, rid, ts, {"method": method, "path": path, "headers": forwarded}, body)
        except protocol.ProtocolError:
            return _error(400, "invalid_request_error", "request_too_large")
        admission = protocol.seal_admission(settings.psk, settings.kid, rid, ts, len(envelope))
        opener = protocol.ResponseOpener(settings.psk, settings.kid, rid, ts)
        client = state["client"]
        try:
            outer = await client.send(client.build_request(
                "POST", settings.remote_url.rstrip("/") + "/poc/v1/exchange", content=envelope,
                headers={"content-type": "application/json", "accept-encoding": "identity",
                         protocol.ADMISSION_HEADER: admission}), stream=True)
        except httpx.ProxyError:
            # The configured proxy turned the tunnel down: a wrong proxy password, or the
            # gateway's hostname is blocked. Worth telling apart from a network outage.
            return _gateway_error("proxy_refused")
        except httpx.HTTPError:
            return _gateway_error("gateway_unreachable")

        handed_over = False
        try:
            content_type = outer.headers.get("content-type", "")
            if outer.status_code != 200 or not content_type.startswith("application/x-ndjson"):
                preview = b""
                with contextlib.suppress(httpx.HTTPError):
                    async for chunk in outer.aiter_raw():
                        preview += chunk
                        if len(preview) >= _OUTER_ERROR_PREVIEW_BYTES:
                            break
                return _gateway_error(outer_error_code(outer.status_code, preview))

            records = _records(outer, opener)
            try:
                first = await anext(records)
                if first.type == protocol.ERROR:
                    return _gateway_error(_record_error_code(first))
                status = first.value["status"]
                upstream_type = first.value["headers"].get("content-type")
                headers = {"content-type": upstream_type} if upstream_type else {}

                if status == 200 and upstream_type and upstream_type.startswith("text/event-stream"):
                    handed_over = True
                    return WatchedStreamingResponse(
                        release_sse(records, outer), status_code=200, headers=headers,
                        abort_on=(StreamAborted, protocol.ProtocolError, sse.SseError, httpx.HTTPError))

                # Anything that is not a successful event stream is delivered whole or not at all.
                buffered = bytearray()
                async for record in records:
                    if record.type == protocol.ERROR:
                        return _gateway_error(_record_error_code(record))
                    if record.type == protocol.DATA:
                        buffered += record.payload
                        if len(buffered) > MAX_BUFFERED_RESPONSE_BYTES:
                            return _gateway_error("bad_gateway_response")
                return Response(bytes(buffered), status_code=status, headers=headers)
            except (protocol.ProtocolError, httpx.HTTPError, StopAsyncIteration):
                return _gateway_error("bad_gateway_response")
        finally:
            if not handed_over:
                await outer.aclose()

    async def identity(request):
        """Answers a caller's challenge. Needs no credential, so nothing is risked by asking."""
        if "origin" in request.headers:
            return _error(403, "invalid_request_error", "browser_origin_refused")
        nonce = request.query_params.get("nonce", "")
        if not _NONCE_PATTERN.fullmatch(nonce):
            return _error(400, "invalid_request_error", "invalid_nonce")
        proof = identity_proof(settings.local_key, bytes.fromhex(nonce))
        return Response(json.dumps({"proof": proof}), media_type="application/json")

    async def handle(request):
        if "origin" in request.headers:
            return _error(403, "invalid_request_error", "browser_origin_refused")
        if not authorized(request):
            return _error(401, "invalid_request_error", "invalid_local_key")
        if request.url.query:
            return _error(400, "invalid_request_error", "query_not_allowed")
        if (request.method, request.url.path) not in policy.ALLOWED_ROUTES:
            return _error(404, "invalid_request_error", "not_found")

        body = bytearray()
        try:
            async for chunk in request.stream():
                body += chunk
                if len(body) > protocol.MAX_BODY_BYTES:
                    return _error(413, "invalid_request_error", "request_too_large")
        except ClientDisconnect:
            return Response(status_code=400)

        forwarded = {name.lower(): value for name, value in request.headers.items()
                     if name.lower() in policy.FORWARDED_REQUEST_HEADERS}
        started = time.monotonic()
        response = await run_unless_client_leaves(
            request.receive, exchange(request.method, request.url.path, forwarded, bytes(body)))
        if response is None:
            log.info("request path=%s outcome=client_left seconds=%.3f", request.url.path, time.monotonic() - started)
            return Response(status_code=499)
        log.info("request path=%s status=%d bytes_in=%d seconds_to_headers=%.3f",
                 request.url.path, response.status_code, len(body), time.monotonic() - started)
        return response

    return Starlette(
        routes=[
            Route("/v1/models", handle, methods=["GET"]),
            Route("/v1/responses", handle, methods=["POST"]),
            Route("/cgw/identity", identity, methods=["GET"]),
        ],
        lifespan=lifespan,
    )
