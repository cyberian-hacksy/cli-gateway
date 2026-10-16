"""Local bridge: the endpoint command-line tools talk to on loopback.

It speaks whichever API format the tool uses (OpenAI, Anthropic or Gemini), within the
routes in `policy.py`. For each request it runs a fresh X25519 handshake with the remote
bridge, encrypts the request with keys from that handshake, verifies every record of the
encrypted response, and releases only verified plaintext to the tool. A stream that cannot
be verified to its final record is aborted, never completed.
"""
import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
import random
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
    "rejected", "stale_timestamp", "replayed", "busy", "too_large", "forbidden",
    "too_slow", "length_required"})
_RECORD_ERROR_CODES = frozenset({"upstream_unreachable", "upstream_timeout", "upstream_failed"})
_OUTER_ERROR_PREVIEW_BYTES = 4096
_HANDSHAKE_REPLY_MAX_BYTES = 4096
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
    # How long a request may wait, queued here and refused as busy, for a place at the gateway.
    place_wait_seconds: float = 120.0
    clock: Callable[[], float] = time.time

    def __post_init__(self):
        url = urlsplit(self.remote_url)
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOOPBACK_HOSTS):
            raise ValueError("remote_url must use https (plain http is allowed for loopback only)")
        if not isinstance(self.psk, bytes) or len(self.psk) != protocol.PSK_BYTES:
            raise ValueError("psk must be 32 bytes")
        if not isinstance(self.kid, str) or not _KID_PATTERN.fullmatch(self.kid):
            raise ValueError("kid must be 1-64 characters of [A-Za-z0-9_-]")
        if not (math.isfinite(self.place_wait_seconds) and self.place_wait_seconds > 0):
            raise ValueError("place_wait_seconds must be positive and finite")
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
    if status == 404:
        return "protocol_mismatch"
    try:
        code = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return "bad_gateway_response"
    return code if isinstance(code, str) and code in _OUTER_ERROR_CODES else "bad_gateway_response"


def _error(status, error_type, code):
    message = ("Gateway protocol mismatch: the gateway address answered 404. Check remote_url and any "
               "proxy in between. If both are right, the gateway runs an older or newer version than "
               "this machine: bring both to the same one." if code == "protocol_mismatch" else "Gateway error: " + code)
    payload = {"error": {"type": error_type, "code": code, "message": message}}
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


class _Busy(Exception):
    """The gateway refused a handshake as busy. No request has been sent yet, so it may be tried again."""


class _Place:
    """One of the gateway's places, held from the handshake until the response is over."""

    def __init__(self, places):
        self._places, self._held, self.handed_over = places, True, False

    def release(self):
        if self._held:
            self._held = False
            self._places.release()


def _record_error_code(record):
    code = record.value.get("code")
    return code if code in _RECORD_ERROR_CODES else "bad_gateway_response"


class Exchanger:
    """Sends one request through the gateway and returns only verified plaintext.

    The local bridge uses it for every request a tool makes; the admin tools use it with the
    admin key for sign-in requests.
    """

    def __init__(self, settings):
        self.settings = settings
        self._admission_key = protocol.derive_admission_key(settings.psk)
        # Sending more requests than the gateway has places only earns `busy`. The rest
        # wait here instead, in order.
        self._places = asyncio.Semaphore(protocol.MAX_IN_FLIGHT)

    async def _release_sse(self, records, outer):
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

    async def _post(self, client, path, content, tag):
        return await client.send(client.build_request(
            "POST", self.settings.remote_url.rstrip("/") + path, content=content,
            headers={"content-type": "application/json", "accept-encoding": "identity",
                     protocol.ADMISSION_HEADER: tag}), stream=True)

    @staticmethod
    async def _read_capped(response, limit):
        received = b""
        async for chunk in response.aiter_raw():
            received += chunk
            if len(received) > limit:
                break
        return received

    async def _handshake(self, client, ts):
        """A fresh X25519 exchange with the gateway. Returns (session, None) or (None, error response)."""
        hello = protocol.ClientHandshake(self.settings.psk, self.settings.kid, ts)
        message = hello.message()
        tag = protocol.seal_admission(self._admission_key, hello.hid, ts, len(message))
        reply = await self._post(client, "/poc/v3/handshake", message, tag)
        try:
            body = await self._read_capped(reply, _HANDSHAKE_REPLY_MAX_BYTES)
        finally:
            await reply.aclose()
        if reply.status_code != 200 or not reply.headers.get("content-type", "").startswith("application/json"):
            code = outer_error_code(reply.status_code, body[:_OUTER_ERROR_PREVIEW_BYTES])
            if code == "busy":
                # Safe to try again: nothing that could be forwarded has been sent.
                raise _Busy
            return None, _gateway_error(code)
        try:
            return hello.complete(body), None
        except protocol.ProtocolError:
            return None, _gateway_error("bad_gateway_response")

    async def exchange(self, client, method, path, query, forwarded, body):
        """Send one request through the gateway; return the verified response or a gateway error.

        At most MAX_IN_FLIGHT requests go to the gateway at once; the rest wait their turn.
        A handshake refused as `busy` is tried again after a growing pause, until
        `place_wait_seconds` have passed in all. An exchange refused as `busy` is reported,
        never sent again: the refusal is not authenticated, so someone on the path could
        forge it after the gateway forwarded the request, and a second sending would
        deliver it twice.
        """
        if len(body) > protocol.MAX_BODY_BYTES:
            return _error(400, "invalid_request_error", "request_too_large")
        deadline = time.monotonic() + self.settings.place_wait_seconds
        try:
            async with asyncio.timeout(self.settings.place_wait_seconds):
                await self._places.acquire()
        except TimeoutError:
            return self._still_busy()
        place = _Place(self._places)
        try:
            pause = 0.1
            while True:
                try:
                    return await self._attempt(client, method, path, query, forwarded, body, place)
                except _Busy:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return self._still_busy()
                    # The last pause is cut short, so the final try comes at the deadline.
                    await asyncio.sleep(min(pause * random.uniform(0.5, 1.0), remaining))
                    pause = min(pause * 2, 2.0)
        finally:
            if not place.handed_over:
                place.release()

    def _still_busy(self):
        log.warning("no place free at the gateway after %.0f s", self.settings.place_wait_seconds)
        return _gateway_error("busy")

    async def _attempt(self, client, method, path, query, forwarded, body, place):
        """One try: a fresh handshake, then the exchange. Raises _Busy if the handshake was refused as busy."""
        settings = self.settings
        rid = os.urandom(protocol.RID_BYTES)
        ts = int(settings.clock())
        metadata = {"method": method, "path": path, "headers": forwarded}
        if query:
            metadata["query"] = query
        try:
            session, refused = await self._handshake(client, ts)
            if refused is not None:
                return refused
            try:
                envelope = protocol.seal_request(session, rid, ts, metadata, body)
            except protocol.ProtocolError:
                return _error(400, "invalid_request_error", "request_too_large")
            opener = protocol.ResponseOpener(session, rid, ts)
            del session  # nothing outlives this request; the opener holds only the response key
            tag = protocol.seal_admission(self._admission_key, rid, ts, len(envelope))
            outer = await self._post(client, "/poc/v3/exchange", envelope, tag)
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
                    # The stream keeps the gateway's place until it ends, so it keeps its own too.
                    handed_over = place.handed_over = True
                    return WatchedStreamingResponse(
                        self._release_sse(records, outer), status_code=200, headers=headers,
                        on_close=place.release,
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


def create_app(settings):
    state = {"client": None}
    exchanger = Exchanger(settings)
    local_key = settings.local_key.encode()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with build_client(settings) as client:
            state["client"] = client
            yield

    def authorized(request):
        """The local key, sent the way the tool's API format sends a key: as a Bearer token
        (OpenAI, and Anthropic's auth token), as x-api-key (Anthropic) or x-goog-api-key (Gemini)."""
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        candidates = [token] if scheme == "Bearer" else []
        candidates += [request.headers[name] for name in ("x-api-key", "x-goog-api-key") if name in request.headers]
        # Every candidate is compared, so the time taken does not depend on which one matched.
        matches = [hmac.compare_digest(candidate.encode(), local_key) for candidate in candidates]
        return any(matches)

    async def identity(request):
        """Answers a caller's challenge. Needs no credential, so nothing is risked by asking."""
        if "origin" in request.headers:
            return _error(403, "invalid_request_error", "browser_origin_refused")
        nonce = request.query_params.get("nonce", "")
        if not _NONCE_PATTERN.fullmatch(nonce):
            return _error(400, "invalid_request_error", "invalid_nonce")
        proof = identity_proof(settings.local_key, bytes.fromhex(nonce))
        return Response(json.dumps({"proof": proof, "protocol": protocol.VERSION}), media_type="application/json")

    async def handle(request):
        if "origin" in request.headers:
            return _error(403, "invalid_request_error", "browser_origin_refused")
        if not authorized(request):
            return _error(401, "invalid_request_error", "invalid_local_key")
        if not policy.route_allowed(request.method, request.url.path):
            return _error(404, "invalid_request_error", "not_found")
        try:
            query = policy.clean_query(request.url.query)
        except ValueError:
            return _error(400, "invalid_request_error", "invalid_query")
        forwarded = {name.lower(): value for name, value in request.headers.items() if policy.header_forwarded(name)}
        if len(forwarded) > policy.MAX_FORWARDED_HEADERS:
            return _error(400, "invalid_request_error", "too_many_headers")

        body = bytearray()
        try:
            async for chunk in request.stream():
                body += chunk
                if len(body) > protocol.MAX_BODY_BYTES:
                    return _error(413, "invalid_request_error", "request_too_large")
        except ClientDisconnect:
            return Response(status_code=400)

        started = time.monotonic()
        response = await run_unless_client_leaves(
            request.receive, exchanger.exchange(state["client"], request.method, request.url.path, query,
                                                forwarded, bytes(body)))
        if response is None:
            log.info("request path=%s outcome=client_left seconds=%.3f", request.url.path, time.monotonic() - started)
            return Response(status_code=499)
        log.info("request path=%s status=%d bytes_in=%d seconds_to_headers=%.3f",
                 request.url.path, response.status_code, len(body), time.monotonic() - started)
        return response

    return Starlette(
        routes=[
            Route("/cgw/identity", identity, methods=["GET"]),
            # Every other path is checked against the policy in `handle`.
            Route("/{path:path}", handle, methods=["GET", "POST"]),
        ],
        lifespan=lifespan,
    )
