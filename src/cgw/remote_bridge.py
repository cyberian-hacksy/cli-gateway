"""Remote bridge: the only public surface of the gateway container.

Authenticates and decrypts each envelope, rejects replays through the ledger, forwards
the request to the fixed loopback upstream, and streams the response back as encrypted
records.
"""
import asyncio
import contextlib
import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import httpx
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from starlette.routing import Route

from cgw import policy, protocol
from cgw.ledger import LedgerError
from cgw.streaming import WatchedStreamingResponse

log = logging.getLogger("cgw.remote")

_METADATA_FIELDS = frozenset({"method", "path", "headers"})
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_HEADER_VALUE_FORBIDDEN = re.compile(r"[\x00\r\n]")
_QUEUE_RECORDS = 16  # 16 records of at most 16 KiB: a 256 KiB transport queue
_HEALTH_CACHE_SECONDS = 10.0


@dataclass(frozen=True)
class Settings:
    keys: Mapping[str, bytes]
    upstream_url: str
    upstream_key: str
    heartbeat_seconds: float = 15.0
    connect_seconds: float = 15.0
    upstream_idle_seconds: float = 180.0
    overall_seconds: float = 600.0
    max_in_flight: int = 2
    clock: Callable[[], float] = time.time


class _Rejected(Exception):
    """An authenticated request that the bridge will not forward."""


def _json(status, payload):
    return Response(json.dumps(payload, separators=(",", ":")), status_code=status, media_type="application/json")


def _validate_metadata(metadata):
    """Return (method, path, headers to forward). There is no way to name another destination."""
    if set(metadata) != _METADATA_FIELDS:
        raise _Rejected("unexpected metadata fields")
    method, path, headers = metadata["method"], metadata["path"], metadata["headers"]
    if not isinstance(method, str) or not isinstance(path, str) or (method, path) not in policy.ALLOWED_ROUTES:
        raise _Rejected("route not allowed")
    if type(headers) is not dict:
        raise _Rejected("invalid headers")
    forwarded = {}
    for name, value in headers.items():
        if not isinstance(value, str) or not _HEADER_NAME.fullmatch(name) or _HEADER_VALUE_FORBIDDEN.search(value):
            raise _Rejected("invalid header")
        if name.lower() in policy.FORWARDED_REQUEST_HEADERS:
            forwarded[name.lower()] = value
    return method, path, forwarded


def create_app(settings, ledger):
    state = {"in_flight": 0, "client": None, "health": (0.0, False)}

    @contextlib.asynccontextmanager
    async def lifespan(app):
        timeout = httpx.Timeout(connect=settings.connect_seconds, read=settings.upstream_idle_seconds,
                                write=settings.connect_seconds, pool=settings.connect_seconds)
        # trust_env=False: the loopback upstream is never reached through a proxy.
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            state["client"] = client
            yield

    def upstream_headers(forwarded=None):
        headers = dict(forwarded or {})
        headers["authorization"] = "Bearer " + settings.upstream_key
        headers["accept-encoding"] = "identity"
        return headers

    async def read_upstream(method, path, forwarded, body, queue):
        """Runs the upstream call and feeds the queue; always ends with ("end",) or ("error", code)."""
        try:
            async with state["client"].stream(method, settings.upstream_url + path,
                                              headers=upstream_headers(forwarded), content=body or None) as response:
                returned = {name.lower(): value for name, value in response.headers.items()
                            if name.lower() in policy.RETURNED_RESPONSE_HEADERS}
                await queue.put(("meta", response.status_code, returned))
                async for chunk in response.aiter_raw():
                    for piece in protocol.chunks(chunk):
                        await queue.put(("data", piece))
            await queue.put(("end",))
        except (httpx.ConnectError, httpx.ConnectTimeout):
            await queue.put(("error", "upstream_unreachable"))
        except httpx.TimeoutException:
            await queue.put(("error", "upstream_timeout"))
        except httpx.HTTPError:
            await queue.put(("error", "upstream_failed"))

    async def relay(opened, method, path, forwarded, summary):
        sealer = protocol.ResponseSealer(settings.keys[opened.kid], opened.kid, opened.rid, opened.ts)
        yield sealer.header_line()
        queue = asyncio.Queue(maxsize=_QUEUE_RECORDS)
        reader = asyncio.create_task(read_upstream(method, path, forwarded, opened.body, queue))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + settings.overall_seconds
        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    summary["outcome"] = "upstream_timeout"
                    yield sealer.error({"code": "upstream_timeout"})
                    return
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=min(settings.heartbeat_seconds, remaining))
                except asyncio.TimeoutError:
                    if deadline - loop.time() > 0:
                        yield sealer.heartbeat()
                    continue
                if item[0] == "meta":
                    summary["upstream_status"] = item[1]
                    yield sealer.meta(item[1], item[2])
                elif item[0] == "data":
                    summary["bytes_out"] += len(item[1])
                    yield sealer.data(item[1])
                elif item[0] == "end":
                    summary["outcome"] = "completed"
                    yield sealer.end()
                    return
                else:
                    summary["outcome"] = item[1]
                    yield sealer.error({"code": item[1]})
                    return
        finally:
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader

    def reject(status, error, reason):
        log.warning("rejected reason=%s", reason)
        return _json(status, {"error": error})

    async def exchange(request):
        if "origin" in request.headers:
            return reject(403, "forbidden", "browser_origin")
        declared = request.headers.get("content-length", "")
        if declared and (not declared.isdigit() or int(declared) > protocol.MAX_OUTER_REQUEST_BYTES):
            return reject(413, "too_large", "too_large")
        envelope = bytearray()
        try:
            async for chunk in request.stream():
                envelope += chunk
                if len(envelope) > protocol.MAX_OUTER_REQUEST_BYTES:
                    return reject(413, "too_large", "too_large")
        except ClientDisconnect:
            return Response(status_code=400)

        try:
            opened = protocol.open_request(bytes(envelope), settings.keys)
            method, path, forwarded = _validate_metadata(opened.metadata)
        except (protocol.ProtocolError, _Rejected) as error:
            return reject(400, "rejected", type(error).__name__)
        if not protocol.timestamp_is_fresh(opened.ts, int(settings.clock())):
            return reject(400, "stale_timestamp", "stale_timestamp")

        # The id is committed before anything else happens, and stays consumed whatever follows.
        try:
            fresh = await asyncio.to_thread(ledger.consume, opened.kid, opened.rid)
        except LedgerError:
            return reject(503, "unavailable", "ledger")
        if not fresh:
            return reject(409, "replayed", "replayed")

        # Only fresh requests take a slot, so replayed envelopes cannot make the bridge busy.
        # No await between the check and the increment, so the limit cannot be raced.
        if state["in_flight"] >= settings.max_in_flight:
            return reject(429, "busy", "busy")
        state["in_flight"] += 1
        released = False

        def release():
            nonlocal released
            if not released:
                released = True
                state["in_flight"] -= 1

        started = time.monotonic()
        summary = {"outcome": "aborted", "upstream_status": None, "bytes_out": 0}

        def on_close():
            release()
            log.info("exchange rid=%s outcome=%s upstream_status=%s bytes_in=%d bytes_out=%d seconds=%.3f",
                     opened.rid.hex()[:12], summary["outcome"], summary["upstream_status"],
                     len(opened.body), summary["bytes_out"], time.monotonic() - started)

        return WatchedStreamingResponse(
            relay(opened, method, path, forwarded, summary), on_close=on_close,
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    async def healthz(request):
        checked_at, healthy = state["health"]
        if time.monotonic() - checked_at > _HEALTH_CACHE_SECONDS or not healthy:
            try:
                await asyncio.to_thread(ledger.count)
                response = await state["client"].get(
                    settings.upstream_url + "/v1/models", headers=upstream_headers(), timeout=5.0)
                healthy = response.status_code == 200
            except (LedgerError, httpx.HTTPError):
                healthy = False
            state["health"] = (time.monotonic(), healthy)
        return _json(200 if healthy else 503, {"status": "ok" if healthy else "unavailable"})

    return Starlette(
        routes=[
            Route("/poc/v1/exchange", exchange, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        lifespan=lifespan,
    )
