"""Remote bridge: the only public surface of the gateway container.

Runs a fresh X25519 handshake for every request, authenticates and decrypts each envelope
with that request's own keys, refuses replays through single-use admission tags and
sessions, forwards the request to the fixed loopback upstream, and streams the response
back as encrypted records. Each client has its own pre-shared key, looked up by its name.
"""
import asyncio
import collections
import contextlib
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import httpx
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from starlette.routing import Route

from cgw import policy, protocol
from cgw.streaming import WatchedStreamingResponse

log = logging.getLogger("cgw.remote")

_METADATA_FIELDS = frozenset({"method", "path", "headers"})
_OPTIONAL_METADATA_FIELDS = frozenset({"query"})
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_HEADER_VALUE_FORBIDDEN = re.compile(r"[\x00\r\n]")
_CONTENT_LENGTH = re.compile(r"[0-9]{1,12}")
_QUEUE_RECORDS = 16  # 16 records of at most 16 KiB: a 256 KiB transport queue
_HEALTHY_CACHE_SECONDS = 10.0
# Admission tags are single-use. One is remembered for longer than its timestamp stays fresh.
_ADMISSION_MEMORY_SECONDS = 300.0
_MAX_REMEMBERED_ADMISSIONS = 100_000
_UNHEALTHY_CACHE_SECONDS = 2.0
# A handshake's session waits in memory for its exchange, never longer, and is used once.
_SESSION_SECONDS = 30.0
_MAX_PENDING_SESSIONS = 256
_MAX_SIGN_IN_LIST_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Settings:
    keys: Mapping[str, bytes]
    upstream_url: str
    upstream_key: str
    # Key identifiers that may manage subscription sign-ins, and nothing else.
    admins: frozenset = frozenset()
    # CLIProxyAPI's management key, presented only on those requests. None disables them.
    management_key: str | None = None
    heartbeat_seconds: float = 15.0
    connect_seconds: float = 15.0
    upstream_idle_seconds: float = 180.0
    overall_seconds: float = 600.0
    max_in_flight: int = 2
    # Budgets for work done before a request has authenticated. Anyone on the internet can
    # start such work, so it is admitted against these limits before any body byte is read.
    max_pre_auth: int = 8
    pre_auth_bytes: int = 2 * protocol.MAX_OUTER_REQUEST_BYTES
    receive_seconds: float = 30.0
    clock: Callable[[], float] = time.time


class _Rejected(Exception):
    """An authenticated request that the bridge will not forward."""


class _PendingSessions:
    """Sessions between their handshake and their exchange: in memory only, short-lived, used once.

    Nothing here survives a restart, which is intended: a session is never needed again
    after its exchange, and keeping it would undo the forward secrecy.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = collections.OrderedDict()

    def _prune(self, now):
        while self._sessions and next(iter(self._sessions.values()))[1] < now:
            self._sessions.popitem(last=False)

    def add(self, session):
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            if len(self._sessions) >= _MAX_PENDING_SESSIONS:
                return False
            self._sessions[(session.kid, session.hid)] = (session, now + _SESSION_SECONDS)
            return True

    def find(self, kid, hid):
        """Look a session up without using it up."""
        with self._lock:
            self._prune(time.monotonic())
            entry = self._sessions.get((kid, hid))
            return entry[0] if entry else None

    def discard(self, kid, hid):
        """Use a session up. True only for the first caller."""
        with self._lock:
            return self._sessions.pop((kid, hid), None) is not None


def _json(status, payload):
    return Response(json.dumps(payload, separators=(",", ":")), status_code=status, media_type="application/json")


def _validate_metadata(metadata, admin=False):
    """Return (method, path with query, headers to forward). There is no way to name another destination.

    A client key may use the model routes only, and an admin key the sign-in routes only.
    """
    fields = set(metadata)
    if not _METADATA_FIELDS <= fields <= _METADATA_FIELDS | _OPTIONAL_METADATA_FIELDS:
        raise _Rejected("unexpected metadata fields")
    method, path, headers = metadata["method"], metadata["path"], metadata["headers"]
    query = metadata.get("query", "")
    try:
        # Only a query already in the canonical form, credentials removed, is accepted.
        if not isinstance(query, str) or policy.clean_query(query) != query:
            raise _Rejected("invalid query")
    except ValueError:
        raise _Rejected("invalid query") from None
    if admin:
        if not (isinstance(method, str) and isinstance(path, str) and policy.management_allowed(method, path, query)):
            raise _Rejected("route not allowed for an admin key")
    elif not policy.route_allowed(method, path):
        raise _Rejected("route not allowed")
    if type(headers) is not dict or len(headers) > policy.MAX_FORWARDED_HEADERS:
        raise _Rejected("invalid headers")
    forwarded = {}
    for name, value in headers.items():
        if not isinstance(value, str) or not _HEADER_NAME.fullmatch(name) or _HEADER_VALUE_FORBIDDEN.search(value):
            raise _Rejected("invalid header")
        if policy.header_forwarded(name):
            forwarded[name.lower()] = value
    return method, path + ("?" + query if query else ""), forwarded


def create_app(settings):
    state = {"in_flight": 0, "pre_auth": 0, "pre_auth_bytes": 0, "client": None,
             "health": (float("-inf"), False), "health_lock": None,
             "admissions": collections.OrderedDict()}
    sessions = _PendingSessions()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        timeout = httpx.Timeout(connect=settings.connect_seconds, read=settings.upstream_idle_seconds,
                                write=settings.connect_seconds, pool=settings.connect_seconds)
        # trust_env=False: the loopback upstream is never reached through a proxy.
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            state["client"] = client
            state["health_lock"] = asyncio.Lock()
            yield

    def upstream_headers(forwarded=None, management=False):
        headers = dict(forwarded or {})
        # Sign-in requests present the management key, everything else the client key.
        # The management key is never sent anywhere else.
        key = settings.management_key if management else settings.upstream_key
        headers["authorization"] = "Bearer " + key
        headers["accept-encoding"] = "identity"
        return headers

    async def read_upstream(method, path, forwarded, body, queue, management=False):
        """Runs the upstream call and feeds the queue; always ends with ("end",) or ("error", code)."""
        listing = management and method == "GET" and path == policy.SIGN_INS_PATH
        try:
            async with state["client"].stream(method, settings.upstream_url + path,
                                              headers=upstream_headers(forwarded, management),
                                              content=body or None) as response:
                returned = {name.lower(): value for name, value in response.headers.items()
                            if name.lower() in policy.RETURNED_RESPONSE_HEADERS}
                await queue.put(("meta", response.status_code, returned))
                if listing:
                    # The list of sign-ins is reduced to harmless fields before it leaves.
                    raw = b""
                    async for chunk in response.aiter_raw():
                        raw += chunk
                        if len(raw) > _MAX_SIGN_IN_LIST_BYTES:
                            raise httpx.HTTPError("sign-in list too large")
                    for piece in protocol.chunks(policy.filter_sign_ins(raw)):
                        await queue.put(("data", piece))
                else:
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
        except Exception:
            # Never leave the stream waiting for the overall deadline on an unexpected failure.
            log.exception("upstream call failed unexpectedly")
            await queue.put(("error", "upstream_failed"))

    async def relay(opened, method, path, forwarded, summary):
        sealer = protocol.ResponseSealer(opened.session, opened.rid, opened.ts)
        yield sealer.header_line()
        queue = asyncio.Queue(maxsize=_QUEUE_RECORDS)
        reader = asyncio.create_task(read_upstream(method, path, forwarded, opened.body, queue,
                                                   management=opened.kid in settings.admins))
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

    def claim_admission(admitted):
        """Mark a tag as used. Entries expire in insertion order, so pruning is cheap."""
        now = time.monotonic()
        remembered = state["admissions"]
        while remembered and next(iter(remembered.values())) < now:
            remembered.popitem(last=False)
        key = (admitted.kid, admitted.rid)
        if key in remembered:
            return "replayed"
        if len(remembered) >= _MAX_REMEMBERED_ADMISSIONS:
            return "full"
        remembered[key] = now + _ADMISSION_MEMORY_SECONDS
        return "claimed"

    async def receive_envelope(request, declared):
        chunks, received = [], 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > declared:
                raise _Rejected("body longer than declared")
            chunks.append(chunk)
        return b"".join(chunks)

    def authenticate(envelope):
        opened = protocol.open_request(envelope, sessions.find)
        # Used up only now that the envelope has authenticated, and only once.
        if not sessions.discard(opened.kid, opened.hid):
            raise _Rejected("session already used")
        admin = opened.kid in settings.admins
        if admin and (settings.management_key is None or (opened.body and opened.metadata.get("method") != "POST")):
            raise _Rejected("sign-in management unavailable or malformed")
        return opened, _validate_metadata(opened.metadata, admin=admin)

    async def admit(request, max_size):
        """Checks made from the request head alone, before any body byte is read.

        Returns (admission, size), or (None, response) when the request is refused. The
        admission tag proves possession of the key for this request ID and body length, so
        a client without the key cannot hold a place, use the memory budget, or make the
        bridge read a single body byte.
        """
        if "origin" in request.headers:
            return None, reject(403, "forbidden", "browser_origin")
        declared = request.headers.get("content-length", "")
        if not _CONTENT_LENGTH.fullmatch(declared):
            return None, reject(411, "length_required", "length_required")
        size = int(declared)
        if size > max_size:
            return None, reject(413, "too_large", "too_large")
        try:
            admitted = protocol.open_admission(request.headers.get(protocol.ADMISSION_HEADER), settings.keys, size)
        except protocol.ProtocolError:
            return None, reject(400, "rejected", "admission")
        if not protocol.timestamp_is_fresh(admitted.ts, int(settings.clock())):
            return None, reject(400, "stale_timestamp", "stale_timestamp")
        claim = claim_admission(admitted)
        if claim == "replayed":
            return None, reject(409, "replayed", "admission_replayed")
        if claim == "full":
            return None, reject(429, "busy", "admissions_full")
        return admitted, size

    async def handshake(request):
        """First half of every request: a fresh X25519 exchange, answered with a fresh key."""
        admitted, size = await admit(request, protocol.MAX_HANDSHAKE_BYTES)
        if admitted is None:
            return size
        try:
            message = await asyncio.wait_for(receive_envelope(request, size), settings.receive_seconds)
        except asyncio.TimeoutError:
            return reject(408, "too_slow", "receive_timeout")
        except ClientDisconnect:
            return Response(status_code=400)
        except _Rejected:
            return reject(400, "rejected", "body_length")
        try:
            answered = protocol.answer_handshake(message, settings.keys)
        except protocol.ProtocolError:
            return reject(400, "rejected", "handshake")
        session = answered.session
        if (session.kid, session.hid, answered.ts) != (admitted.kid, admitted.rid, admitted.ts):
            return reject(400, "rejected", "admission_mismatch")
        if not sessions.add(session):
            return reject(429, "busy", "sessions_full")
        return Response(answered.reply, media_type="application/json", headers={"Cache-Control": "no-store"})

    async def exchange(request):
        admitted, size = await admit(request, protocol.MAX_OUTER_REQUEST_BYTES)
        if admitted is None:
            return size

        # Admission to the work itself: a count limit, a memory budget charged at the declared
        # length, and below a deadline for the upload. These still bound key holders.
        # No await between the check and the increments, so the limits cannot be raced.
        if (state["pre_auth"] >= settings.max_pre_auth
                or state["pre_auth_bytes"] + size > settings.pre_auth_bytes):
            return reject(429, "busy", "pre_auth_busy")
        state["pre_auth"] += 1
        state["pre_auth_bytes"] += size
        try:
            try:
                envelope = await asyncio.wait_for(receive_envelope(request, size), settings.receive_seconds)
            except asyncio.TimeoutError:
                return reject(408, "too_slow", "receive_timeout")
            except ClientDisconnect:
                return Response(status_code=400)
            try:
                # Parsing and decrypting up to 12 MiB runs off the event loop, so an
                # unauthenticated request cannot stall streams that are in progress.
                opened, (method, path, forwarded) = await asyncio.to_thread(authenticate, envelope)
            except (protocol.ProtocolError, _Rejected) as error:
                return reject(400, "rejected", type(error).__name__)
        except _Rejected as error:
            return reject(400, "rejected", type(error).__name__)
        finally:
            state["pre_auth"] -= 1
            state["pre_auth_bytes"] -= size
        if (opened.kid, opened.rid, opened.ts) != (admitted.kid, admitted.rid, admitted.ts):
            return reject(400, "rejected", "admission_mismatch")
        if not protocol.timestamp_is_fresh(opened.ts, int(settings.clock())):
            return reject(400, "stale_timestamp", "stale_timestamp")

        # Only fresh requests reach this point: admission tags and sessions are single-use, so a
        # replayed envelope was refused above and cannot make the bridge busy.
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
            if opened.kid in settings.admins:
                # Sign-in management is rare and worth an audit line naming what was done.
                log.info("manage client=%s request=%s %s outcome=%s upstream_status=%s", opened.kid, method,
                         path.split("?", 1)[0], summary["outcome"], summary["upstream_status"])
            log.info("exchange client=%s rid=%s outcome=%s upstream_status=%s bytes_in=%d bytes_out=%d seconds=%.3f",
                     opened.kid, opened.rid.hex()[:12], summary["outcome"], summary["upstream_status"],
                     len(opened.body), summary["bytes_out"], time.monotonic() - started)

        return WatchedStreamingResponse(
            relay(opened, method, path, forwarded, summary), on_close=on_close,
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    async def probe():
        try:
            response = await state["client"].get(
                settings.upstream_url + "/v1/models", headers=upstream_headers(), timeout=5.0)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def health_is_current():
        checked_at, healthy = state["health"]
        lifetime = _HEALTHY_CACHE_SECONDS if healthy else _UNHEALTHY_CACHE_SECONDS
        return time.monotonic() - checked_at <= lifetime

    async def healthz(request):
        # Health is unauthenticated. Both outcomes are cached and only one probe runs at a
        # time, so a flood of requests cannot become a flood of upstream calls.
        if not health_is_current():
            async with state["health_lock"]:
                if not health_is_current():
                    state["health"] = (time.monotonic(), await probe())
        healthy = state["health"][1]
        return _json(200 if healthy else 503, {"status": "ok" if healthy else "unavailable"})

    return Starlette(
        routes=[
            Route("/poc/v2/handshake", handshake, methods=["POST"]),
            Route("/poc/v2/exchange", exchange, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        lifespan=lifespan,
    )
