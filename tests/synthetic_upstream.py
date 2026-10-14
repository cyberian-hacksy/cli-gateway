"""Synthetic upstream standing in for CLIProxyAPI in bridge tests.

Speaks the two endpoints the gateway allows and records every call it receives. The
request body's "scenario" field selects the behaviour, so tests steer it without the
bridges needing to know.
"""
import asyncio
import json
import threading
import time

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

INTERNAL_KEY = "synthetic-internal-key-0123456789abcdef"
MODELS = {"object": "list", "data": [{"id": "gpt-6-astra", "object": "model"}]}


def sse(event, data):
    return ("event: %s\ndata: %s\n\n" % (event, json.dumps(data, separators=(",", ":")))).encode()


CREATED = sse("response.created", {"type": "response.created"})
COMPLETED = sse("response.completed", {"type": "response.completed", "response": {"id": "resp_1"}})


def delta(index, text=None):
    return sse("response.output_text.delta",
               {"type": "response.output_text.delta", "delta": text or "tok%d ✓ " % index})


def expected_stream(events=5, text=None):
    """The exact bytes the 'stream' scenario sends."""
    return CREATED + b"".join(delta(i, text) for i in range(events)) + COMPLETED


class Upstream:
    def __init__(self, internal_key=INTERNAL_KEY, default_scenario="stream"):
        self.internal_key = internal_key
        self.default_scenario = default_scenario
        self.calls = []                       # one dict per request received
        self.disconnected = threading.Event()  # set when a streaming client goes away early
        self.disconnected_at = None
        self.app = Starlette(routes=[
            Route("/v1/models", self._models, methods=["GET"]),
            Route("/v1/responses", self._responses, methods=["POST"]),
        ])

    @property
    def response_calls(self):
        return [call for call in self.calls if call["path"] == "/v1/responses"]

    def _record(self, request, body=b""):
        self.calls.append({"method": request.method, "path": request.url.path,
                           "headers": dict(request.headers), "body": body, "at": time.monotonic()})

    def _authorized(self, request):
        return request.headers.get("authorization") == "Bearer " + self.internal_key

    async def _models(self, request):
        self._record(request)
        if not self._authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse(MODELS)

    async def _responses(self, request):
        body = await request.body()
        self._record(request, body)
        if not self._authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            options = json.loads(body)
        except ValueError:
            options = {}
        scenario = options.get("scenario", self.default_scenario)
        events, delay = options.get("events", 5), options.get("delay", 0.0)

        if scenario == "json":
            return JSONResponse({"id": "resp_1", "output_text": options.get("text", "pong ✓")})
        if scenario == "error":
            return JSONResponse({"error": {"message": "bad request from upstream", "code": "invalid"}},
                                status_code=options.get("status", 400))
        if scenario == "echo":
            return JSONResponse({"headers": dict(request.headers), "body_bytes": len(body)})
        if scenario == "slow_start":
            # Silent before any header. Polls so a caller that gives up is noticed promptly.
            deadline = time.monotonic() + options.get("wait", 0.5)
            while time.monotonic() < deadline:
                if await request.is_disconnected():
                    self.disconnected_at = time.monotonic()
                    self.disconnected.set()
                    return Response(status_code=499)
                await asyncio.sleep(0.02)
        if scenario == "cut_json":
            async def half_a_document():
                yield b'{"id":"resp_1","output_text":"PARTIAL-BODY-MARKER and then the connection'
                raise ConnectionError("synthetic upstream cut")

            return StreamingResponse(half_a_document(), media_type="application/json")

        async def stream():
            try:
                yield CREATED
                for index in range(events):
                    if delay:
                        await asyncio.sleep(delay)
                    yield delta(index, options.get("text"))
                    if scenario == "gap" and index == 0:
                        await asyncio.sleep(options.get("wait", 0.5))
                    if scenario == "cut" and index == 1:
                        raise ConnectionError("synthetic upstream cut")
                if scenario == "hang":
                    while True:
                        await asyncio.sleep(0.05)
                        yield b": ping\n\n"
                if scenario == "silent":
                    # Sends nothing more. A server only learns of a vanished client when it
                    # writes, so poll for the disconnect to observe it promptly.
                    while not await request.is_disconnected():
                        await asyncio.sleep(0.02)
                    self.disconnected_at = time.monotonic()
                    self.disconnected.set()
                    return
                if scenario != "no_terminal":
                    yield COMPLETED
            except (asyncio.CancelledError, GeneratorExit):
                self.disconnected_at = time.monotonic()
                self.disconnected.set()
                raise

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Access-Control-Allow-Origin": "*", "X-Cpa-Trace-Id": "trace-1"})


def html_error_app(status=502):
    """An endpoint that answers everything with an HTML error page, like a proxy block page."""
    async def anything(request):
        return Response("<html><body><h1>Blocked by policy</h1></body></html>",
                        status_code=status, media_type="text/html")
    return Starlette(routes=[Route("/{path:path}", anything, methods=["GET", "POST"])])
