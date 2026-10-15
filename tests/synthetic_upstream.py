"""Synthetic upstream standing in for CLIProxyAPI in bridge tests.

Speaks the Responses endpoint in detail, plus a stream in each other API format the gateway
carries (chat completions, Anthropic messages, Gemini), and records every call it receives.
The request body's "scenario" field selects the behaviour, so tests steer it without the
bridges needing to know.
"""
import asyncio
import json
import threading
import time
import urllib.parse

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

INTERNAL_KEY = "synthetic-internal-key-0123456789abcdef"
MANAGEMENT_KEY = "synthetic-management-key-0123456789abcd"
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


def _data(value):
    return ("data: %s\n\n" % (value if isinstance(value, str) else json.dumps(value, separators=(",", ":")))).encode()


# Each other format's stream, as events. The last event is the one that says it is done.
FORMAT_EVENTS = {
    "chat": [_data({"choices": [{"index": 0, "delta": {"content": "tok%d ✓ " % i}}]}) for i in range(3)]
            + [_data({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}), _data("[DONE]")],
    "messages": [sse("message_start", {"type": "message_start", "message": {"id": "msg_1"}})]
                + [sse("content_block_delta", {"type": "content_block_delta", "delta": {"text": "tok%d ✓ " % i}})
                   for i in range(3)]
                + [sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}}),
                   sse("message_stop", {"type": "message_stop"})],
    "gemini": [_data({"candidates": [{"content": {"parts": [{"text": "tok%d ✓ " % i}]}}]}) for i in range(3)]
              + [_data({"candidates": [{"content": {"parts": [{"text": "."}]}, "finishReason": "STOP"}]})],
}
FORMAT_PATHS = {"chat": "/v1/chat/completions", "messages": "/v1/messages",
                "gemini": "/v1beta/models/gemini-test:streamGenerateContent"}


class Upstream:
    def __init__(self, internal_key=INTERNAL_KEY, default_scenario="stream", models_delay=0.0,
                 management_key=MANAGEMENT_KEY, redirect_port=1455):
        self.internal_key = internal_key
        self.management_key = management_key
        self.redirect_port = redirect_port      # where a sign-in's redirect_uri points
        self.sign_in_sessions = {}              # state -> {"provider", "status"}
        self.sign_ins = {"codex-someone.json": {"provider": "codex", "email": "someone@example.com"}}
        self.default_scenario = default_scenario
        self.models_delay = models_delay
        self.calls = []                       # one dict per request received
        self.disconnected = threading.Event()  # set when a streaming client goes away early
        self.disconnected_at = None
        self.app = Starlette(routes=[
            Route("/v1/models", self._models, methods=["GET"]),
            Route("/v1/responses", self._responses, methods=["POST"]),
            Route("/v1/chat/completions", self._format("chat"), methods=["POST"]),
            Route("/v1/messages", self._format("messages"), methods=["POST"]),
            Route("/v1beta/models/{action}", self._format("gemini"), methods=["POST"]),
            Route("/v0/management/{action}", self._management, methods=["GET", "POST", "DELETE"]),
        ])

    @property
    def response_calls(self):
        return [call for call in self.calls if call["path"] == "/v1/responses"]

    def _record(self, request, body=b""):
        self.calls.append({"method": request.method, "path": request.url.path, "query": request.url.query,
                           "headers": dict(request.headers), "body": body, "at": time.monotonic()})

    async def _management(self, request):
        """A stand-in for the slice of CLIProxyAPI's management API the gateway lets admins use."""
        body = await request.body()
        self._record(request, body)
        if request.headers.get("authorization") != "Bearer " + self.management_key:
            return JSONResponse({"error": "invalid management key"}, status_code=401)
        action, params = request.path_params["action"], request.query_params
        if action.endswith("-auth-url") and request.method == "GET":
            provider = action[:-len("-auth-url")]
            state = "state-%d" % (len(self.sign_in_sessions) + 1)
            self.sign_in_sessions[state] = {"provider": provider, "status": "wait"}
            redirect = "http%%3A%%2F%%2Flocalhost%%3A%d%%2Fcallback" % self.redirect_port
            url = "https://sign-in.example.com/authorize?client_id=c&redirect_uri=%s&state=%s" % (redirect, state)
            return JSONResponse({"status": "ok", "url": url, "state": state})
        if action == "oauth-callback" and request.method == "POST":
            sent = json.loads(body)
            query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(sent.get("redirect_url", "")).query))
            session = self.sign_in_sessions.get(query.get("state"))
            if session is None:
                return JSONResponse({"status": "error", "error": "unknown or expired state"}, status_code=404)
            if query.get("code"):
                session["status"] = "ok"
                self.sign_ins["%s-new.json" % session["provider"]] = {"provider": session["provider"],
                                                                      "email": "new@example.com"}
            else:
                session["status"] = "error"
            return JSONResponse({"status": "ok"})
        if action == "get-auth-status" and request.method == "GET":
            session = self.sign_in_sessions.get(params.get("state"))
            if session is None:
                return JSONResponse({"status": "error", "error": "unknown or expired state"})
            return JSONResponse({"status": session["status"]} if session["status"] != "error"
                                else {"status": "error", "error": "Bad request"})
        if action == "auth-files" and request.method == "GET":
            files = [{"name": name, "provider": entry["provider"], "email": entry["email"], "status": "active",
                      "id_token": "SECRET-ID-TOKEN", "path": "/data/cliproxy/auth/" + name}
                     for name, entry in sorted(self.sign_ins.items())]
            return JSONResponse({"observed_at": "2026-10-14T00:00:00Z", "files": files})
        if action == "auth-files" and request.method == "DELETE":
            if params.get("all"):
                self.sign_ins.clear()
                return JSONResponse({"status": "ok"})
            removed = self.sign_ins.pop(params.get("name", ""), None)
            return JSONResponse({"status": "ok"} if removed else {"error": "not found"}, status_code=200 if removed else 404)
        return JSONResponse({"error": "not here"}, status_code=404)

    def _format(self, name):
        async def handler(request):
            body = await request.body()
            self._record(request, body)
            if not self._authorized(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            try:
                options = json.loads(body)
            except ValueError:
                options = {}
            scenario = options.get("scenario", "stream")
            if scenario == "echo":
                return JSONResponse({"path": request.url.path, "query": request.url.query,
                                     "headers": dict(request.headers)})

            async def stream():
                for index, event in enumerate(FORMAT_EVENTS[name]):
                    if scenario == "cut" and index == len(FORMAT_EVENTS[name]) - 1:
                        raise ConnectionError("synthetic upstream cut before the last event")
                    yield event
                    await asyncio.sleep(options.get("delay", 0.0))

            return StreamingResponse(stream(), media_type="text/event-stream")
        return handler

    def _authorized(self, request):
        return request.headers.get("authorization") == "Bearer " + self.internal_key

    async def _models(self, request):
        self._record(request)
        if self.models_delay:
            await asyncio.sleep(self.models_delay)
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
