"""A hostile network in miniature: sits between the two bridges.

It records every outer byte it sees, the way an HTTPS-inspecting proxy would after
decryption, and can tamper with the response stream in the ways the design must survive.
"""
import asyncio
import json

import httpx
from starlette.applications import Starlette
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

import wire_reference as ref


class TamperProxy:
    """Modes: pass, drop_last, cut_after:N, flip:N, swap:N, duplicate:N, inject:N, html, endless_line,
    endless_handshake.

    N counts response lines from 0, where line 0 is the stream header and line 1 the
    first record. The modes act on the encrypted exchange; handshakes pass through
    untouched, except in "html" mode, which answers everything with a block page.
    """

    def __init__(self, target_url, mode="pass"):
        self.target_url = target_url
        self.mode = mode
        self.requests = []           # (headers dict, body bytes) as seen on the wire
        self.paths = []              # the request path of each entry in `requests`
        self.response_bytes = b""    # everything sent back towards the client
        self.app = Starlette(routes=[Route("/{path:path}", self._handle, methods=["GET", "POST"])])

    @property
    def exchanges(self):
        """(headers, body) of the requests sent to the exchange endpoint."""
        return [entry for path, entry in zip(self.paths, self.requests) if path.endswith("/exchange")]

    @property
    def captured(self):
        """All outer traffic in both directions, plus base64-decoded payload fields."""
        blobs = [self.response_bytes]
        for headers, body in self.requests:
            blobs.append(json.dumps(headers).encode())
            blobs.append(body)
            try:
                blobs.append(ref.unb64(json.loads(body)["data"]))
            except (ValueError, KeyError, TypeError):
                pass
        for line in self.response_bytes.split(b"\n"):
            try:
                blobs.append(ref.unb64(json.loads(line)["data"]))
            except (ValueError, KeyError, TypeError):
                pass
        return b"\n".join(blobs)

    def _tamper(self, lines):
        name, _, argument = self.mode.partition(":")
        index = int(argument) if argument else None
        if name == "drop_last":
            return lines[:-1]
        if name == "flip":
            entry = json.loads(lines[index])
            raw = bytearray(ref.unb64(entry["data"]))
            raw[len(raw) // 2] ^= 0x01
            entry["data"] = ref.b64(bytes(raw))
            lines[index] = ref.dump(entry) + b"\n"
        elif name == "swap":
            lines[index], lines[index + 1] = lines[index + 1], lines[index]
        elif name == "duplicate":
            lines.insert(index, lines[index])
        elif name == "inject":
            forged = ref.dump({"seq": index - 1, "data": ref.b64(b"\x02" + b"INJECTED-PLAINTEXT" * 2)}) + b"\n"
            lines.insert(index, forged)
        return lines

    async def _handle(self, request):
        body = await request.body()
        self.requests.append((dict(request.headers), body))
        self.paths.append(request.url.path)
        tampering = self.mode != "pass" and request.url.path.endswith("/exchange")
        if self.mode == "endless_handshake" and request.url.path.endswith("/handshake"):
            async def endless_reply():
                while not await request.is_disconnected():
                    yield b"A" * 4096
                    await asyncio.sleep(0.001)

            return StreamingResponse(endless_reply(), status_code=200, media_type="application/json")
        if self.mode == "endless_line" and tampering:
            async def flood():
                # Stops when the reader gives up; the sleep lets the event loop see that.
                while not await request.is_disconnected():
                    yield b"A" * 4096
                    await asyncio.sleep(0.001)

            return StreamingResponse(flood(), status_code=200, media_type="application/x-ndjson")
        if self.mode == "html":
            page = b"<html><body><h1>Blocked by policy</h1></body></html>"
            self.response_bytes += page
            return Response(page, status_code=502, media_type="text/html")

        forward = {name: value for name, value in request.headers.items()
                   if name.lower() not in ("host", "content-length")}
        client = httpx.AsyncClient(timeout=30, trust_env=False)
        upstream = await client.send(
            client.build_request(request.method, self.target_url + request.url.path, headers=forward, content=body),
            stream=True)

        async def relay():
            try:
                if not tampering or upstream.status_code != 200:
                    async for chunk in upstream.aiter_raw():
                        self.response_bytes += chunk
                        yield chunk
                    return
                if self.mode.startswith("cut_after"):
                    limit, sent, pending = int(self.mode.partition(":")[2]), 0, b""
                    async for chunk in upstream.aiter_raw():
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            self.response_bytes += line + b"\n"
                            yield line + b"\n"
                            sent += 1
                            if sent >= limit:
                                raise ConnectionError("tamper proxy cut the connection")
                    return
                # The remaining modes need the whole stream to rearrange it.
                raw = b"".join([chunk async for chunk in upstream.aiter_raw()])
                for line in self._tamper(raw.splitlines(keepends=True)):
                    self.response_bytes += line
                    yield line
            finally:
                await upstream.aclose()
                await client.aclose()

        headers = {"content-type": upstream.headers.get("content-type", "application/octet-stream")}
        return StreamingResponse(relay(), status_code=upstream.status_code, headers=headers)
