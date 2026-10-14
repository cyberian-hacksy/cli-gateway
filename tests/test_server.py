"""The public listener closes connections that do not deliver a request head in time.

Without this, a connection that sends nothing is held forever and counts toward the
connection cap, so idle anonymous connections could fill it and lock everyone out.
"""
import asyncio
import socket
import time

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, StreamingResponse
from starlette.routing import Route

from cgw import server
from harness import ServerThread

HEAD_TIMEOUT = 0.5


class QuickProtocol(server.HeadTimeoutProtocol):
    head_timeout = HEAD_TIMEOUT


async def hello(request):
    return PlainTextResponse("hello")


async def slow_stream(request):
    async def chunks():
        for index in range(6):
            await asyncio.sleep(0.25)
            yield b"chunk %d\n" % index
    return StreamingResponse(chunks(), media_type="text/plain")


APP = Starlette(routes=[Route("/", hello), Route("/stream", slow_stream)])
REQUEST = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


@pytest.fixture
def listener():
    with ServerThread(APP, http=QuickProtocol) as running:
        yield running


def connect(url):
    host, port = url.removeprefix("http://").split(":")
    return socket.create_connection((host, int(port)), timeout=5)


def closed_within(connection, seconds):
    """True if the server closes the connection within `seconds`."""
    connection.settimeout(seconds)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                return True
    except (socket.timeout, TimeoutError):
        return False
    except ConnectionResetError:
        return True


def read_response(connection):
    connection.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data or not data.endswith((b"hello", b"0\r\n\r\n")):
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def test_connection_that_sends_nothing_is_closed_after_the_head_timeout(listener):
    with connect(listener.url) as connection:
        started = time.monotonic()
        assert closed_within(connection, 3.0)
        assert HEAD_TIMEOUT * 0.8 < time.monotonic() - started < HEAD_TIMEOUT + 1.0


def server_has_closed(connection):
    connection.setblocking(False)
    try:
        return connection.recv(4096) == b""
    except BlockingIOError:
        return False
    except OSError:
        return True
    finally:
        connection.setblocking(True)


def test_trickled_request_head_does_not_extend_the_deadline(listener):
    # One byte every 0.1 s for three seconds, far beyond the deadline. A server that pushed
    # the deadline back on each byte would keep the connection open the whole time.
    head = b"GET / HTTP/1.1\r\nX-Padding: " + b"a" * 100
    with connect(listener.url) as connection:
        started, closed_at = time.monotonic(), None
        for byte in head[:30]:
            if server_has_closed(connection):
                closed_at = time.monotonic() - started
                break
            try:
                connection.sendall(bytes([byte]))
            except OSError:
                closed_at = time.monotonic() - started
                break
            time.sleep(0.1)
        assert closed_at is not None, "the connection stayed open while the head trickled in"
        assert closed_at < HEAD_TIMEOUT + 0.6


def test_a_complete_request_is_served(listener):
    with connect(listener.url) as connection:
        connection.sendall(REQUEST)
        assert read_response(connection).startswith(b"HTTP/1.1 200")


def test_a_response_longer_than_the_head_timeout_is_not_cut_off(listener):
    with connect(listener.url) as connection:
        connection.sendall(b"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n")
        response = read_response(connection)
    assert b"chunk 5" in response and response.endswith(b"0\r\n\r\n")


def test_a_kept_alive_connection_can_send_another_request(listener):
    with connect(listener.url) as connection:
        connection.sendall(REQUEST)
        assert read_response(connection).startswith(b"HTTP/1.1 200")
        time.sleep(HEAD_TIMEOUT * 1.5)  # idle between requests is covered by the keep-alive timeout
        connection.sendall(REQUEST)
        assert read_response(connection).startswith(b"HTTP/1.1 200")


def test_a_stalled_second_request_head_is_closed(listener):
    with connect(listener.url) as connection:
        connection.sendall(REQUEST)
        assert read_response(connection).startswith(b"HTTP/1.1 200")
        connection.sendall(b"GET / HTTP/1.1\r\nHo")
        started = time.monotonic()
        assert closed_within(connection, 3.0)
        assert time.monotonic() - started < HEAD_TIMEOUT + 1.0


def test_idle_connections_cannot_hold_the_connection_cap():
    with ServerThread(APP, http=QuickProtocol, limit_concurrency=4) as capped:
        idle = [connect(capped.url) for _ in range(4)]
        try:
            time.sleep(0.1)
            with connect(capped.url) as connection:
                connection.sendall(REQUEST)
                assert read_response(connection).startswith(b"HTTP/1.1 503")
            time.sleep(HEAD_TIMEOUT + 0.5)
            with connect(capped.url) as connection:
                connection.sendall(REQUEST)
                assert read_response(connection).startswith(b"HTTP/1.1 200")
        finally:
            for connection in idle:
                connection.close()


def test_default_head_timeout_is_ten_seconds():
    assert server.HeadTimeoutProtocol.head_timeout == 10.0
