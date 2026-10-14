"""Gate-2 streaming probe. Throwaway: delete the Railway service once the gate passes.

GET /healthz            -> 200 "ok"
GET /stream?seconds=N   -> one NDJSON line per second for N seconds (default 300, max 600)

Each line carries its sequence number and the server send time, so the client can tell
whether lines arrived as they were sent or were buffered into a lump on the way.
Standard library only.
"""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MAX_SECONDS = 600


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def _chunk(self, data):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if url.path != "/stream":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        try:
            seconds = int(parse_qs(url.query).get("seconds", ["300"])[0])
        except ValueError:
            seconds = 300
        seconds = max(1, min(seconds, MAX_SECONDS))

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for seq in range(seconds):
                line = json.dumps({"seq": seq, "of": seconds, "sent": round(time.time(), 3)})
                self._chunk(line.encode() + b"\n")
                time.sleep(1)
            self._chunk(json.dumps({"end": True, "sent": round(time.time(), 3)}).encode() + b"\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            print("client disconnected mid-stream", flush=True)
            self.close_connection = True


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print("probe listening on 0.0.0.0:%d" % port, flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
