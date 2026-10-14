"""In-container check: one streamed request through CLIProxyAPI on loopback.

Run inside the gateway container:
    python3 /opt/cgw/egress_check.py [model]

Proves that this container's outbound IPs are accepted upstream. Prints the model count,
the HTTP status, SSE event timing and the short reply. Exits 0 only if the terminal
`response.completed` event arrives. Standard library only.
"""
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8317"
RENDERED = Path("/run/cgw/cliproxy.yaml")
PROMPT = "Reply with exactly: pong from the gateway container"


def internal_key():
    match = re.search(r'api-keys:\s*\n\s*-\s*"([^"]+)"', RENDERED.read_text())
    if not match:
        sys.exit("could not read the internal key from %s" % RENDERED)
    return match.group(1)


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "gpt-6-astra"
    auth = {"Authorization": "Bearer " + internal_key()}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    with opener.open(urllib.request.Request(BASE + "/v1/models", headers=auth), timeout=20) as response:
        models = sorted(entry["id"] for entry in json.load(response)["data"])
    print("models served: %d, %s listed: %s" % (len(models), model, model in models))
    if not models:
        sys.exit("FAIL: no models; is a credential file present in the auth directory?")

    body = {"model": model, "stream": True, "reasoning": {"effort": "low"},
            "input": [{"role": "user", "content": PROMPT}]}
    request = urllib.request.Request(
        BASE + "/v1/responses", data=json.dumps(body).encode(),
        headers={**auth, "Content-Type": "application/json", "Accept": "text/event-stream"})
    started = time.monotonic()
    try:
        response = opener.open(request, timeout=180)
    except urllib.error.HTTPError as error:
        print("status %d: %s" % (error.code, error.read()[:800].decode("utf-8", "replace")))
        sys.exit("FAIL: upstream request was rejected")

    events, text, completed, event = [], [], False, None
    with response:
        print("status %d, content-type %s" % (response.status, response.headers.get("Content-Type")))
        for raw in response:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("event:"):
                event = line[6:].strip()
                events.append((round(time.monotonic() - started, 2), event))
            elif line.startswith("data:") and event:
                if event == "response.output_text.delta":
                    try:
                        text.append(json.loads(line[5:]).get("delta", ""))
                    except ValueError:
                        pass
                elif event == "response.completed":
                    completed = True
                elif event in ("response.failed", "response.incomplete", "error"):
                    print("failure event %s: %s" % (event, line[5:].strip()[:800]))

    if events:
        print("events: %d, first %s at %.2fs, last %s at %.2fs"
              % (len(events), events[0][1], events[0][0], events[-1][1], events[-1][0]))
    print("reply: %r" % "".join(text)[:200])
    if not completed:
        sys.exit("FAIL: stream ended without response.completed")
    print("PASS: real model output through this container's egress")


if __name__ == "__main__":
    main()
