"""Client for the gate-2 streaming probe.

Usage: python3 check_stream.py https://<service>.up.railway.app [seconds]

Reads /stream and reports whether lines arrived incrementally. Honours HTTPS_PROXY and
the system trust store, and never disables TLS verification. Standard library only.

Pass: every line arrives, the end marker arrives, and no gap between consecutive lines
exceeds MAX_GAP seconds (the server sends one line per second).
"""
import json
import sys
import time
import urllib.request

MAX_GAP = 5.0


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    base = sys.argv[1].rstrip("/")
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    url = "%s/stream?seconds=%d" % (base, seconds)
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})

    started = time.monotonic()
    arrivals, ended, last_report = [], False, 0.0
    with urllib.request.urlopen(request, timeout=30) as response:
        print("status %d, content-type %s" % (response.status, response.headers.get("Content-Type")))
        for raw in response:
            now = time.monotonic() - started
            record = json.loads(raw)
            if record.get("end"):
                ended = True
                break
            arrivals.append((now, record["seq"]))
            if now - last_report >= 30 or record["seq"] == 0:
                print("  t=%6.1fs  seq=%d" % (now, record["seq"]))
                last_report = now

    gaps = [b[0] - a[0] for a, b in zip(arrivals, arrivals[1:])]
    max_gap = max(gaps) if gaps else 0.0
    in_order = [seq for _, seq in arrivals] == list(range(len(arrivals)))
    first = arrivals[0][0] if arrivals else None
    total = arrivals[-1][0] if arrivals else 0.0

    print("lines received: %d of %d, in order: %s, end marker: %s" % (len(arrivals), seconds, in_order, ended))
    print("first line at %.1fs, last at %.1fs, largest gap %.1fs" % (first or 0.0, total, max_gap))

    problems = []
    if len(arrivals) != seconds:
        problems.append("missing lines")
    if not in_order:
        problems.append("lines out of order")
    if not ended:
        problems.append("no end marker (stream cut short)")
    if max_gap > MAX_GAP:
        problems.append("gap of %.1fs between lines (buffering on the path)" % max_gap)
    if seconds > 10 and total < seconds * 0.5:
        problems.append("lines arrived in a lump (whole stream in %.1fs)" % total)

    if problems:
        print("FAIL: " + "; ".join(problems))
        sys.exit(1)
    print("PASS: stream arrived incrementally")


if __name__ == "__main__":
    main()
