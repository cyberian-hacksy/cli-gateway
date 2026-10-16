"""Synthetic loopback measurements; no provider access or real credentials.

    .venv/bin/python tests/benchmark_v3.py --runs 40

Bytes count HTTP bodies at the capture proxy, excluding HTTP/TLS framing. Latency
includes the capture proxy (which opens an upstream HTTP connection per request).
Percentiles use nearest rank; added latency is paired gateway minus direct time.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import math
import statistics
import time

import httpx

from cgw import local_bridge, protocol, remote_bridge
from harness import ServerThread
from synthetic_upstream import INTERNAL_KEY, Upstream, expected_stream
from tamper_proxy import TamperProxy


def summary(values):
    ordered = sorted(values)
    return {"p50": round(ordered[math.ceil(len(ordered) * .5) - 1], 3),
            "p95": round(ordered[math.ceil(len(ordered) * .95) - 1], 3)}


def request_body(options):
    options = {**options, "input": ""}
    dump = lambda: json.dumps(options, separators=(",", ":")).encode()
    options["input"] = "x" * (70_000 - len(dump()))
    body = dump()
    assert len(body) == 70_000
    return body


def measure(client, url, key, body, expected, streaming):
    begin, first, received = time.perf_counter(), None, bytearray()
    with client.stream("POST", url + "/v1/responses", content=body,
                       headers={"authorization": "Bearer " + key, "content-type": "application/json"}) as response:
        response.raise_for_status()
        for chunk in response.iter_raw():
            received.extend(chunk)
            if first is None and (not streaming or b"\n\n" in received):
                first = time.perf_counter() - begin
    total = time.perf_counter() - begin
    assert bytes(received) == expected
    assert first is not None
    return {"first_ms": first * 1000, "total_ms": total * 1000}


def admission_cost():
    results = {}
    for count in (1, 16, 64):
        raw = {str(i): protocol.derive_admission_key(hashlib.sha256(str(i).encode()).digest())
               for i in range(count)}
        keys = protocol.AdmissionKeys(raw)  # as the gateway holds them
        tag = protocol.seal_admission(raw[str(count - 1)], b"r" * 32, 1800000000, 70000)
        samples = []
        for _ in range(40):
            start = time.perf_counter_ns()
            for _ in range(100):
                protocol.open_admission(tag, keys, 70000)
            samples.append((time.perf_counter_ns() - start) / 100_000)
        results[str(count)] = summary(samples)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=40)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    cases = [
        ("2KB", {"scenario": "bytes", "size": 2000}, b"x" * 2000),
        ("1.3MB", {"scenario": "bytes", "size": 1_300_000}, b"x" * 1_300_000),
        ("stream", {"scenario": "stream", "events": 20, "delay": .01}, expected_stream(20)),
    ]
    result = {"runs": args.runs, "percentile": "nearest rank", "request_bytes": 70000,
              "transport": "loopback HTTP with capture proxy; no TLS", "cases": {}}
    with ExitStack() as stack:
        upstream = Upstream()
        direct = stack.enter_context(ServerThread(upstream.app)).url
        psk, local_key = bytes(range(32)), "benchmark-local-key-0123456789abcdef"
        remote = stack.enter_context(ServerThread(remote_bridge.create_app(remote_bridge.Settings(
            keys={"benchmark": psk}, upstream_url=direct, upstream_key=INTERNAL_KEY)))).url
        proxy = TamperProxy(remote)
        captured = stack.enter_context(ServerThread(proxy.app)).url
        gateway = stack.enter_context(ServerThread(local_bridge.create_app(local_bridge.Settings(
            remote_url=captured, kid="benchmark", psk=psk, local_key=local_key)))).url
        client = stack.enter_context(httpx.Client(trust_env=False, timeout=20))
        for name, options, expected in cases:
            body = request_body(options)
            timings = {"direct": [], "gateway": [], "added": []}
            sizes = {"requests": [], "responses": []}
            # One warm-up pair, then alternate ordering to reduce order bias.
            for run in range(-1, args.runs):
                measured = {}
                for route in (("direct", "gateway") if run % 2 else ("gateway", "direct")):
                    proxy.requests.clear()
                    proxy.paths.clear()
                    proxy.responses.clear()
                    proxy.response_bytes = b""
                    upstream.calls.clear()
                    measured[route] = measure(client, direct if route == "direct" else gateway,
                                              INTERNAL_KEY if route == "direct" else local_key,
                                              body, expected, name == "stream")
                    if route == "gateway" and run >= 0:
                        sizes["requests"].append(sum(len(raw) for _, raw in proxy.requests))
                        sizes["responses"].append(len(proxy.response_bytes))
                if run >= 0:
                    for route in ("direct", "gateway"):
                        timings[route].append(measured[route])
                    timings["added"].append({key: measured["gateway"][key] - measured["direct"][key]
                                             for key in ("first_ms", "total_ms")})
            entry = {route: {key: summary([row[key] for row in rows]) for key in ("first_ms", "total_ms")}
                     for route, rows in timings.items()}
            entry["upstream_response_bytes"] = len(expected)
            entry["outer_body_bytes"] = {direction: {"min": min(values), "median": statistics.median(values),
                                                     "max": max(values)} for direction, values in sizes.items()}
            result["cases"][name] = entry
            print(json.dumps({name: entry}), flush=True)
    result["admission_us_per_check"] = admission_cost()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
