"""Run focused single-rule weakenings on temporary copies, never the working tree.

    .venv/bin/python tests/check_v3_mutations.py
    .venv/bin/python tests/check_v3_mutations.py --list

A kill requires an assertion/test failure, not a syntax error, collection error or timeout.
"""
import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class Mutation:
    name: str
    file: str
    before: str
    after: str
    test: str


MUTATIONS = [
    Mutation("lenient-unpadding", "protocol.py", "if len(data) != size_for(marker):", "if False:",
             "tests/test_protocol_padding.py::test_noncanonical_padding_is_rejected"),
    *[Mutation("unpadded-" + kind.lower(), "protocol.py", "pad_response(bytes([record_type]) + payload)",
               "(bytes([record_type]) + payload if record_type == %s else pad_response(bytes([record_type]) + payload))" % kind,
               "tests/test_protocol_v3.py::test_small_record_types_have_equal_ciphertext_sizes")
      for kind in ("HEARTBEAT", "END")],
    Mutation("no-request-floor", "protocol.py", "max(unpadded_length + 1, 4096)", "max(unpadded_length + 1, 1)",
             "tests/test_protocol_padding.py::test_request_bucket_includes_marker_and_floor"),
    Mutation("admission-early-exit", "protocol.py", "matches.append(kid)", "matches.append(kid)\n                break",
             "tests/test_protocol_v3.py::test_admission_checks_every_key_without_rekeying"),
    Mutation("request-split-copies", "protocol.py",
             "view = memoryview(plaintext)[:_unpadded_length(plaintext, request_padded_size)]",
             "view = memoryview(unpad_request(plaintext))",
             "tests/test_protocol_padding.py::test_splitting_a_large_decrypted_request_copies_its_body_once"),
    Mutation("aad-ignores-ts", "protocol.py", 'struct.pack(">Q", ts), bytes([direction])',
             'struct.pack(">Q", 0), bytes([direction])',
             "tests/test_protocol_request.py::test_changed_timestamp_is_rejected"),
    Mutation("no-session-owner", "protocol.py", "(session.kid, session.hid) != (kid, hid)", "session.hid != hid",
             "tests/test_protocol_v3.py::test_request_owner_must_match_admission"),
    Mutation("handshake-ignores-places", "remote_bridge.py",
             'return reject(429, "busy", "busy_at_handshake")', 'pass',
             "tests/test_remote_bridge.py::test_a_handshake_is_refused_as_busy_while_every_place_is_taken"),
    Mutation("no-config-key-cap", "config.py",
             "if sum(name.startswith((CLIENT_PREFIX, ADMIN_PREFIX)) for name in names) > protocol.MAX_KEYS:", "if False:",
             "tests/test_key_capacity.py::test_remote_key_limit_counts_clients_and_admins"),
    Mutation("no-app-key-cap", "remote_bridge.py", "if len(keys) > protocol.MAX_KEYS:", "if False:",
             "tests/test_key_capacity.py::test_app_rejects_65_keys_and_duplicate_psks"),
    Mutation("overwrite-pending-hid", "remote_bridge.py", 'if key in self._sessions:', 'if False:',
             "tests/test_v3_sessions.py::test_a_live_duplicate_is_refused_without_replacing_the_session"),
    Mutation("sessions-ignore-owner", "remote_bridge.py", "key = (session.kid, session.hid)", "key = session.hid",
             "tests/test_v3_sessions.py::test_another_key_naming_a_pending_handshake_gets_its_own_session"),
    *[Mutation(kind + "-bypasses-grid", "relay.py", "if delay > 0:",
               "if delay > 0 and not (backlog._items and backlog._items[0][0] == %r):" % kind,
               "tests/test_relay.py::test_ready_control_record_waits_for_a_tick") for kind in ("meta", "end")],
    Mutation("relative-grid", "relay.py",
             "tick = max(tick + 1, math.floor((monotonic() - started) / grid_seconds) + 1)",
             "started, tick = monotonic(), 1",
             "tests/test_relay.py::test_slow_consumer_keeps_grid_anchor_and_skips_missed_ticks"),
    Mutation("deadline-discards-reply", "relay.py", "if tick >= deadline_tick and not finished:", "if tick >= deadline_tick:",
             "tests/test_relay.py::test_a_reply_that_finished_is_delivered_at_the_deadline_tick"),
    Mutation("late-idle-wakeup-skips-tick", "relay.py", "tick = min(due, first_tick_at(monotonic()))",
             "tick = first_tick_at(monotonic())",
             "tests/test_relay.py::test_an_idle_wakeup_that_is_late_still_takes_the_due_tick"),
    Mutation("busy-passed-on", "local_bridge.py", "remaining = deadline - time.monotonic()", "remaining = 0",
             "tests/test_local_waiting.py::test_a_busy_handshake_is_sent_again"),
    Mutation("busy-exchange-sent-again", "local_bridge.py",
             "                return _gateway_error(outer_error_code(outer.status_code, preview))",
             "                if outer_error_code(outer.status_code, preview) == \"busy\":\n"
             "                    raise _Busy\n"
             "                return _gateway_error(outer_error_code(outer.status_code, preview))",
             "tests/test_local_waiting.py::test_a_busy_exchange_is_never_sent_again"),
    Mutation("user-agent-sent", "local_bridge.py", 'del client.headers["user-agent"]', "pass",
             "tests/test_local_bridge.py::test_the_outer_requests_name_no_client_software"),
    Mutation("body-end-not-read", "local_bridge.py", "            await _read_to_end(lines)", "            pass",
             "tests/test_local_bridge.py::test_consecutive_requests_share_one_connection_to_the_gateway"),
    Mutation("stale-handshake-not-retried", "local_bridge.py",
             "                session, refused = await self._handshake(client, ts)\n            if refused",
             "                raise\n            if refused",
             "tests/test_local_waiting.py::test_a_handshake_on_a_connection_the_gateway_had_just_closed_is_sent_again"),
    Mutation("no-local-queue", "local_bridge.py", "self._places = asyncio.Semaphore(protocol.MAX_IN_FLIGHT)",
             "self._places = asyncio.Semaphore(1000)",
             "tests/test_local_waiting.py::test_no_more_requests_go_to_the_gateway_at_once_than_it_has_places"),
    Mutation("stream-gives-up-its-place-early", "local_bridge.py", "handed_over = place.handed_over = True",
             "handed_over = True", "tests/test_local_waiting.py::test_an_event_stream_keeps_its_place_until_it_ends"),
    Mutation("version-bypasses-proof", "cli.py", "if not genuine:",
             'if not genuine and payload.get("protocol") != protocol.VERSION:',
             "tests/test_bridge_version.py::test_claimed_version_with_bad_identity_is_an_impostor"),
]


def run_tests(root, nodes, env, report):
    return subprocess.run([sys.executable, "-m", "pytest", "-q", *nodes, "--junitxml", str(report)],
                          cwd=root, env=env, capture_output=True, text=True, timeout=60)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--mutation", choices=[item.name for item in MUTATIONS])
    args = parser.parse_args(argv)
    selected = [item for item in MUTATIONS if not args.mutation or item.name == args.mutation]
    if args.list:
        print("\n".join(item.name for item in selected))
        return 0
    source = Path(__file__).resolve().parents[1]
    failures = []
    with tempfile.TemporaryDirectory(prefix="cgw-v3-mutations-") as directory:
        root = Path(directory)
        for name in ("src", "tests"):
            shutil.copytree(source / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(source / "pyproject.toml", root / "pyproject.toml")
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(root / "src"), str(root / "tests")])}
        subprocess.run([sys.executable, "-c",
                        "import cgw, pathlib; assert pathlib.Path(cgw.__file__).resolve().is_relative_to(pathlib.Path('src').resolve())"],
                       cwd=root, env=env, check=True)
        report = root / "report.xml"
        baseline = run_tests(root, sorted({item.test for item in selected}), env, report)
        if baseline.returncode:
            print(baseline.stdout, baseline.stderr)
            return 1
        for item in selected:
            path = root / "src" / "cgw" / item.file
            original = path.read_text()
            if original.count(item.before) != 1:
                failures.append(item.name)
                print("INVALID:", item.name, "replacement is not unique")
                continue
            mutated = original.replace(item.before, item.after, 1)
            compile(mutated, str(path), "exec")
            path.write_text(mutated)
            # Avoid timestamp/size-based bytecode cache reuse between isolated runs.
            shutil.rmtree(path.parent / "__pycache__", ignore_errors=True)
            try:
                result = run_tests(root, [item.test], env, report)
                document = ET.parse(report)
                assertions = document.findall(".//failure")
                # Runtime exceptions are failures in JUnit too; they do not prove the
                # safeguard's behavioral assertion caught this weakening.
                behavioral = assertions and all(node.get("message", "").startswith(
                    ("assert ", "AssertionError", "Failed: DID NOT RAISE", "DID NOT RAISE")) for node in assertions)
                killed = result.returncode == 1 and behavioral and not document.findall(".//error")
                if not killed:
                    failures.append(item.name)
                    print("SURVIVED/INVALID:", item.name, result.stdout, result.stderr)
                else:
                    print("KILLED:", item.name, flush=True)
            except subprocess.TimeoutExpired:
                failures.append(item.name)
                print("INVALID:", item.name, "test timed out")
            finally:
                path.write_text(original)
                shutil.rmtree(path.parent / "__pycache__", ignore_errors=True)
    print("%d/%d mutations caught" % (len(selected) - len(failures), len(selected)))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
