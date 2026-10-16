"""Run the real Bash launcher with controlled process and identity boundaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

STUB = r'''
import json, os, sys, time
from pathlib import Path
state_path = Path(os.environ["CGW_TEST_STATE"])
state = json.loads(state_path.read_text())
mode = state["mode"]
def note(value):
    with open(os.environ["CGW_TEST_EVENTS"], "a") as f:
        f.write(value + "\n")
def save():
    temp = state_path.with_name("state-" + str(os.getpid()))
    temp.write_text(json.dumps(state))
    temp.replace(state_path)
def present():
    return not state.get("stopped") and mode != "absent" or state.get("started")
name = Path(sys.argv[0]).name
if name == "lsof":
    state["lookups"] = state.get("lookups", 0) + 1
    save()
    note("lookup")
    if mode == "no_pid" or not present(): sys.exit(1)
    print("12345\n54321" if mode == "ambiguous" else
          "54321" if mode == "changed" and state["lookups"] > 1 or state.get("replaced") else "12345")
elif len(sys.argv) > 1 and sys.argv[1] == "kill":
    note("signal " + " ".join(sys.argv[2:]))
    if sys.argv[2] == "-0": sys.exit(0 if present() or mode == "lingering" else 1)
    if mode == "replaced_after_term":
        # Another launcher's current bridge takes the port as soon as this one is freed.
        state["replaced"] = True
        save()
    elif mode != "sticky":
        state["stopped"] = True
        # The real listener closes on the server's next tick: one more probe still connects.
        state["closing"] = mode == "slow_close"
        save()
elif name == "fake-tool":
    assert os.environ.get("OPENAI_API_KEY") == "synthetic-local-key-0123456789abcdef"
    note("tool")
elif sys.argv[1:4] == ["-m", "cgw", "verify-bridge"]:
    state["probes"] = state.get("probes", 0) + 1
    save()
    if state.get("started") or state.get("replaced"):
        code = {"bad_replacement": 1, "old_replacement": 4}.get(mode, 0)
    elif not present(): code = 3
    elif mode == "replaced_meanwhile" and state["probes"] > 1: code = 0
    elif mode == "stopped_after_check" and state["probes"] == 2:
        # Another launcher stops the old bridge right after this one checked it again.
        state["stopped"] = True
        save()
        code = 4
    elif mode == "stopped_meanwhile":
        # Another launcher stops the old bridge right after this one first saw it.
        state["stopped"] = True
        save()
        code = 4
    elif mode == "current": code = 0
    elif mode == "impostor" or mode == "proof_changed" and state["probes"] > 1: code = 1
    else: code = 4
    note("verify " + str(code))
    sys.exit(code)
elif sys.argv[1:4] == ["-m", "cgw", "local"]:
    note("start")
    state["started"] = True
    save()
elif sys.argv[1] == "-c":
    code = sys.argv[2]
    if "import socket" in code:
        if state.get("closing"):
            state["closing"] = False
            save()
            sys.exit(0)
        sys.exit(0 if present() else 1)
    if "time.sleep" in code: time.sleep(.005)
    else:
        sys.argv = ["-c", *sys.argv[3:]]
        exec(code)
else:
    raise AssertionError(sys.argv)
'''


def launch(tmp_path, mode, *command):
    root = tmp_path / "launcher"
    (root / "bin").mkdir(parents=True)
    (root / ".venv" / "bin").mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / "bin" / "cgw", root / "bin" / "cgw")
    stub = "#!%s\n%s" % (sys.executable, STUB)
    for path in (root / ".venv" / "bin" / "python", root / "bin" / "lsof", root / "bin" / "fake-tool"):
        path.write_text(stub)
        path.chmod(0o755)
    state, events = tmp_path / "state.json", tmp_path / "events.txt"
    state.write_text(json.dumps({"mode": mode}))
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"port": 8318, "local_key": "synthetic-local-key-0123456789abcdef"}))
    bash_env = tmp_path / "bash-env"
    bash_env.write_text('kill() { "$CGW_TEST_STUB" kill "$@"; }\n')
    env = {**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"],
           "CGW_CONFIG": str(config), "CGW_TEST_STATE": str(state), "CGW_TEST_EVENTS": str(events),
           "CGW_TEST_STUB": str(root / ".venv" / "bin" / "python"), "BASH_ENV": str(bash_env)}
    result = subprocess.run(["bash", str(root / "bin" / "cgw"), *(command or ("run", "fake-tool"))],
                            env=env, capture_output=True, text=True, timeout=15)
    return result, events.read_text().splitlines() if events.exists() else []


@pytest.mark.parametrize("mode", ["current", "absent", "old"])
def test_launcher_starts_tool_only_after_current_identity(tmp_path, mode):
    result, events = launch(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    assert events[-2:] == ["verify 0", "tool"]
    if mode == "old":
        assert events.count("signal -TERM 12345") == 1
        assert events.index("verify 4") < events.index("signal -TERM 12345") < events.index("start")
    else:
        assert not any(line.startswith("signal") for line in events)


@pytest.mark.parametrize("mode", ["impostor", "ambiguous", "changed", "proof_changed", "no_pid"])
def test_unverified_or_unidentified_listener_is_never_stopped(tmp_path, mode):
    result, events = launch(tmp_path, mode)
    assert result.returncode != 0
    assert not any(line.startswith("signal") for line in events)
    assert "start" not in events and "tool" not in events


@pytest.mark.parametrize("mode", ["sticky", "bad_replacement"])
def test_failed_restart_never_launches_tool(tmp_path, mode):
    result, events = launch(tmp_path, mode)
    assert result.returncode != 0
    assert events.count("signal -TERM 12345") == 1
    assert "tool" not in events
    assert not any("KILL" in line or "-9" in line for line in events)


def test_old_bridge_still_finishing_a_stream_is_replaced_once_its_port_is_free(tmp_path):
    # TERM closes the listener at once; the process lives on while it finishes a stream.
    result, events = launch(tmp_path, "lingering")
    assert result.returncode == 0, result.stderr
    assert events.count("signal -TERM 12345") == 1
    assert events[-2:] == ["verify 0", "tool"]


def test_bridge_replaced_by_a_concurrent_launcher_is_used_as_it_is(tmp_path):
    result, events = launch(tmp_path, "replaced_meanwhile")
    assert result.returncode == 0, result.stderr
    assert not any(line.startswith("signal") for line in events)
    assert "start" not in events and events[-2:] == ["verify 0", "tool"]


def test_bridge_stopped_by_a_concurrent_launcher_is_started_again(tmp_path):
    result, events = launch(tmp_path, "stopped_meanwhile")
    assert result.returncode == 0, result.stderr
    assert not any(line.startswith("signal") for line in events)
    assert events[-3:] == ["start", "verify 0", "tool"]


def test_replacement_that_speaks_another_version_is_not_called_an_impostor(tmp_path):
    result, events = launch(tmp_path, "old_replacement")
    assert result.returncode != 0 and "tool" not in events
    assert "not this gateway's local bridge" not in result.stderr
    assert "another protocol version" in result.stderr


@pytest.mark.parametrize("mode", ["current", "old"])
def test_stop_signals_only_the_verified_listener(tmp_path, mode):
    result, events = launch(tmp_path, mode, "stop")
    assert result.returncode == 0, result.stderr
    assert "local bridge stopped" in result.stdout
    assert [line for line in events if line.startswith("signal")] == ["signal -TERM 12345"]


@pytest.mark.parametrize("mode", ["impostor", "changed", "no_pid"])
def test_stop_never_signals_an_unverified_or_unidentified_listener(tmp_path, mode):
    result, events = launch(tmp_path, mode, "stop")
    assert result.returncode != 0
    assert not any(line.startswith("signal") for line in events)


def test_stop_without_a_bridge_says_so(tmp_path):
    result, events = launch(tmp_path, "absent", "stop")
    assert result.returncode == 0 and "not running" in result.stdout
    assert not any(line.startswith("signal") for line in events)


def test_status_names_the_listener_pid(tmp_path):
    result, _ = launch(tmp_path, "current", "status")
    assert result.returncode == 0, result.stderr
    assert "(pid 12345)" in result.stdout


def test_listener_that_closes_between_two_probes_is_a_free_port(tmp_path):
    result, events = launch(tmp_path, "slow_close")
    assert result.returncode == 0, result.stderr
    assert events.count("signal -TERM 12345") == 1
    assert events[-3:] == ["start", "verify 0", "tool"]


def test_bridge_stopped_by_another_launcher_after_this_check_is_started_again(tmp_path):
    result, events = launch(tmp_path, "stopped_after_check")
    assert result.returncode == 0, result.stderr
    assert not any(line.startswith("signal") for line in events)
    assert events[-3:] == ["start", "verify 0", "tool"]


def test_current_bridge_that_took_the_freed_port_is_used(tmp_path):
    result, events = launch(tmp_path, "replaced_after_term")
    assert result.returncode == 0, result.stderr
    assert events.count("signal -TERM 12345") == 1
    assert "start" not in events and events[-2:] == ["verify 0", "tool"]
