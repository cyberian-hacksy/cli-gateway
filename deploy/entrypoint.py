"""Container entrypoint.

Renders the CLIProxyAPI config from the environment, then runs CLIProxyAPI on container
loopback and the remote bridge on the public port. If either exits, the container exits
and the platform restarts it.

The bridge is started only once a replay ledger exists. A ledger is never created here:
on a fresh or lost volume the bridge stays down until `python -m cgw init-ledger` is run
on purpose, because a silently recreated ledger would forget every consumed request.
"""
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path

from cgw import config, supervisor

TEMPLATE = Path("/opt/cgw/cliproxy.yaml")
RENDERED = Path("/run/cgw/cliproxy.yaml")
AUTH_DIR = Path("/data/cliproxy/auth")
CLIPROXY_DIR = "/opt/cliproxy"
KEY_PLACEHOLDER = "__CGW_CLIPROXY_KEY__"
KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,128}")


def render_config():
    key = os.environ.get("CGW_CLIPROXY_KEY", "")
    if not KEY_PATTERN.fullmatch(key):
        sys.exit("CGW_CLIPROXY_KEY must be 32-128 characters of [A-Za-z0-9_-]")
    if not Path("/data").is_mount():
        sys.exit("/data is not a mounted volume; refusing to start without persistent storage")
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(AUTH_DIR, 0o700)
    RENDERED.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(RENDERED.parent, 0o700)
    fd = os.open(RENDERED, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as rendered:
        rendered.write(TEMPLATE.read_text().replace(KEY_PLACEHOLDER, key))


def main():
    render_config()
    ledger_path = Path(os.environ.get("CGW_LEDGER_PATH") or config.DEFAULT_LEDGER_PATH)

    def start_cliproxy():
        # CLIProxyAPI reads its key from the rendered file, so it gets no CGW_* secrets.
        env = {name: value for name, value in os.environ.items() if not name.startswith("CGW_")}
        return subprocess.Popen(["./CLIProxyAPI", "-config", str(RENDERED), "-local-model"],
                                cwd=CLIPROXY_DIR, env=env)

    def start_bridge():
        return subprocess.Popen([sys.executable, "-m", "cgw", "remote"])

    announced = False

    def ledger_exists():
        nonlocal announced
        if ledger_path.is_file():
            return True
        if not announced:
            announced = True
            print("no replay ledger at %s: the bridge stays down until `python -m cgw init-ledger` is run"
                  % ledger_path, flush=True)
        return False

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    sys.exit(supervisor.supervise(start_cliproxy, start_bridge, ledger_exists, stop))


if __name__ == "__main__":
    main()
