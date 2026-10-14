"""Container entrypoint.

Renders the CLIProxyAPI config from the environment, then runs CLIProxyAPI on container
loopback and the remote bridge on the public port. If either exits, the container exits
and the platform restarts it.

The bridge keeps nothing on disk: replay protection lives in memory and is meant to
vanish on restart. The volume at /data holds only CLIProxyAPI's ChatGPT login.
"""
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path

from cgw import supervisor

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

    def start_cliproxy():
        # CLIProxyAPI reads its key from the rendered file, so it gets no CGW_* secrets.
        env = {name: value for name, value in os.environ.items() if not name.startswith("CGW_")}
        return subprocess.Popen(["./CLIProxyAPI", "-config", str(RENDERED), "-local-model"],
                                cwd=CLIPROXY_DIR, env=env)

    def start_bridge():
        return subprocess.Popen([sys.executable, "-m", "cgw", "remote"])

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    sys.exit(supervisor.supervise(start_cliproxy, start_bridge, stop))


if __name__ == "__main__":
    main()
