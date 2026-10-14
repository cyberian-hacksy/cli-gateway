"""Minimal supervision for the gateway container's two processes."""
import subprocess
import time


def _stop_all(processes, grace_seconds):
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + grace_seconds
    for process in processes:
        try:
            process.wait(timeout=max(deadline - time.monotonic(), 0))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def supervise(start_first, start_second, ready, stop, poll_seconds=1.0, grace_seconds=10.0):
    """Run the first process now and the second once `ready()` is true.

    Returns 0 when `stop` is set, and 1 as soon as either process exits by itself. Both
    processes are stopped before returning, so the container exits as a unit and the
    platform restarts it.
    """
    processes = [start_first()]
    try:
        while not stop.is_set():
            if any(process.poll() is not None for process in processes):
                return 1
            if len(processes) == 1 and ready():
                processes.append(start_second())
            stop.wait(poll_seconds)
        return 0
    finally:
        _stop_all(processes, grace_seconds)
