"""Process supervision for the gateway container, exercised with real child processes."""
import subprocess
import sys
import threading
import time

from cgw import supervisor
from harness import wait_until

SLEEPER = [sys.executable, "-c", "import time; time.sleep(60)"]
STUBBORN = [sys.executable, "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('up', flush=True); time.sleep(60)"]


def exits_with(code, after=0.0):
    return [sys.executable, "-c", "import sys, time; time.sleep(%r); sys.exit(%d)" % (after, code)]


class Run:
    """Runs supervisor.supervise in a thread and records what it started."""

    def __init__(self, first, second, grace_seconds=5.0):
        self.started, self.result, self.error = [], None, None
        self.stop = threading.Event()

        def starter(command):
            def start():
                process = subprocess.Popen(command, stdout=subprocess.PIPE)
                self.started.append(process)
                return process
            return start

        def target():
            try:
                self.result = supervisor.supervise(
                    starter(first), starter(second), self.stop, poll_seconds=0.02, grace_seconds=grace_seconds)
            except BaseException as error:  # surfaced by join(), never swallowed by the thread
                self.error = error

        self.thread = threading.Thread(target=target)
        self.thread.start()

    def join(self, timeout=10):
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "supervisor did not return"
        if self.error is not None:
            raise self.error
        return self.result

    def all_dead(self):
        return bool(self.started) and all(process.poll() is not None for process in self.started)


def test_both_processes_start_at_once():
    run = Run(SLEEPER, SLEEPER)
    wait_until(lambda: len(run.started) == 2)
    run.stop.set()
    assert run.join() == 0
    assert run.all_dead()


def test_when_the_first_process_dies_the_second_is_stopped_and_the_exit_is_a_failure():
    run = Run(exits_with(3, after=0.3), SLEEPER)
    assert run.join() != 0
    assert len(run.started) == 2 and run.all_dead()


def test_when_the_second_process_dies_the_first_is_stopped_and_the_exit_is_a_failure():
    run = Run(SLEEPER, exits_with(0, after=0.3))
    assert run.join() != 0
    assert len(run.started) == 2 and run.all_dead()


def test_stop_request_ends_both_processes_cleanly():
    run = Run(SLEEPER, SLEEPER)
    wait_until(lambda: len(run.started) == 2)
    run.stop.set()
    assert run.join() == 0
    assert run.all_dead()


def test_process_that_ignores_termination_is_killed_after_the_grace_period():
    run = Run(STUBBORN, SLEEPER, grace_seconds=0.3)
    wait_until(lambda: len(run.started) == 2)
    run.started[0].stdout.readline()  # the child has installed its signal handler
    started = time.monotonic()
    run.stop.set()
    run.join()
    assert run.all_dead()
    assert time.monotonic() - started < 3.0
