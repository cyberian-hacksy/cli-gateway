"""Deterministic grid scheduling: no wall-clock sleeps or network jitter."""
import asyncio

import pytest

from cgw import remote_bridge
from cgw.relay import BACKLOG_BYTES, Backlog, grid_batches


class Clock:
    def __init__(self, backlog, events):
        self.now = 0.0
        self.backlog = backlog
        self.events = list(events)
        self.sleeps = []
        self.waits = []

    def _deliver(self):
        while self.events and self.events[0][0] <= self.now + 1e-6:
            _, item = self.events.pop(0)
            self.backlog.put_nowait(item)

    async def sleep(self, delay):
        assert delay > 0, "the grid must not spin or replay missed ticks"
        self.sleeps.append(delay)
        self.now += delay
        self._deliver()

    async def wait(self, ready, timeout):
        """An idle wait ends when the next item arrives, or after the timeout."""
        assert timeout > 0 and not ready.is_set()
        self.waits.append(timeout)
        arrival = self.events[0][0] if self.events else float("inf")
        self.now = max(self.now, min(self.now + timeout, arrival))
        self._deliver()


def collect(events, *, heartbeat=15, overall=1, stalled=False, base=0.0, write=0.0):
    """Batches with their times since the start. `base` is the monotonic clock at the
    start, and `write` how long the consumer takes to send each batch."""
    async def work():
        backlog = Backlog()
        clock = Clock(backlog, [(base + t, item) for t, item in events])
        clock.now = base
        output = []
        async for batch in grid_batches(backlog, started=base, grid_seconds=.05, heartbeat_seconds=heartbeat,
                                        overall_seconds=overall, monotonic=lambda: clock.now,
                                        sleep=clock.sleep, wait=clock.wait):
            output.append((clock.now - base, batch))
            if stalled and len(output) == 1:
                clock.now = base + .181
            clock.now += write
        return output, clock
    return asyncio.run(work())


def test_burst_is_merged_and_output_only_leaves_on_ticks():
    output, _ = collect([(.001, ("meta", 200, {})), (.020, ("data", b"one")),
                         (.049, ("data", b"two")), (.051, ("data", b"three")), (.052, ("end",))])
    assert [t for t, _ in output] == pytest.approx([.05, .10])
    assert [b for _, b in output] == [[("meta", 200, {}), ("data", b"onetwo")],
                                     [("data", b"three"), ("end",)]]


def test_many_small_chunks_within_one_tick_leave_on_that_tick():
    # One item per upstream HTTP chunk: a count-bounded queue would hold most of these back.
    events = [(.001, ("meta", 200, {}))]
    events += [(.002 + i * .00002, ("data", b"x" * 27)) for i in range(2000)]
    events += [(.045, ("end",))]
    output, _ = collect(events)
    assert [t for t, _ in output] == pytest.approx([.05])
    assert output[0][1] == [("meta", 200, {}), ("data", b"x" * 16384), ("data", b"x" * 16384),
                            ("data", b"x" * 16384), ("data", b"x" * 4848), ("end",)]


def test_idle_ticks_are_silent_and_heartbeat_is_on_grid():
    output, _ = collect([(15.051, ("error", "upstream_failed"))], overall=16)
    assert [t for t, _ in output] == pytest.approx([15, 15.10])
    assert [b for _, b in output] == [[("heartbeat",)], [("error", "upstream_failed")]]


def test_heartbeat_resets_after_any_record():
    output, _ = collect([(.09, ("meta", 200, {})), (.19, ("data", b"x")),
                         (.451, ("end",))], heartbeat=.15)
    assert [t for t, b in output if b == [("heartbeat",)]] == pytest.approx([.35])


def test_the_time_a_write_takes_does_not_move_the_heartbeat():
    output, _ = collect([(.01, ("meta", 200, {}))], heartbeat=.3, write=.002)
    assert [t for t, _ in output] == pytest.approx([.05, .35, .65, .95, 1.0])
    assert [b for _, b in output][1:] == [[("heartbeat",)]] * 3 + [[("error", "upstream_timeout")]]


def test_ticks_stay_exact_on_a_host_with_a_large_monotonic_clock():
    # About 115 days of uptime: sums at this size round by more than a nanosecond.
    output, _ = collect([(.01, ("meta", 200, {}))], heartbeat=.1, overall=.3, base=1e7)
    assert [t for t, _ in output] == pytest.approx([.05, .15, .25, .30], abs=1e-6)
    assert output[-1][1] == [("error", "upstream_timeout")]


def test_an_idle_stream_does_not_wake_on_every_tick():
    output, clock = collect([(.01, ("meta", 200, {})), (40.01, ("end",))], overall=60)
    assert [t for t, _ in output] == pytest.approx([.05, 15.05, 30.05, 40.05])
    assert [b for _, b in output][1:3] == [[("heartbeat",)], [("heartbeat",)]]
    assert len(clock.sleeps) + len(clock.waits) <= 10


def test_an_idle_wakeup_that_is_late_still_takes_the_due_tick():
    async def work():
        backlog, now = Backlog(), [0.0]
        backlog.put_nowait(("meta", 200, {}))

        async def sleep(delay):
            now[0] += delay

        async def wait(ready, timeout):
            now[0] += timeout + .003  # timer latency

        output = []
        async for batch in grid_batches(backlog, started=0, grid_seconds=.05, heartbeat_seconds=.1,
                                        overall_seconds=.32, monotonic=lambda: now[0], sleep=sleep, wait=wait):
            output.append((now[0], batch))
        assert [t for t, _ in output] == pytest.approx([.05, .153, .253, .353])
        assert [b for _, b in output][1:] == [[("heartbeat",)], [("heartbeat",)], [("error", "upstream_timeout")]]
    asyncio.run(work())


def test_data_splits_at_16k_and_terminal_follows_last_byte():
    data = b"a" * 16383 + b"bc"
    output, _ = collect([(.001, ("meta", 200, {})), (.002, ("data", data[:16383])),
                         (.003, ("data", data[16383:])), (.004, ("end",))])
    assert output[0][1] == [("meta", 200, {}), ("data", data[:16384]), ("data", b"c"), ("end",)]


def test_error_follows_queued_data_and_no_empty_data_record():
    output, _ = collect([(.001, ("meta", 200, {})), (.002, ("data", b"")),
                         (.003, ("data", b"x")), (.004, ("error", "upstream_failed"))])
    assert output[0][1] == [("meta", 200, {}), ("data", b"x"), ("error", "upstream_failed")]


def test_a_reply_that_finished_is_delivered_at_the_deadline_tick():
    output, _ = collect([(.12, ("meta", 200, {})), (.13, ("end",))], overall=.125)
    assert output == [(pytest.approx(.15), [("meta", 200, {}), ("end",)])]


def test_at_the_deadline_what_arrived_goes_out_before_the_timeout():
    output, _ = collect([(.01, ("meta", 200, {})), (.12, ("data", b"late"))], overall=.125)
    assert [t for t, _ in output] == pytest.approx([.05, .15])
    assert output[1][1] == [("data", b"late"), ("error", "upstream_timeout")]


def test_an_idle_stream_times_out_on_the_tick_after_the_deadline():
    output, _ = collect([(.01, ("meta", 200, {}))], overall=.125)
    assert [t for t, _ in output] == pytest.approx([.05, .15])
    assert output[1][1] == [("error", "upstream_timeout")]


def test_slow_consumer_keeps_grid_anchor_and_skips_missed_ticks():
    output, clock = collect([(.01, ("meta", 200, {})), (.18, ("data", b"x")),
                            (.19, ("end",))], stalled=True)
    assert [t for t, _ in output] == pytest.approx([.05, .20])
    assert len(clock.sleeps) == 2


def test_late_wakeup_makes_one_batch_then_advances_to_future_tick():
    async def work():
        backlog = Backlog()
        backlog.put_nowait(("meta", 200, {}))
        now = [0.0]

        async def sleep(delay):
            assert delay > 0
            now[0] = .181 if now[0] == 0 else now[0] + delay

        async def wait(ready, timeout):
            now[0] = .19
            backlog.put_nowait(("end",))

        output = []
        async for batch in grid_batches(backlog, started=0, grid_seconds=.05, heartbeat_seconds=15,
                                        overall_seconds=1, monotonic=lambda: now[0], sleep=sleep, wait=wait):
            output.append((now[0], batch))
        assert [t for t, _ in output] == pytest.approx([.181, .20])
    asyncio.run(work())


@pytest.mark.parametrize("ready", [False, True], ids=["idle", "ready"])
def test_cancelling_while_the_grid_waits_is_prompt(ready):
    async def work():
        backlog = Backlog()
        if ready:
            backlog.put_nowait(("meta", 200, {}))
        # The real waits, over the real event loop: the fake clock never advances.
        batches = grid_batches(backlog, started=0, grid_seconds=.05, heartbeat_seconds=15,
                               overall_seconds=600, monotonic=lambda: -600, sleep=asyncio.sleep)
        task = asyncio.create_task(anext(batches))
        await asyncio.sleep(.01)
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await batches.aclose()
    asyncio.run(work())


def test_backlog_is_bounded_by_bytes_not_by_chunks():
    backlog = Backlog()
    for _ in range(BACKLOG_BYTES // 16):
        backlog.put_nowait(("data", b"x" * 16))
    with pytest.raises(asyncio.QueueFull):
        backlog.put_nowait(("data", b"x"))
    backlog.put_nowait(("end",))  # control records are never held back
    assert sum(len(item[1]) for item in backlog.take() if item[0] == "data") == BACKLOG_BYTES
    # A single chunk larger than the bound still fits into an empty backlog.
    backlog.put_nowait(("data", b"y" * (BACKLOG_BYTES + 1)))


def test_full_backlog_holds_the_producer_until_the_next_tick():
    async def work():
        backlog = Backlog()
        for _ in range(16):
            backlog.put_nowait(("data", b"x" * 16384))
        producer = asyncio.create_task(backlog.put(("data", b"y")))
        await asyncio.sleep(0)
        assert not producer.done()
        clock = Clock(backlog, [])
        batches = grid_batches(backlog, started=0, grid_seconds=.05, heartbeat_seconds=15, overall_seconds=1,
                               monotonic=lambda: clock.now, sleep=clock.sleep, wait=clock.wait)
        batch = await anext(batches)
        assert len(batch) == 16 and sum(len(item[1]) for item in batch) == 256 * 1024
        await producer
        assert await anext(batches) == [("data", b"y")]
        await batches.aclose()
    asyncio.run(work())


@pytest.mark.parametrize("item", [("meta", 200, {}), ("end",)])
def test_ready_control_record_waits_for_a_tick(item):
    async def work():
        backlog = Backlog()
        backlog.put_nowait(item)
        clock = Clock(backlog, [])
        batches = grid_batches(backlog, started=0, grid_seconds=.05, heartbeat_seconds=15, overall_seconds=1,
                               monotonic=lambda: clock.now, sleep=clock.sleep, wait=clock.wait)
        assert await anext(batches) == [item]
        assert clock.now == pytest.approx(.05)
        await batches.aclose()
    asyncio.run(work())


@pytest.mark.parametrize("grid", [0, -1, float("inf"), float("nan")])
def test_invalid_grid_is_rejected(grid):
    with pytest.raises(ValueError, match="grid"):
        remote_bridge.Settings({"client": b"k" * 32}, "http://127.0.0.1:8317", "key", grid_seconds=grid)
