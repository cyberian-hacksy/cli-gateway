"""A byte-bounded upstream backlog, released on a monotonic response grid."""
import asyncio
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Literal

from cgw import protocol

RelayItem = (tuple[Literal["meta"], int, dict] | tuple[Literal["data"], bytes]
             | tuple[Literal["end", "heartbeat"]] | tuple[Literal["error"], str])

# Upstream bytes waiting for the next tick. Bounded by bytes, not by chunks: an upstream
# that sends one small chunk per event must not be held to a few chunks per tick.
BACKLOG_BYTES = 256 * 1024


def _coalesce(items):
    batch, run = [], []

    def flush():
        batch.extend(("data", chunk) for chunk in protocol.chunks(b"".join(run)))
        run.clear()

    for item in items:
        if item[0] == "data":
            run.append(item[1])
        else:
            flush()
            batch.append(item)
            if item[0] in ("end", "error"):
                break
    flush()
    return batch


class Backlog:
    """What upstream has sent and the grid has not yet released, in order.

    Only DATA counts against the bound; META and the final record are never held back.
    A single chunk larger than the bound is accepted into an empty backlog.
    """

    def __init__(self, limit=BACKLOG_BYTES):
        self._limit = limit
        self._items, self._bytes = [], 0
        self.ready = asyncio.Event()  # set while anything waits to be released
        self._room = asyncio.Event()  # set while DATA may be added
        self._room.set()

    def put_nowait(self, item):
        if item[0] == "data" and self._bytes and self._bytes + len(item[1]) > self._limit:
            raise asyncio.QueueFull
        self._items.append(item)
        if item[0] == "data":
            self._bytes += len(item[1])
        self.ready.set()

    async def put(self, item):
        while True:
            try:
                return self.put_nowait(item)
            except asyncio.QueueFull:
                self._room.clear()
                await self._room.wait()

    def take(self):
        """Everything waiting, as records: DATA merged and split at 16 KiB."""
        items, self._items, self._bytes = self._items, [], 0
        self.ready.clear()
        self._room.set()
        return _coalesce(items)


async def wait_ready(ready: asyncio.Event, timeout: float) -> None:
    """Return once the backlog has something to release, or after `timeout` seconds."""
    try:
        async with asyncio.timeout(timeout):
            await ready.wait()
    except TimeoutError:
        pass


async def grid_batches(
    backlog: Backlog, *, started: float,
    grid_seconds: float, heartbeat_seconds: float, overall_seconds: float,
    monotonic: Callable[[], float], sleep: Callable[[float], Awaitable[None]],
    wait: Callable[[asyncio.Event, float], Awaitable[None]] = wait_ready,
) -> AsyncIterator[list[RelayItem]]:
    """Release one finite snapshot per tick; never hold a tick open for more upstream bytes.

    The schedule is kept in whole ticks: heartbeats and the deadline fall on fixed ticks,
    however long a write takes or however large the clock is. A late wakeup makes one
    batch, and missed ticks are skipped. An idle stream sleeps until something arrives,
    a heartbeat is due or the deadline passes, then waits for the next tick. Network
    backpressure can delay emission: this bounds deliberate batching delay, not
    delivery latency.
    """
    heartbeat_ticks = max(1, math.ceil(heartbeat_seconds / grid_seconds - 1e-9))
    deadline_tick = math.ceil(overall_seconds / grid_seconds - 1e-9)
    tick, last_tick = 1, 0  # the header line, at tick 0, counts as the last record

    def first_tick_at(moment):
        # moment - started is exact for nearby floats, so this rounds in tick units only.
        return max(tick, math.ceil((moment - started) / grid_seconds - 1e-9))

    while True:
        if not backlog.ready.is_set():
            due = max(tick, min(last_tick + heartbeat_ticks, deadline_tick))
            timeout = started + due * grid_seconds - monotonic()
            if timeout > 0:
                await wait(backlog.ready, timeout)
            # A wakeup that is late for the due tick takes that tick, as a late sleep does.
            tick = min(due, first_tick_at(monotonic()))
        delay = started + tick * grid_seconds - monotonic()
        if delay > 0:
            await sleep(delay)
        # No await while draining: a busy reader cannot refill this snapshot forever.
        batch = backlog.take()
        finished = bool(batch) and batch[-1][0] in ("end", "error")
        if tick >= deadline_tick and not finished:
            # What arrived before this tick still goes out, then the timeout ends the stream.
            yield batch + [("error", "upstream_timeout")]
            return
        if not batch and tick - last_tick >= heartbeat_ticks:
            batch = [("heartbeat",)]
        if batch:
            yield batch
            last_tick = tick
            if finished:
                return
        tick = max(tick + 1, math.floor((monotonic() - started) / grid_seconds) + 1)
