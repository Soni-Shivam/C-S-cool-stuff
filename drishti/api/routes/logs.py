"""The live log stream. `GET /api/logs/stream`.

docs/PHASE_0_FOUNDATIONS.md T0.6, 00_GUIDING_MAP.md §9.7.

**The live log stream is part of the demo.** On stage it is what shows the frontier
reasoning in real time — `[M3] sample queried PackageManager('com.sbi.yono') -> MISS
-> stall detected` — so it has to be tailable and readable by a human, not just
parseable by the UI.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from drishti.api.deps import SettingsDep

router = APIRouter(prefix="/api/logs", tags=["logs"])

#: How long to wait between polls of the log file when it has no new lines.
_IDLE_SLEEP_S = 0.25
#: Lines of history to send on connect, so a late-joining browser is not staring at
#: an empty pane during a demo.
_BACKFILL_LINES = 50


async def _tail(path: Path, *, backfill: int) -> AsyncIterator[dict[str, str]]:
    """Yield JSON log lines, starting with a little history then following the file.

    Polling rather than inotify/kqueue: one dependency fewer, and at a quarter-second
    interval a human cannot tell the difference on a demo screen.
    """
    if path.exists():
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            history = handle.readlines()[-backfill:]
            for line in history:
                if line.strip():
                    yield {"event": "log", "data": line.rstrip("\n")}
            handle.seek(0, 2)  # follow from the end
            while True:
                line = handle.readline()
                if line:
                    if line.strip():
                        yield {"event": "log", "data": line.rstrip("\n")}
                    continue
                await asyncio.sleep(_IDLE_SLEEP_S)
    else:
        # The file appears on the first log write. Wait for it rather than 404-ing, so
        # the UI can connect before any job has been submitted.
        while not path.exists():
            await asyncio.sleep(_IDLE_SLEEP_S)
        async for item in _tail(path, backfill=0):
            yield item


@router.get("/stream")
async def stream_logs(settings: SettingsDep) -> EventSourceResponse:
    return EventSourceResponse(_tail(settings.log_path, backfill=_BACKFILL_LINES))
