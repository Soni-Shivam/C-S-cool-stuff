"""structlog configuration. One line per meaningful event, JSON to a file.

docs/00_GUIDING_MAP.md §9.7. The live log stream **is part of the demo**, so lines in
the M3/frontier path are written for a human to read on a screen:

    [M3] sample queried PackageManager('com.sbi.yono') -> MISS -> stall detected

not a struct dump. `event` carries that human sentence; structured fields carry the
machine-readable detail.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog


def configure_logging(*, level: str = "INFO", log_path: Path | None = None) -> None:
    """Configure structlog once, at process start.

    Emits JSON to `log_path` (which the dashboard tails over SSE) and human-readable
    lines to stderr, because the two audiences are different: the UI needs parseable
    events, an operator watching a terminal needs to read them.
    """
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(format="%(message)s", handlers=handlers, level=level.upper())

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
