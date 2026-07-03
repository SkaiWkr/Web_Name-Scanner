"""Network resilience primitives: rate limiting and retries."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class RateLimiter:
    """Simple per-process rate limiter for outbound operations."""

    def __init__(self, interval_seconds: float) -> None:
        """Initialize the limiter with a minimum interval between calls."""
        self.interval_seconds = max(0.0, interval_seconds)
        self._last_call = 0.0

    def wait(self) -> None:
        """Sleep until the next operation is allowed."""
        elapsed = time.monotonic() - self._last_call
        delay = self.interval_seconds - elapsed
        if delay > 0:
            time.sleep(delay)
        self._last_call = time.monotonic()


def retry(operation: Callable[[], T], retries: int, backoff_factor: float, logger: logging.Logger) -> T:
    """Run an operation with retry and exponential backoff."""
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return operation()
        except Exception as exc:  # noqa: BLE001 - batch scanning must isolate failures.
            last_error = exc
            if attempt == retries:
                break
            sleep_for = backoff_factor * (2 ** (attempt - 1))
            logger.debug("operation failed on attempt %s/%s: %s", attempt, retries, exc)
            time.sleep(sleep_for)
    assert last_error is not None
    raise last_error
