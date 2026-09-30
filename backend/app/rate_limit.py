"""Simple in-memory rate limiter for AegisAI."""

from collections import defaultdict
from time import monotonic

from fastapi import HTTPException, status


RATE_LIMIT = 60
WINDOW_SECONDS = 60


_request_history: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(identifier: str) -> None:
    """Allow a request or raise HTTP 429 when the limit is exceeded."""

    now = monotonic()
    window_start = now - WINDOW_SECONDS

    timestamps = _request_history[identifier]

    timestamps[:] = [
        timestamp
        for timestamp in timestamps
        if timestamp > window_start
    ]

    if len(timestamps) >= RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )

    timestamps.append(now)