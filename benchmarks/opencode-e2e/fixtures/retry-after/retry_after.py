"""Utilities for HTTP retry handling."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
from typing import Optional


def parse_retry_after(value: str, now: datetime) -> Optional[int]:
    """Return the non-negative delay described by Retry-After, or None."""

    candidate = value.strip()
    if not candidate:
        return None
    if candidate.isascii() and candidate.isdecimal():
        return int(candidate)

    try:
        retry_at = parsedate_to_datetime(candidate)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at is None or retry_at.tzinfo is None:
        return None

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    delay_seconds = (
        retry_at.astimezone(timezone.utc) - now.astimezone(timezone.utc)
    ).total_seconds()
    # BUG: int() rounds a positive fractional delay down. Retry-After must not
    # let the caller retry before the HTTP date.
    return max(0, int(delay_seconds))
