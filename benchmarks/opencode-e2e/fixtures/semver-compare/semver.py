"""Utilities for comparing semantic version strings."""

import re
from typing import Optional

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


def _release(value: str) -> Optional[tuple[int, int, int]]:
    match = _VERSION.match(value.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _prerelease(value: str) -> Optional[str]:
    match = _VERSION.match(value.strip())
    return None if match is None else match.group(4)


def compare_versions(left: str, right: str) -> Optional[int]:
    """Return -1, 0, or 1 comparing two semantic versions, or None if invalid."""

    left_release = _release(left)
    right_release = _release(right)
    if left_release is None or right_release is None:
        return None

    if left_release != right_release:
        return -1 if left_release < right_release else 1

    left_pre = _prerelease(left)
    right_pre = _prerelease(right)
    if left_pre == right_pre:
        return 0
    # BUG: a prerelease sorts before its own release, but this treats a missing
    # prerelease as the empty string, which sorts first instead of last.
    return -1 if (left_pre or "") < (right_pre or "") else 1
