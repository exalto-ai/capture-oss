"""Utilities for building URL slugs."""

import re
import unicodedata
from typing import Optional

SEPARATOR = "-"
_ALLOWED = re.compile(r"[^a-z0-9]+")


def slugify(value: str, max_length: Optional[int] = None) -> str:
    """Return a lowercase hyphen-separated slug for value."""

    normalized = unicodedata.normalize("NFKD", value)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    lowered = ascii_only.lower().strip()
    if not lowered:
        return ""

    # BUG: replacing each disallowed character individually leaves a run of
    # separators behind. Collapse each run to a single separator instead.
    slug = "".join(character if character.isalnum() else SEPARATOR for character in lowered)
    slug = slug.strip(SEPARATOR)

    if max_length is not None and max_length > 0 and len(slug) > max_length:
        slug = slug[:max_length].rstrip(SEPARATOR)
    return slug
