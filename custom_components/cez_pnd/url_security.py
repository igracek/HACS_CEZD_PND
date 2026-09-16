"""Shared URL path validation for browser and direct HTTP navigation."""

import posixpath
import re
from urllib.parse import unquote


MAX_URL_DECODE_ROUNDS = 5
_ENCODED_RESERVED_PATTERN = re.compile(
    r"%(?:21|23|24|26|27|28|29|2a|2b|2c|2e|2f|3a|3b|3d|3f|40|5b|5c|5d|7b|7d)",
    re.IGNORECASE,
)


def normalize_url_path(raw_path: str) -> str:
    """Decode and normalize a URL path under the strict navigation contract.

    Every decode round is inspected so double-encoded delimiters and traversal
    cannot become meaningful only after an earlier round has been accepted.
    """
    if not isinstance(raw_path, str):
        raise ValueError("path must be text")

    decoded_path = raw_path or "/"
    for _decode_round in range(MAX_URL_DECODE_ROUNDS):
        if re.search(r"%(?![0-9a-fA-F]{2})", decoded_path):
            raise ValueError("malformed percent escape")
        if _ENCODED_RESERVED_PATTERN.search(decoded_path):
            raise ValueError("encoded reserved delimiter or traversal")
        next_path = unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path
    else:
        raise ValueError("excessively encoded path")

    if "\\" in decoded_path or "\x00" in decoded_path:
        raise ValueError("ambiguous path")
    if "\ufffd" in decoded_path or any(
        ord(character) < 32 or ord(character) == 127 for character in decoded_path
    ):
        raise ValueError("malformed encoded path")
    if any(segment in (".", "..") for segment in decoded_path.split("/")):
        raise ValueError("path traversal")

    normalized_path = posixpath.normpath(decoded_path)
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    return normalized_path


def matches_segment_prefix(path: str, prefix: str) -> bool:
    """Return whether path equals a prefix or starts at its next segment."""
    clean_prefix = prefix.rstrip("/") or "/"
    return path == clean_prefix or path.startswith(clean_prefix + "/")
