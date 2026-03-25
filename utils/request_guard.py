"""
SCAM SENSE AI — Request Guard
Sanitizes and validates all incoming text input before processing.
Use sanitize_text() on every user-submitted string before sending to AI or fallback.
"""

import re
import html


# ── Limits ────────────────────────────────────────────────────────────────────
MAX_TEXT_LENGTH   = 5000
MAX_URL_LENGTH    = 2000
MAX_REPORT_LENGTH = 10000


def sanitize_text(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """
    Clean user-submitted text before processing.

    Steps:
    1. Strip leading/trailing whitespace
    2. Remove HTML injection characters (< >)
    3. Remove null bytes
    4. Collapse excessive whitespace/newlines
    5. Truncate to max_length

    Args:
        text:       Raw input string from form or request
        max_length: Maximum allowed character length

    Returns:
        Sanitized string
    """
    if not text:
        return ""

    # Strip whitespace
    text = text.strip()

    # Remove null bytes (common in malicious payloads)
    text = text.replace("\x00", "")

    # Remove HTML injection characters
    text = re.sub(r"[<>]", "", text)

    # Collapse more than 3 consecutive newlines → 2
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Collapse multiple spaces into one
    text = re.sub(r" {3,}", "  ", text)

    # Truncate
    if len(text) > max_length:
        text = text[:max_length]

    return text


def sanitize_url(url: str) -> str:
    """
    Clean and normalize a URL before scanning.

    Steps:
    1. Strip whitespace
    2. Remove null bytes
    3. Prepend https:// if no scheme present
    4. Truncate to MAX_URL_LENGTH

    Args:
        url: Raw URL string from user input

    Returns:
        Cleaned URL string
    """
    if not url:
        return ""

    url = url.strip()
    url = url.replace("\x00", "")
    url = re.sub(r"[<>]", "", url)

    # Auto-prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if len(url) > MAX_URL_LENGTH:
        url = url[:MAX_URL_LENGTH]

    return url


def sanitize_report(text: str) -> str:
    """
    Clean user-submitted scam report content.
    Same as sanitize_text but allows a longer max_length.

    Args:
        text: Raw report text

    Returns:
        Sanitized string
    """
    return sanitize_text(text, max_length=MAX_REPORT_LENGTH)


def is_empty(text: str) -> bool:
    """
    Check if text is empty or only whitespace after stripping.

    Args:
        text: Any string

    Returns:
        True if effectively empty, else False
    """
    return not text or not text.strip()


def truncate_for_preview(text: str, limit: int = 300) -> str:
    """
    Truncate text for safe DB storage or UI preview display.

    Args:
        text:  Input string
        limit: Max characters to keep

    Returns:
        Truncated string with ellipsis if cut
    """
    if not text:
        return ""

    text = sanitize_text(text, max_length=limit + 10)

    if len(text) > limit:
        return text[:limit] + "..."

    return text
