"""
SCAM SENSE AI — Security Utilities
Centralizes all file and input safety checks.
Use these functions everywhere instead of raw filename or extension handling.
"""

import os
import imghdr
from werkzeug.utils import secure_filename


# ── Allowed file extensions ───────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}

# ── Allowed MIME types (as returned by imghdr) ───────────────────────────────
ALLOWED_MIME_TYPES = {"jpeg", "png"}

# ── Max filename length ───────────────────────────────────────────────────────
MAX_FILENAME_LENGTH = 100


def safe_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    Uses werkzeug's secure_filename under the hood.

    Args:
        filename: Raw filename from user upload

    Returns:
        Sanitized, safe filename string

    Example:
        safe_filename("../../app.py")  →  "app.py"
        safe_filename("my photo.jpg")  →  "my_photo.jpg"
    """
    if not filename:
        return "upload"

    name = secure_filename(filename)

    # Truncate if too long
    if len(name) > MAX_FILENAME_LENGTH:
        ext  = name.rsplit(".", 1)[-1] if "." in name else ""
        base = name[:MAX_FILENAME_LENGTH - len(ext) - 1]
        name = f"{base}.{ext}" if ext else base

    return name or "upload"


def is_allowed_extension(filename: str) -> bool:
    """
    Check if a filename has an allowed image extension.

    Args:
        filename: File name string (may include path)

    Returns:
        True if extension is in ALLOWED_EXTENSIONS, else False
    """
    if not filename or "." not in filename:
        return False

    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def is_allowed_mime(filepath: str) -> bool:
    """
    Verify the actual MIME type of an uploaded file using imghdr.
    Extension-only checks can be spoofed — always call this after saving.

    Args:
        filepath: Full path to the saved file on disk

    Returns:
        True if file is a genuine JPEG or PNG, else False
    """
    if not os.path.exists(filepath):
        return False

    detected = imghdr.what(filepath)
    return detected in ALLOWED_MIME_TYPES


def validate_uploaded_file(filename: str, filepath: str) -> tuple[bool, str]:
    """
    Full validation pipeline for an uploaded screenshot.
    Checks extension + MIME type.

    Args:
        filename: Original or sanitized filename
        filepath: Full path to file saved on disk

    Returns:
        (True, "")           if file passes all checks
        (False, error_msg)   if any check fails
    """
    if not is_allowed_extension(filename):
        return False, "Invalid file type. Please upload a JPG or PNG image."

    if not is_allowed_mime(filepath):
        return False, "File content does not match its extension. Please upload a genuine JPG or PNG image."

    return True, ""


def build_safe_filepath(upload_folder: str, filename: str) -> str:
    """
    Build a safe, absolute file path for saving an upload.
    Prevents any directory traversal by combining folder + safe_filename.

    Args:
        upload_folder: Absolute path to uploads directory
        filename:      Raw filename from user

    Returns:
        Full safe absolute path string
    """
    name = safe_filename(filename)
    return os.path.join(os.path.abspath(upload_folder), name)
