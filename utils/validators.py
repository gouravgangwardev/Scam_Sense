"""
SCAM SENSE AI — Input Validators
Validates all user input before processing begins.
Prevents bad data, oversized files, and unsupported formats.
"""

import os
import re
from urllib.parse import urlparse

# ── Configuration ─────────────────────────────────────────────────────────────
MAX_MESSAGE_LENGTH = 5000          # Maximum characters allowed in message
MIN_MESSAGE_LENGTH = 5             # Minimum characters to be worth scanning
MAX_FILE_SIZE_MB   = 5             # Maximum upload size in megabytes
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}

ALLOWED_URL_SCHEMES = {"http", "https"}


# ── Message Validator ─────────────────────────────────────────────────────────
def validate_message(text: str) -> tuple:
    """
    Validate pasted message text input.

    Args:
        text: The message text submitted by user

    Returns:
        (True, None)           if valid
        (False, error_string)  if invalid
    """
    if not text or not text.strip():
        return False, "Message cannot be empty. Please paste the suspicious message."

    text = text.strip()

    if len(text) < MIN_MESSAGE_LENGTH:
        return False, f"Message is too short. Please enter at least {MIN_MESSAGE_LENGTH} characters."

    if len(text) > MAX_MESSAGE_LENGTH:
        return False, f"Message is too long. Maximum allowed is {MAX_MESSAGE_LENGTH} characters."

    return True, None


# ── URL Validator ─────────────────────────────────────────────────────────────
def validate_url(url: str) -> tuple:
    """
    Validate URL input before link scanning.

    Args:
        url: The URL string submitted by user

    Returns:
        (True, None)           if valid
        (False, error_string)  if invalid
    """
    if not url or not url.strip():
        return False, "URL cannot be empty. Please paste the suspicious link."

    url = url.strip()

    # Add scheme if missing so urlparse works correctly
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        # Must have a valid scheme
        if parsed.scheme not in ALLOWED_URL_SCHEMES:
            return False, "Only http and https links are supported."

        # Must have a domain/netloc
        if not parsed.netloc or "." not in parsed.netloc:
            return False, "This does not appear to be a valid URL. Please check and try again."

        # Domain must not contain spaces
        if " " in parsed.netloc:
            return False, "Invalid URL format. Please paste the complete link."

    except Exception:
        return False, "Could not read this URL. Please paste the complete link."

    return True, None


# ── File Validator ────────────────────────────────────────────────────────────
def validate_file(filename: str, file_storage) -> tuple:
    """
    Validate uploaded screenshot file.

    Args:
        filename    : Original filename from the upload
        file_storage: Flask FileStorage object (werkzeug)

    Returns:
        (True, None)           if valid
        (False, error_string)  if invalid
    """
    if not filename or filename.strip() == "":
        return False, "No file was selected. Please choose a screenshot to upload."

    # Check file extension
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return False, (
            f"File type '.{ext}' is not supported. "
            f"Please upload a JPG or PNG image."
        )

    # Check file size by reading content length
    try:
        file_storage.seek(0, os.SEEK_END)   # Move to end of file
        file_size = file_storage.tell()      # Get position = size in bytes
        file_storage.seek(0)                 # Reset to beginning for saving

        if file_size == 0:
            return False, "The uploaded file is empty. Please select a valid image."

        if file_size > MAX_FILE_SIZE_BYTES:
            size_mb = round(file_size / (1024 * 1024), 1)
            return False, (
                f"File size ({size_mb} MB) exceeds the {MAX_FILE_SIZE_MB} MB limit. "
                "Please upload a smaller image."
            )

    except Exception as e:
        print(f"[VALIDATOR ERROR] File size check failed: {e}")
        return False, "Could not read the uploaded file. Please try again."

    return True, None


# ── Report Content Validator ──────────────────────────────────────────────────
def validate_report(content: str, report_type: str) -> tuple:
    """
    Validate user-submitted scam report form.

    Args:
        content     : Scam content submitted by user
        report_type : Category selected by user

    Returns:
        (True, None)           if valid
        (False, error_string)  if invalid
    """
    ALLOWED_REPORT_TYPES = {"message", "link", "call", "screenshot", "other"}

    if not content or not content.strip():
        return False, "Report content cannot be empty."

    if len(content.strip()) < 10:
        return False, "Please provide more detail in your report (minimum 10 characters)."

    if len(content.strip()) > 10000:
        return False, "Report content is too long. Maximum 10,000 characters allowed."

    if report_type not in ALLOWED_REPORT_TYPES:
        return False, "Invalid report type selected. Please choose a valid category."

    return True, None
    