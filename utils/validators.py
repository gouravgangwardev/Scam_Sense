"""
SCAM SENSE AI — Input Validators
Validates all user input before processing begins.
Prevents bad data, oversized files, and unsupported formats.
"""

import os
import re
import imghdr
from urllib.parse import urlparse

# ── Configuration ─────────────────────────────────────────────────────────────
MAX_MESSAGE_LENGTH  = 5000
MIN_MESSAGE_LENGTH  = 5
MAX_FILE_SIZE_MB    = 5
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
ALLOWED_MIME_TYPES = {"jpeg", "png"}        # imghdr returns these strings
ALLOWED_URL_SCHEMES = {"http", "https"}


# ── Message Validator ─────────────────────────────────────────────────────────
def validate_message(text: str) -> tuple:
    """
    Validate pasted message text input.

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

        if parsed.scheme not in ALLOWED_URL_SCHEMES:
            return False, "Only http and https links are supported."

        if not parsed.netloc or "." not in parsed.netloc:
            return False, "This does not appear to be a valid URL. Please check and try again."

        if " " in parsed.netloc:
            return False, "Invalid URL format. Please paste the complete link."

    except Exception:
        return False, "Could not read this URL. Please paste the complete link."

    return True, None


# ── File Validator ────────────────────────────────────────────────────────────
def validate_file(filename: str, file_storage) -> tuple:
    """
    Validate uploaded screenshot file.
    Checks extension, file size, AND actual MIME type (prevents spoofed extensions).

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
            "Please upload a JPG or PNG image."
        )

    # Check file size
    try:
        file_storage.seek(0, os.SEEK_END)
        file_size = file_storage.tell()
        file_storage.seek(0)

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

    # Check actual MIME type using imghdr (prevents renaming exe to .png)
    try:
        file_storage.seek(0)
        detected_type = imghdr.what(file_storage)
        file_storage.seek(0)

        if detected_type not in ALLOWED_MIME_TYPES:
            return False, (
                "The uploaded file does not appear to be a valid image. "
                "Please upload a real JPG or PNG screenshot."
            )

    except Exception as e:
        print(f"[VALIDATOR ERROR] MIME type check failed: {e}")
        # If imghdr fails, allow through — extension check already passed
        file_storage.seek(0)

    return True, None


# ── Report Content Validator ──────────────────────────────────────────────────
def validate_report(content: str, report_type: str) -> tuple:
    """
    Validate user-submitted scam report form.

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
