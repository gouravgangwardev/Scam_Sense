"""
SCAM SENSE AI — Error Response
Centralizes all error page rendering.
Use this everywhere instead of calling render_template("error.html") directly.
"""

from flask import render_template


def render_error(code: int, title: str, message: str, show_home: bool = True):
    """
    Render the standard error.html page with consistent variables.

    Args:
        code:      HTTP status code (int) or string like "OCR" / "AI"
        title:     Short error title shown as heading
        message:   Full error description shown to user
        show_home: Whether to show the "Go Back Home" button

    Returns:
        Flask response tuple (rendered template, status code)

    Usage in app.py:
        from utils.error_response import render_error
        return render_error(400, "Invalid Input", "Message is too short.")
    """
    # Determine numeric HTTP code for response tuple
    http_code = code if isinstance(code, int) else 400

    return render_template(
        "error.html",
        error_code      = code,
        error_title     = title,
        error_message   = message,
        show_home_button= show_home,
    ), http_code


# ── Preset error helpers ──────────────────────────────────────────────────────

def bad_request(message: str = "The information you submitted was not valid."):
    """400 — bad or missing input from user."""
    return render_error(400, "Invalid Input", message)


def not_found(message: str = "The page you are looking for does not exist."):
    """404 — route or resource missing."""
    return render_error(404, "Page Not Found", message)


def method_not_allowed(message: str = "This action is not permitted here."):
    """405 — wrong HTTP method."""
    return render_error(405, "Action Not Allowed", message)


def file_too_large(message: str = "The image you uploaded is too large. Maximum allowed size is 5 MB."):
    """413 — uploaded file exceeds size limit."""
    return render_error(413, "File Too Large", message)


def rate_limited(message: str = "You have made too many requests. Please wait 1 minute before trying again."):
    """429 — rate limit exceeded."""
    return render_error(429, "Too Many Requests", message)


def server_error(message: str = "An unexpected error occurred. Please try again in a moment."):
    """500 — internal server error."""
    return render_error(500, "Something Went Wrong", message)


def ocr_failure(message: str = (
    "We could not extract text from your screenshot. "
    "Please make sure the image is clear and contains visible text."
)):
    """OCR — could not read image."""
    return render_error("OCR", "Could Not Read Image", message)


def ai_failure(message: str = "Our scan system is temporarily unavailable. Please try again in a few moments."):
    """AI — engine completely unreachable and fallback also failed."""
    return render_error("AI", "Analysis Unavailable", message)


def invalid_file(reason: str = ""):
    """400 — uploaded file failed validation."""
    message = reason if reason else "The uploaded file is not supported. Please upload a JPG or PNG image under 5 MB."
    return render_error(400, "Invalid File", message)
