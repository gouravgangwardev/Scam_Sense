from flask import render_template, jsonify, request




def register_error_handlers(app):
    """
    Attach all error handlers to the Flask app.
    Call this once during app initialization in app.py.

    Usage in app.py:
        from error_handlers.handlers import register_error_handlers
        register_error_handlers(app)
    """

    
    @app.errorhandler(400)
    def bad_request(error):
        """
        Triggered when user submits invalid or malformed input.
        Example: empty message, invalid URL format.
        """
        return render_template(
            "error.html",
            error_code=400,
            error_title="Invalid Input",
            error_message=(
                "The information you submitted was not valid. "
                "Please go back and check your input."
            ),
            show_home_button=True,
        ), 400


   
    @app.errorhandler(404)
    def page_not_found(error):
        """
        Triggered when user visits a URL that does not exist.
        Example: /scan/random or a mistyped route.
        """
        return render_template(
            "error.html",
            error_code=404,
            error_title="Page Not Found",
            error_message=(
                "The page you are looking for does not exist. "
                "Please return to the home page."
            ),
            show_home_button=True,
        ), 404


    
    @app.errorhandler(405)
    def method_not_allowed(error):
        """
        Triggered when wrong HTTP method is used on a route.
        Example: GET request sent to a POST-only scan route.
        """
        return render_template(
            "error.html",
            error_code=405,
            error_title="Action Not Allowed",
            error_message=(
                "This action is not permitted here. "
                "Please use the scan form on the home page."
            ),
            show_home_button=True,
        ), 405


    
    @app.errorhandler(413)
    def file_too_large(error):
        """
        Triggered when uploaded file exceeds MAX_CONTENT_LENGTH (5MB).
        Flask raises this automatically before the route runs.
        """
        return render_template(
            "error.html",
            error_code=413,
            error_title="File Too Large",
            error_message=(
                "The image you uploaded is too large. "
                "Maximum allowed file size is 5 MB. "
                "Please compress the image and try again."
            ),
            show_home_button=True,
        ), 413


    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        """
        Triggered when a user exceeds the rate limit.
        Set in middleware/rate_limiter.py (10 scans per minute).
        """
        return render_template(
            "error.html",
            error_code=429,
            error_title="Too Many Requests",
            error_message=(
                "You have made too many scan requests in a short time. "
                "Please wait 1 minute before scanning again."
            ),
            show_home_button=True,
        ), 429


   
    @app.errorhandler(500)
    def internal_server_error(error):
        """
        Triggered when an unexpected error occurs inside any route.
        Catches any crash that was not handled by the route itself.
        """
        print(f"[ERROR 500] Internal server error: {error}")

        return render_template(
            "error.html",
            error_code=500,
            error_title="Something Went Wrong",
            error_message=(
                "An unexpected error occurred on our server. "
                "Please try again in a moment."
            ),
            show_home_button=True,
        ), 500


    print("[ERROR HANDLERS] All error handlers registered successfully.")




def ocr_failure_response():
    """
    Returns error page when OCR fails to extract text from image.
    Called inside scan_screenshot() in app.py when extracted_text is empty.

    Usage in app.py:
        from error_handlers.handlers import ocr_failure_response
        if not extracted_text:
            return ocr_failure_response()
    """
    return render_template(
        "error.html",
        error_code="OCR",
        error_title="Could Not Read Image",
        error_message=(
            "We could not extract text from your screenshot. "
            "Please make sure the image is clear, not blurry, "
            "and contains visible text. Then try again."
        ),
        show_home_button=True,
    ), 400


def ai_failure_response():
    """
    Returns error page when AI engine is completely unreachable
    and the rule-based fallback also fails.
    Called only in extreme failure scenarios.

    Usage in app.py:
        from error_handlers.handlers import ai_failure_response
        if not result:
            return ai_failure_response()
    """
    return render_template(
        "error.html",
        error_code="AI",
        error_title="Analysis Unavailable",
        error_message=(
            "Our scan system is temporarily unavailable. "
            "Please try again in a few moments."
        ),
        show_home_button=True,
    ), 503


def invalid_file_response(reason: str = ""):
    """
    Returns error page when uploaded file fails validation.
    Called inside scan_screenshot() in app.py after validate_file() fails.

    Args:
        reason: The specific validation error message from validators.py

    Usage in app.py:
        from error_handlers.handlers import invalid_file_response
        is_valid, error = validate_file(filename, file)
        if not is_valid:
            return invalid_file_response(reason=error)
    """
    message = reason if reason else (
        "The uploaded file is not supported. "
        "Please upload a JPG or PNG image under 5 MB."
    )

    return render_template(
        "error.html",
        error_code=400,
        error_title="Invalid File",
        error_message=message,
        show_home_button=True,
    ), 400
    
    
