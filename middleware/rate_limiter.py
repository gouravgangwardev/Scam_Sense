from flask_limiter import Limiter

from flask_limiter.util import get_remote_address



limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  
                               
)


def init_limiter(app):
    """
    Attach the rate limiter to the Flask app.
    Call this once in app.py during app initialization.

    Args:
        app: Flask application instance

    Usage in app.py:
        from middleware.rate_limiter import init_limiter, limiter
        init_limiter(app)
    """
    limiter.init_app(app)
    print("[RATE LIMITER] Initialized successfully.")
    print("[RATE LIMITER] Default limits: 200/day, 50/hour per IP")



home_limit = limiter.limit("60 per minute")


scan_limit = limiter.limit("10 per minute")


report_limit = limiter.limit("5 per minute")


stats_limit = limiter.limit("30 per minute")



def get_rate_limit_error_message() -> str:
    """
    Returns a user-friendly message shown when rate limit is exceeded.
    Called by the 429 error handler in error_handlers/handlers.py
    """
    return (
        "You have made too many requests in a short time. "
        "Please wait 1 minute before scanning again."
    )

