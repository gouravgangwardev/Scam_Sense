"""
SCAM SENSE AI — Rate Limiter
Controls how many requests a single user (by IP address) can make per minute.
Prevents abuse, server overload, and brute-force scanning attacks.

Uses: flask-limiter library
Install: pip install flask-limiter
"""

from flask_limiter import Limiter

from flask_limiter.util import get_remote_address


# ── Initialize Limiter ────────────────────────────────────────────────────────
# get_remote_address: identifies each user by their IP address
# Default limit applies to ALL routes unless overridden per route
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Stores rate limit counts in memory
                               # For production: use "redis://localhost:6379"
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


# ── Rate Limit Decorators ─────────────────────────────────────────────────────
# Import and apply these directly on routes in app.py

# For home page — very relaxed
# Usage: @home_limit on the / route
home_limit = limiter.limit("60 per minute")

# For scan routes — moderate limit
# Usage: @scan_limit on /scan/message, /scan/link, /scan/screenshot
scan_limit = limiter.limit("10 per minute")

# For report submission — strict limit
# Usage: @report_limit on /report POST route
report_limit = limiter.limit("5 per minute")

# For stats page — relaxed
# Usage: @stats_limit on /stats route
stats_limit = limiter.limit("30 per minute")


# ── Rate Limit Error Response ─────────────────────────────────────────────────
def get_rate_limit_error_message() -> str:
    """
    Returns a user-friendly message shown when rate limit is exceeded.
    Called by the 429 error handler in error_handlers/handlers.py
    """
    return (
        "You have made too many requests in a short time. "
        "Please wait 1 minute before scanning again."
    )


# ── Per-Route Limit Reference ─────────────────────────────────────────────────
"""
How to apply limits in app.py:

    from middleware.rate_limiter import limiter, scan_limit, report_limit

    # Option 1: Use pre-defined decorator
    @app.route("/scan/message", methods=["POST"])
    @scan_limit
    def scan_message():
        ...

    # Option 2: Define custom limit inline
    @app.route("/scan/link", methods=["POST"])
    @limiter.limit("10 per minute")
    def scan_link():
        ...

    # Option 3: Exempt a route from all limits (e.g. health check)
    @app.route("/health")
    @limiter.exempt
    def health_check():
        ...
"""