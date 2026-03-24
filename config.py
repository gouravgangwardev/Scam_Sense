"""
SCAM SENSE AI — Configuration
All app settings loaded from environment variables.
Never hardcode secrets — always use .env file.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Flask Core ────────────────────────────────────────────────────────────────
SECRET_KEY   = os.getenv("SECRET_KEY", "scam-sense-default-key-change-in-production")
DEBUG        = os.getenv("DEBUG", "False").lower() == "true"
PORT         = int(os.getenv("PORT", 8080))
HOST         = os.getenv("HOST", "0.0.0.0")

# ── AI Engine ─────────────────────────────────────────────────────────────────
MESSAGE_AI_URL     = os.getenv("MESSAGE_AI_URL", "http://localhost:5001/predict")
LINK_AI_URL        = os.getenv("LINK_AI_URL",    "http://localhost:5002/predict/url")
AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", 10))

# ── File Upload ───────────────────────────────────────────────────────────────
UPLOAD_FOLDER      = os.path.join(os.path.dirname(__file__), "uploads")
MAX_FILE_SIZE_MB   = int(os.getenv("MAX_FILE_SIZE_MB", 5))
MAX_CONTENT_LENGTH = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "database", "scans.db")

# ── Rate Limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_DEFAULT = "200 per day"
RATE_LIMIT_HOURLY  = "50 per hour"
RATE_LIMIT_SCAN    = "10 per minute"
RATE_LIMIT_REPORT  = "5 per minute"
RATE_LIMIT_HOME    = "60 per minute"

# ── Input Validation ──────────────────────────────────────────────────────────
MAX_MESSAGE_LENGTH = int(os.getenv("MAX_MESSAGE_LENGTH", 5000))
MIN_MESSAGE_LENGTH = 5

# ── Session ───────────────────────────────────────────────────────────────────
SESSION_COOKIE_SECURE      = not DEBUG
SESSION_COOKIE_HTTPONLY    = True
SESSION_COOKIE_SAMESITE    = "Lax"
PERMANENT_SESSION_LIFETIME = 300