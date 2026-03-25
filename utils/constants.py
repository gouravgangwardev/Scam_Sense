"""
SCAM SENSE AI — Constants
Single source of truth for all hardcoded values used across the system.
Import from here instead of repeating literals in multiple files.
"""

# ── Risk Levels ───────────────────────────────────────────────────────────────
RISK_SAFE       = "SAFE"
RISK_SUSPICIOUS = "SUSPICIOUS"
RISK_DANGEROUS  = "DANGEROUS"

VALID_RISK_LEVELS = (RISK_SAFE, RISK_SUSPICIOUS, RISK_DANGEROUS)

# ── Default Fallback Values ───────────────────────────────────────────────────
DEFAULT_FALLBACK_RISK_LEVEL  = RISK_SUSPICIOUS
DEFAULT_FALLBACK_SCORE       = 50
DEFAULT_FALLBACK_EXPLANATION = ["AI unavailable — fallback detection used."]
DEFAULT_FALLBACK_SOURCE      = "fallback"

# ── Input Types ───────────────────────────────────────────────────────────────
INPUT_MESSAGE    = "message"
INPUT_LINK       = "link"
INPUT_SCREENSHOT = "screenshot"

VALID_INPUT_TYPES = (INPUT_MESSAGE, INPUT_LINK, INPUT_SCREENSHOT)

# ── Supported Languages ───────────────────────────────────────────────────────
LANG_EN = "en"
LANG_HI = "hi"
LANG_ES = "es"

VALID_LANGUAGES = (LANG_EN, LANG_HI, LANG_ES)
DEFAULT_LANGUAGE = LANG_EN

# ── File Upload ───────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS      = {"jpg", "jpeg", "png"}
ALLOWED_MIME_TYPES      = {"jpeg", "png"}
MAX_FILE_SIZE_MB        = 5
MAX_FILE_SIZE_BYTES     = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_FILENAME_LENGTH     = 100

# ── Input Length Limits ───────────────────────────────────────────────────────
MIN_MESSAGE_LENGTH  = 5
MAX_MESSAGE_LENGTH  = 5000
MAX_URL_LENGTH      = 2000
MIN_REPORT_LENGTH   = 10
MAX_REPORT_LENGTH   = 10000

# ── AI Engine ─────────────────────────────────────────────────────────────────
AI_REQUEST_TIMEOUT    = 10          # seconds
AI_DEFAULT_PORT_MSG   = 5001
AI_DEFAULT_PORT_LINK  = 5002

# ── Risk Score Thresholds ─────────────────────────────────────────────────────
SCORE_DANGEROUS_MIN  = 60
SCORE_SUSPICIOUS_MIN = 25
SCORE_SAFE_MAX       = 24

# ── Session Keys ─────────────────────────────────────────────────────────────
SESSION_SCAN_RESULT    = "scan_result"
SESSION_INPUT_PREVIEW  = "input_preview"
SESSION_INPUT_TYPE     = "input_type"

# ── Database Tables ───────────────────────────────────────────────────────────
TABLE_SCANS         = "scans"
TABLE_REPORTS       = "reports"
TABLE_BLOCKED_LINKS = "blocked_links"

# ── Source Labels ─────────────────────────────────────────────────────────────
SOURCE_AI          = "ai-engine"
SOURCE_WHITELIST   = "whitelist"
SOURCE_FALLBACK    = "rule-based-fallback"
SOURCE_OCR_FALLBACK= "ocr_fallback"

# ── Rate Limits ───────────────────────────────────────────────────────────────
RATE_DEFAULT_DAY   = "200 per day"
RATE_DEFAULT_HOUR  = "50 per hour"
RATE_SCAN          = "10 per minute"
RATE_REPORT        = "5 per minute"
RATE_HOME          = "60 per minute"
RATE_STATS         = "30 per minute"

# ── UI / Preview ──────────────────────────────────────────────────────────────
PREVIEW_MAX_LENGTH = 300

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE_PATH = "logs/app.log"
LOG_FORMAT    = "%(asctime)s | %(levelname)s | %(message)s"
LOG_DATE_FMT  = "%Y-%m-%d %H:%M:%S"
