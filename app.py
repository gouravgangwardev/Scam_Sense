"""
SCAM SENSE AI — Main Flask Application
All routes, error handlers, and app initialization in one place.
"""

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, jsonify
)
import os
import re
from werkzeug.utils import secure_filename

# ── Internal Imports ──────────────────────────────────────────────────────────
import config
from utils.ai_client       import analyze_with_ai
from utils.ocr_handler     import extract_text_from_image
from utils.link_checker    import check_link
from utils.logger          import log_scan, log_report, get_scan_summary, get_recent_scans
from utils.validators      import validate_message, validate_url, validate_file, validate_report
from utils.file_cleanup    import delete_file, cleanup_old_files
from utils.fallback_rules  import full_fallback_result
from utils.request_guard   import sanitize_text
from middleware.rate_limiter   import init_limiter, limiter, scan_limit, report_limit, home_limit, stats_limit
from error_handlers.handlers  import register_error_handlers
from database.init_db         import initialize_database


# ── Create Flask App ──────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Apply Config ──────────────────────────────────────────────────────────────
app.secret_key                        = config.SECRET_KEY
app.config["UPLOAD_FOLDER"]           = config.UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"]      = config.MAX_CONTENT_LENGTH
app.config["SESSION_COOKIE_SECURE"]   = config.SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE

# ── Register Middleware and Error Handlers ────────────────────────────────────
init_limiter(app)
register_error_handlers(app)

# ── Ensure uploads folder exists ──────────────────────────────────────────────
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ── Helper: Render Error Page ─────────────────────────────────────────────────
def render_error(code, title, message):
    """Centralized error page renderer — always uses correct template variables."""
    return render_template(
        "error.html",
        error_code=code,
        error_title=title,
        error_message=message,
        show_home_button=True,
    ), code


# ── Helper: Slim down result for session storage ──────────────────────────────
def slim_result(result: dict) -> dict:
    """
    Store only essential fields in session to avoid cookie overflow.
    Full result is kept for immediate redirect use only.
    """
    explanation = result.get("explanation", [])
    # Convert list to joined string if needed for session safety
    if isinstance(explanation, list):
        explanation_str = " | ".join(explanation)
    else:
        explanation_str = str(explanation)

    return {
        "risk_level":       result.get("risk_level", "SUSPICIOUS"),
        "risk_score":       int(result.get("risk_score", 50)),
        "explanation":      explanation_str[:800],   # cap size
        "matched_patterns": result.get("matched_patterns", [])[:10],
        "color":            result.get("color", "orange"),
        "source":           result.get("source", "unknown"),
    }


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 1 — Home Page
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/")
@home_limit
def home():
    """Main landing page with three scan forms."""
    return render_template("index.html")


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 2 — Scan Message
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/scan/message", methods=["POST"])
@scan_limit
def scan_message():
    """
    Receives pasted suspicious message text.
    Validates → Sanitize → AI Analysis → Save result to DB → Show Result
    """
    message_text = request.form.get("message_text", "").strip()

    # Step 1: Validate input
    is_valid, error = validate_message(message_text)
    if not is_valid:
        return render_error(400, "Invalid Input", error)

    # Step 2: Sanitize input
    message_text = sanitize_text(message_text)

    # Step 3: Get guardian mode and language from form
    guardian = request.form.get("guardian", "false").lower() == "true"
    lang     = request.form.get("lang", "en")
    if lang not in ("en", "hi", "es"):
        lang = "en"

    # Step 4: Send to AI for analysis (with fallback on any failure)
    try:
        result = analyze_with_ai(
            input_type = "message",
            content    = message_text,
            guardian   = guardian,
            lang       = lang,
        )
    except Exception as e:
        print(f"[APP] AI failed for message scan: {e}. Using fallback.")
        result = full_fallback_result(message_text, source="fallback")

    # Step 5: Save result to database
    log_scan(
        input_type      = "message",
        risk_level      = result["risk_level"],
        risk_score      = result.get("risk_score", 0),
        explanation     = str(result.get("explanation", ""))[:500],
        content_preview = message_text[:300],
        source          = result.get("source", ""),
    )

    # Step 6: Store slim result in session and redirect
    session["scan_result"]   = slim_result(result)
    session["input_preview"] = message_text[:300]
    session["input_type"]    = "message"

    return redirect(url_for("result_page"))


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 3 — Scan Link / URL
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/scan/link", methods=["POST"])
@scan_limit
def scan_link():
    """
    Receives pasted suspicious URL.
    Validates → Pattern Check → AI Analysis → Save result to DB → Show Result
    """
    url = request.form.get("url", "").strip()

    # Auto-prepend https:// if missing
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Step 1: Validate URL format
    is_valid, error = validate_url(url)
    if not is_valid:
        return render_error(400, "Invalid URL", error)

    # Step 2: Get language from form
    lang = request.form.get("lang", "en")
    if lang not in ("en", "hi", "es"):
        lang = "en"

    # Step 3: Quick pattern-based check before AI
    link_metadata = check_link(url)

    # Step 4: If domain is in safe whitelist — skip AI entirely
    if link_metadata.get("is_safe_domain"):
        result = {
            "risk_level":       "SAFE",
            "risk_score":       0,
            "explanation":      ["✅ This domain is on the verified safe list."],
            "matched_patterns": [],
            "color":            "green",
            "source":           "whitelist",
        }
    else:
        # Step 5: Send to AI with fallback on failure
        try:
            result = analyze_with_ai(
                input_type = "link",
                content    = url,
                metadata   = link_metadata,
                lang       = lang,
            )
        except Exception as e:
            print(f"[APP] AI failed for link scan: {e}. Using fallback.")
            from utils.ai_client import rule_based_link
            result = rule_based_link(url)

    # Step 6: If DANGEROUS — save to blocked_links table
    if result["risk_level"] == "DANGEROUS":
        _save_blocked_link(
            url         = url,
            risk_score  = result.get("risk_score", 0),
            explanation = str(result.get("explanation", ""))[:500],
        )

    # Step 7: Save result to scans table
    log_scan(
        input_type      = "link",
        risk_level      = result["risk_level"],
        risk_score      = result.get("risk_score", 0),
        explanation     = str(result.get("explanation", ""))[:500],
        content_preview = url[:300],
        source          = result.get("source", ""),
    )

    # Step 8: Store slim result in session and redirect
    session["scan_result"]   = slim_result(result)
    session["input_preview"] = url
    session["input_type"]    = "link"

    return redirect(url_for("result_page"))


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 4 — Scan Screenshot
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/scan/screenshot", methods=["POST"])
@scan_limit
def scan_screenshot():
    """
    Receives uploaded screenshot image.
    Validates → Secure Save → OCR → Fallback Rules → Delete File → Save result → Show Result
    NOTE: AI is intentionally disabled for screenshots. Fallback rules are used.
    """
    # Step 1: Check file was submitted
    if "screenshot" not in request.files:
        return render_error(400, "No File Uploaded", "No file was uploaded. Please select a screenshot.")

    file = request.files["screenshot"]

    if file.filename == "":
        return render_error(400, "No File Selected", "No file was selected. Please choose an image.")

    # Step 2: Validate file type and size
    is_valid, error = validate_file(file.filename, file)
    if not is_valid:
        return render_error(400, "Invalid File", error)

    # Step 3: Secure filename to prevent path traversal attacks
    safe_name = secure_filename(file.filename)
    if not safe_name:
        return render_error(400, "Invalid Filename", "The uploaded filename is not valid.")

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    file.save(filepath)

    # Step 4: OCR — extract text from uploaded image
    extracted_text = extract_text_from_image(filepath)

    # Step 5: Delete uploaded file IMMEDIATELY after OCR
    delete_file(filepath)

    # Step 6: Check OCR returned usable text
    if not extracted_text or not extracted_text.strip():
        return render_error(
            "OCR",
            "Could Not Read Image",
            "Could not extract text from this image. Please upload a clear, readable screenshot."
        )

    # Step 7: Sanitize OCR text
    extracted_text = sanitize_text(extracted_text)

    # Step 8: Use fallback rules (AI is NOT used for screenshots)
    result = full_fallback_result(extracted_text, source="ocr_fallback")

    # Step 9: Save result to database
    log_scan(
        input_type      = "screenshot",
        risk_level      = result["risk_level"],
        risk_score      = result.get("risk_score", 0),
        explanation     = str(result.get("explanation", ""))[:500],
        content_preview = extracted_text[:300],
        source          = result.get("source", ""),
    )

    # Step 10: Store slim result in session and redirect
    session["scan_result"]   = slim_result(result)
    session["input_preview"] = f"[Screenshot] {extracted_text[:200]}"
    session["input_type"]    = "screenshot"

    return redirect(url_for("result_page"))


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 5 — Result Page
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/result")
def result_page():
    """
    Displays scan result to the user.
    Red screen = DANGEROUS, Orange = SUSPICIOUS, Green = SAFE.
    """
    result     = session.get("scan_result")
    preview    = session.get("input_preview", "")
    input_type = session.get("input_type", "")

    if not result:
        return redirect(url_for("home"))

    # Ensure explanation is always a list for template rendering
    explanation = result.get("explanation", "")
    if isinstance(explanation, str):
        result["explanation"] = [e.strip() for e in explanation.split("|") if e.strip()]

    return render_template(
        "result.html",
        result     = result,
        preview    = preview,
        input_type = input_type,
    )


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 6 — Report a Scam
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/report", methods=["GET", "POST"])
@report_limit
def report_scam():
    """
    GET  — Show the scam report submission form.
    POST — Validate and save the user report to database.
    """
    if request.method == "POST":
        content     = sanitize_text(request.form.get("report_content", "").strip())
        report_type = request.form.get("report_type", "other").strip()

        is_valid, error = validate_report(content, report_type)
        if not is_valid:
            return render_error(400, "Invalid Report", error)

        log_report(content=content, report_type=report_type)

        return render_template("report_success.html")

    return render_template("report.html")


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 7 — Statistics Dashboard
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/stats")
@stats_limit
def stats():
    """
    Shows scan statistics from the database.
    Total scans, risk breakdown, and recent scan log.
    """
    summary      = get_scan_summary()
    recent_scans = get_recent_scans(limit=50)

    return render_template(
        "stats.html",
        summary      = summary,
        recent_scans = recent_scans,
    )


# ═════════════════════════════════════════════════════════════════════════════
# ROUTE 8 — Health Check
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/health")
@limiter.exempt
def health_check():
    """Simple health check endpoint. No rate limit."""
    return jsonify({
        "status":     "ok",
        "app":        "Scam Sense AI",
        "message_ai": config.MESSAGE_AI_URL,
        "link_ai":    config.LINK_AI_URL,
    }), 200


# ═════════════════════════════════════════════════════════════════════════════
# HELPER — Save Blocked Link to Database
# ═════════════════════════════════════════════════════════════════════════════
def _save_blocked_link(url: str, risk_score: int, explanation: str = ""):
    """
    Save a DANGEROUS URL to blocked_links table.
    Uses context manager to ensure proper connection cleanup.
    """
    import sqlite3
    from datetime import datetime

    try:
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                """
                INSERT INTO blocked_links (url, risk_score, explanation, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (url, int(risk_score), explanation, datetime.now().isoformat()),
            )
        print(f"[APP] Blocked link saved: {url}")

    except Exception as e:
        print(f"[APP] Could not save blocked link: {e}")
