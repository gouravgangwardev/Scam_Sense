"""
SCAM SENSE AI — Startup Script
Runs everything in the correct order with a single command.

Usage:
    python run.py
"""

import os
import sys

print("=" * 55)
print("        SCAM SENSE AI — Starting Up")
print("=" * 55)


# ── Step 1: Check .env file exists ───────────────────────────────────────────
if not os.path.exists(".env"):
    print("\n[WARNING] .env file not found.")
    print("          Creating a default .env file...")

    with open(".env", "w") as f:
        f.write("SECRET_KEY=scam-sense-change-this-key-in-production\n")
        f.write("MESSAGE_AI_URL=http://localhost:5001/predict\n")
        f.write("LINK_AI_URL=http://localhost:5002/predict/url\n")
        f.write("AI_REQUEST_TIMEOUT=10\n")
        f.write("DEBUG=True\n")
        f.write("HOST=0.0.0.0\n")
        f.write("PORT=8080\n")
        f.write("MAX_FILE_SIZE_MB=5\n")
        f.write("MAX_MESSAGE_LENGTH=5000\n")
        f.write("DATABASE_PATH=database/scans.db\n")
        f.write("RATE_LIMIT_SCAN=10\n")
        f.write("UPLOAD_FOLDER=uploads\n")

    print("[OK] .env file created. Edit it before deploying to production.\n")
else:
    print("[OK] .env file found.")


# ── Step 2: Check uploads/ folder exists ─────────────────────────────────────
if not os.path.exists("uploads"):
    os.makedirs("uploads")
    print("[OK] uploads/ folder created.")
else:
    print("[OK] uploads/ folder found.")


# ── Step 3: Initialize database ──────────────────────────────────────────────
print("\n[DB] Checking database...")

try:
    from database.init_db import initialize_database, check_database_exists

    if not check_database_exists():
        print("[DB] Database not found. Creating now...")
        initialize_database()
    else:
        print("[DB] Database already exists. Skipping init.")

except Exception as e:
    print(f"[ERROR] Database initialization failed: {e}")
    print("        Check that database/init_db.py exists.")
    sys.exit(1)


# ── Step 4: Run safety cleanup on uploads folder ─────────────────────────────
print("\n[CLEANUP] Running safety cleanup on uploads folder...")

try:
    from utils.file_cleanup import cleanup_old_files
    deleted = cleanup_old_files("uploads", max_age_minutes=60)

    if deleted == 0:
        print("[CLEANUP] No old files found.")
    else:
        print(f"[CLEANUP] Removed {deleted} old file(s).")

except Exception as e:
    print(f"[WARNING] Cleanup could not run: {e}")


# ── Step 4.5: Check AI servers are running ────────────────────────────────────
print("\n[AI] Checking AI servers...")

import requests as _requests

try:
    _requests.get("http://localhost:5001/health", timeout=3)
    print("[AI] message_ai server → ONLINE ✅")
except Exception:
    print("[AI] message_ai server → OFFLINE ⚠️  (rule-based fallback will be used)")

try:
    _requests.get("http://localhost:5002/health", timeout=3)
    print("[AI] link_ai server    → ONLINE ✅")
except Exception:
    print("[AI] link_ai server    → OFFLINE ⚠️  (rule-based fallback will be used)")


# ── Step 5: Start Flask app ───────────────────────────────────────────────────
print("\n[APP] Starting Flask server...")
print("=" * 55)

try:
    from dotenv import load_dotenv
    load_dotenv()

    port  = int(os.getenv("PORT", 8080))
    debug = os.getenv("DEBUG", "True").lower() == "true"

    print(f"[APP] Mode       : {'Development' if debug else 'Production'}")
    print(f"[APP] Port       : {port}")
    print(f"[APP] URL        : http://localhost:{port}")
    print(f"[APP] Message AI : http://localhost:5001")
    print(f"[APP] Link AI    : http://localhost:5002")
    print("=" * 55)
    print()

    from app import app
    app.run(
        host  = "0.0.0.0",
        port  = port,
        debug = debug,
    )

except KeyboardInterrupt:
    print("\n\n[APP] Server stopped by user.")
    sys.exit(0)

except Exception as e:
    print(f"\n[ERROR] Could not start Flask app: {e}")
    sys.exit(1)