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


# ── Step 3: Check logs/ folder exists ────────────────────────────────────────
if not os.path.exists("logs"):
    os.makedirs("logs")
    print("[OK] logs/ folder created.")
else:
    print("[OK] logs/ folder found.")


# ── Step 4: Initialize database ──────────────────────────────────────────────
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


# ── Step 5: Run safety cleanup on uploads folder ─────────────────────────────
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


# ── Step 6: Check AI servers are running ─────────────────────────────────────
print("\n[AI] Checking AI servers...")

import requests as _requests

message_ai_online = False
link_ai_online    = False

try:
    resp = _requests.get("http://localhost:5001/health", timeout=3)
    if resp.status_code == 200:
        message_ai_online = True
        print("[AI] message_ai server → ONLINE ✅")
    else:
        print(f"[AI] message_ai server → responded {resp.status_code} ⚠️  (fallback will be used)")
except Exception:
    print("[AI] message_ai server → OFFLINE ⚠️  (rule-based fallback will be used)")

try:
    resp = _requests.get("http://localhost:5002/health", timeout=3)
    if resp.status_code == 200:
        link_ai_online = True
        print("[AI] link_ai server    → ONLINE ✅")
    else:
        print(f"[AI] link_ai server    → responded {resp.status_code} ⚠️  (fallback will be used)")
except Exception:
    print("[AI] link_ai server    → OFFLINE ⚠️  (rule-based fallback will be used)")

if not message_ai_online and not link_ai_online:
    print("[AI] Both AI servers offline — running in full fallback mode.")
    print("[AI] Screenshot scans will still work via OCR + rule-based detection.")


# ── Step 7: Start Flask app ───────────────────────────────────────────────────
print("\n[APP] Starting Flask server...")
print("=" * 55)

try:
    from dotenv import load_dotenv
    load_dotenv()

    port  = int(os.getenv("PORT", 8080))
    debug = os.getenv("DEBUG", "True").lower() == "true"

    print(f"[APP] Mode         : {'Development' if debug else 'Production'}")
    print(f"[APP] Port         : {port}")
    print(f"[APP] URL          : http://localhost:{port}")
    print(f"[APP] Message AI   : http://localhost:5001  ({'ONLINE' if message_ai_online else 'OFFLINE — fallback'})")
    print(f"[APP] Link AI      : http://localhost:5002  ({'ONLINE' if link_ai_online else 'OFFLINE — fallback'})")
    print(f"[APP] Screenshot   : OCR + rule-based (AI disabled for images)")
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
