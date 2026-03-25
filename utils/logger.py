"""
SCAM SENSE AI — Scan Logger
Records every scan with FULL AI assessment result into the SQLite database.
Stores: input type, risk level, risk score, AI explanation,
        content preview, detection source, and timestamp.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join("database", "scans.db")


# ══════════════════════════════════════════════════════════════════════════════
# LOG SCAN — Saves full AI result after every scan
# ══════════════════════════════════════════════════════════════════════════════

def log_scan(
    input_type      : str,
    risk_level      : str,
    risk_score      : int  = 0,
    explanation     : str  = "",
    content_preview : str  = "",
    source          : str  = "",
) -> bool:
    """
    Log a completed scan with full AI assessment result to database.

    Args:
        input_type      : "message", "link", or "screenshot"
        risk_level      : "SAFE", "SUSPICIOUS", or "DANGEROUS"
        risk_score      : AI risk score 0-100
        explanation     : AI explanation of why it was flagged
        content_preview : First 300 chars of scanned content
        source          : "ai-engine" or "rule-based-fallback"

    Returns:
        True if saved successfully, False otherwise.
    """
    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
                (input_type, risk_level, risk_score,
                 explanation, content_preview, source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                input_type,
                risk_level,
                int(risk_score),
                explanation.strip(),
                content_preview[:300],          # Never store more than 300 chars
                source,
                datetime.now().isoformat(),
            ),
        )

        conn.commit()
        conn.close()

        print(
            f"[LOGGER] Scan saved — "
            f"Type: {input_type} | "
            f"Risk: {risk_level} | "
            f"Score: {risk_score} | "
            f"Source: {source}"
        )
        return True

    except sqlite3.OperationalError as e:
        print(f"[LOGGER ERROR] Database table not found: {e}")
        print("               Run: python database/init_db.py")
        return False

    except Exception as e:
        print(f"[LOGGER ERROR] Could not save scan: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# LOG REPORT — Saves user submitted scam report
# ══════════════════════════════════════════════════════════════════════════════

def log_report(content: str, report_type: str) -> bool:
    """
    Save a user submitted scam report to the database.

    Args:
        content     : The scam content submitted by user
        report_type : "message", "link", "call", "screenshot", or "other"

    Returns:
        True if saved successfully, False otherwise.
    """
    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO reports (content, report_type, timestamp)
            VALUES (?, ?, ?)
            """,
            (content.strip(), report_type, datetime.now().isoformat()),
        )

        conn.commit()
        conn.close()

        print(f"[LOGGER] Report saved — Type: {report_type}")
        return True

    except Exception as e:
        print(f"[LOGGER ERROR] Could not save report: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# GET SCAN SUMMARY — Risk level counts for stats page
# ══════════════════════════════════════════════════════════════════════════════

def get_scan_summary() -> dict:
    """
    Fetch scan counts grouped by risk level.
    Used by the stats dashboard.

    Returns:
        dict with keys: total, safe, suspicious, dangerous
    """
    summary = {
        "total"      : 0,
        "safe"       : 0,
        "suspicious" : 0,
        "dangerous"  : 0,
    }

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level"
        )
        rows = cursor.fetchall()
        conn.close()

        for risk_level, count in rows:
            summary["total"] += count
            key = risk_level.lower()
            if key in summary:
                summary[key] = count

    except Exception as e:
        print(f"[LOGGER ERROR] Could not fetch summary: {e}")

    return summary


# ══════════════════════════════════════════════════════════════════════════════
# GET RECENT SCANS — Full scan records for stats table
# ══════════════════════════════════════════════════════════════════════════════

def get_recent_scans(limit: int = 50) -> list:
    """
    Fetch the most recent scans including full AI result details.
    Used by the stats dashboard table.

    Args:
        limit: Number of recent scans to return (default 50)

    Returns:
        List of tuples:
        (input_type, risk_level, risk_score, explanation, content_preview, source, timestamp)
    """
    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                input_type,
                risk_level,
                risk_score,
                explanation,
                content_preview,
                source,
                timestamp
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()
        return rows

    except Exception as e:
        print(f"[LOGGER ERROR] Could not fetch recent scans: {e}")
        return []