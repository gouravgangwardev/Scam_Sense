"""
SCAM SENSE AI — Database Initializer
Run this file ONCE before starting the server.
Creates the SQLite database and all required tables.

Usage:
    python database/init_db.py
"""

import sqlite3
import os


DB_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "scans.db")


def initialize_database():
    """
    Create the SQLite database and all tables if they do not already exist.
    Safe to run multiple times — will not overwrite existing data.
    """
    print("=" * 55)
    print("  SCAM SENSE AI — Database Initializer")
    print("=" * 55)

    os.makedirs(DB_DIR, exist_ok=True)

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        print(f"\n[DB] Connected to: {DB_PATH}")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type      TEXT    NOT NULL,
                risk_level      TEXT    NOT NULL,
                risk_score      INTEGER DEFAULT 0,
                explanation     TEXT    DEFAULT '',
                content_preview TEXT    DEFAULT '',
                source          TEXT    DEFAULT '',
                timestamp       TEXT    NOT NULL
            )
        """)
        print("[DB] Table 'scans'         — OK")
        print("     Columns: id, input_type, risk_level, risk_score,")
        print("              explanation, content_preview, source, timestamp")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                content     TEXT    NOT NULL,
                report_type TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL
            )
        """)
        print("[DB] Table 'reports'       — OK")

       
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_links (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                risk_score  INTEGER NOT NULL,
                explanation TEXT    DEFAULT '',
                timestamp   TEXT    NOT NULL
            )
        """)
        print("[DB] Table 'blocked_links' — OK")

        conn.commit()

      
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"\n[DB] Tables in database : {', '.join(tables)}")

        conn.close()

        print(f"\n[DB] Database ready at  : {DB_PATH}")
        print("=" * 55)
        return True

    except sqlite3.Error as e:
        print(f"\n[DB ERROR] SQLite error: {e}")
        return False

    except Exception as e:
        print(f"\n[DB ERROR] Unexpected error: {e}")
        return False


def check_database_exists() -> bool:
    """
    Check if the database file already exists on disk.

    Returns:
        True if scans.db exists, False if not.
    """
    return os.path.exists(DB_PATH)


def get_table_counts() -> dict:
    """
    Get current row counts for all tables.

    Returns:
        dict — table name as key, row count as value.
    """
    counts = {}

    if not check_database_exists():
        print("[DB] Database does not exist. Run initialize_database() first.")
        return counts

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        for table in ["scans", "reports", "blocked_links"]:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                counts[table] = cursor.fetchone()[0]
            except sqlite3.OperationalError:
                counts[table] = "TABLE NOT FOUND"

        conn.close()

    except Exception as e:
        print(f"[DB ERROR] Could not get table counts: {e}")

    return counts


def reset_database():
    """
    Drop all tables and recreate them from scratch.
    WARNING: This permanently deletes ALL data.
    Only use during development or testing.
    """
    print("\n⚠️  WARNING: This will permanently delete ALL data.")
    confirm = input("    Type 'YES' to confirm reset: ")

    if confirm.strip() != "YES":
        print("[DB] Reset cancelled. No data was deleted.")
        return False

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("DROP TABLE IF EXISTS scans")
        cursor.execute("DROP TABLE IF EXISTS reports")
        cursor.execute("DROP TABLE IF EXISTS blocked_links")
        conn.commit()
        conn.close()

        print("[DB] All tables dropped.")
        initialize_database()
        print("[DB] Database reset complete.")
        return True

    except Exception as e:
        print(f"[DB ERROR] Reset failed: {e}")
        return False



if __name__ == "__main__":

    initialize_database()

    print("\n[DB] Current row counts:")
    counts = get_table_counts()
    for table, count in counts.items():
        print(f"     {table}: {count} rows")
