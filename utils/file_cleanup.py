"""
SCAM SENSE AI — File Cleanup
Deletes uploaded screenshot files immediately after OCR is complete.
Also provides a safety cleanup for files older than 60 minutes.
"""

import os
import time
from datetime import datetime


# ── Delete Single File After Scan ─────────────────────────────────────────────
def delete_file(filepath: str) -> bool:
    """
    Delete a single uploaded file after OCR extraction is done.

    Args:
        filepath: Full path to the file to delete

    Returns:
        True if deleted successfully, False otherwise.
    """
    try:
        if not filepath:
            print("[CLEANUP] No filepath provided. Skipping.")
            return False

        if not os.path.exists(filepath):
            print(f"[CLEANUP] File not found (already deleted?): {filepath}")
            return True  # Not an error — file is already gone

        os.remove(filepath)
        print(f"[CLEANUP] Deleted file: {filepath}")
        return True

    except PermissionError:
        print(f"[CLEANUP ERROR] Permission denied when deleting: {filepath}")
        return False

    except Exception as e:
        print(f"[CLEANUP ERROR] Could not delete file {filepath}: {e}")
        return False


# ── Safety Cleanup: Delete Old Files ─────────────────────────────────────────
def cleanup_old_files(folder: str, max_age_minutes: int = 60) -> int:
    """
    Delete all files in the uploads folder older than max_age_minutes.
    This is a safety net in case delete_file() was not called properly.

    Args:
        folder          : Path to the uploads folder
        max_age_minutes : Files older than this are deleted (default: 60 min)

    Returns:
        Number of files deleted.
    """
    if not os.path.exists(folder):
        print(f"[CLEANUP] Uploads folder not found: {folder}")
        return 0

    deleted_count = 0
    now = time.time()
    max_age_seconds = max_age_minutes * 60

    try:
        for filename in os.listdir(folder):
            # Skip hidden files like .gitkeep
            if filename.startswith("."):
                continue

            filepath = os.path.join(folder, filename)

            # Only process files, not subdirectories
            if not os.path.isfile(filepath):
                continue

            try:
                # Get file's last modification time
                file_age_seconds = now - os.path.getmtime(filepath)

                if file_age_seconds > max_age_seconds:
                    os.remove(filepath)
                    deleted_count += 1
                    print(f"[CLEANUP] Removed old file: {filename} "
                          f"(age: {int(file_age_seconds // 60)} min)")

            except Exception as e:
                print(f"[CLEANUP ERROR] Could not process file {filename}: {e}")

    except Exception as e:
        print(f"[CLEANUP ERROR] Could not read uploads folder: {e}")

    if deleted_count > 0:
        print(f"[CLEANUP] Safety cleanup complete — {deleted_count} file(s) removed.")
    else:
        print("[CLEANUP] Safety cleanup complete — no old files found.")

    return deleted_count


# ── Clear Entire Uploads Folder ───────────────────────────────────────────────
def clear_uploads_folder(folder: str) -> int:
    """
    Delete ALL files in the uploads folder.
    Used for testing or manual reset.

    Args:
        folder: Path to the uploads folder

    Returns:
        Number of files deleted.
    """
    if not os.path.exists(folder):
        print(f"[CLEANUP] Uploads folder not found: {folder}")
        return 0

    deleted_count = 0

    try:
        for filename in os.listdir(folder):
            if filename.startswith("."):
                continue

            filepath = os.path.join(folder, filename)

            if os.path.isfile(filepath):
                try:
                    os.remove(filepath)
                    deleted_count += 1
                except Exception as e:
                    print(f"[CLEANUP ERROR] Could not delete {filename}: {e}")

    except Exception as e:
        print(f"[CLEANUP ERROR] {e}")

    print(f"[CLEANUP] Cleared uploads folder — {deleted_count} file(s) removed.")
    return deleted_count