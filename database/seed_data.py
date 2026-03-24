"""
SCAM SENSE AI — Database Seeder
Inserts sample scan records into the database for demo purposes.
Run this ONCE after init_db.py to populate the stats page.

Usage:
    python database/seed_data.py
"""

import sqlite3
import os
from datetime import datetime, timedelta

# ── Database Path ─────────────────────────────────────────────────────────────
DB_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "scans.db")


# ══════════════════════════════════════════════════════════════════════════════
# SAMPLE SCAN DATA
# Format: (input_type, risk_level, risk_score, explanation, content_preview, source)
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_SCANS = [

    # ── DANGEROUS — Bank Impersonation ────────────────────────────────────────
    (
        "message", "DANGEROUS", 94,
        "This message impersonates SBI bank and requests the user to share "
        "their OTP immediately. Real banks never ask for OTP over SMS or call. "
        "This is a classic KYC fraud attempt.",
        "Dear SBI Customer, your account has been blocked due to incomplete KYC. "
        "Share your OTP immediately to unblock: Call 9876543210.",
        "ai-engine"
    ),

    # ── DANGEROUS — Phishing Link ─────────────────────────────────────────────
    (
        "link", "DANGEROUS", 91,
        "This URL impersonates the HDFC Bank login page on a suspicious .xyz domain. "
        "The domain contains brand name with fake verification keyword. "
        "Entering credentials here will result in account theft.",
        "http://hdfc-secure-login.xyz/customer/verify-now",
        "ai-engine"
    ),

    # ── DANGEROUS — Lottery Scam Screenshot ──────────────────────────────────
    (
        "screenshot", "DANGEROUS", 96,
        "Screenshot contains a fake lottery winning notice. "
        "It requests a processing fee of Rs 500 to release the prize money. "
        "No legitimate lottery asks winners to pay fees upfront.",
        "CONGRATULATIONS! You have been selected as lucky winner of Rs 10,00,000. "
        "Pay Rs 500 processing fee to claim your prize. Contact us immediately.",
        "ai-engine"
    ),

    # ── DANGEROUS — Income Tax Impersonation ─────────────────────────────────
    (
        "message", "DANGEROUS", 89,
        "This message impersonates the Income Tax Department of India and "
        "threatens arrest to create fear and urgency. "
        "Government departments never send payment demands via SMS.",
        "URGENT: Income Tax Department. You have unpaid dues of Rs 12,500. "
        "Pay immediately or face arrest warrant. Call 011-XXXXXXXX.",
        "ai-engine"
    ),

    # ── DANGEROUS — Raw IP Phishing URL ──────────────────────────────────────
    (
        "link", "DANGEROUS", 87,
        "This URL uses a raw IP address as the domain which is a strong "
        "indicator of a phishing site. Legitimate banks and payment services "
        "never use IP addresses in their URLs.",
        "http://192.168.10.45/paytm/kyc/update/verify-account",
        "ai-engine"
    ),

    # ── DANGEROUS — Fake Police Threat ───────────────────────────────────────
    (
        "message", "DANGEROUS", 93,
        "Message impersonates cybercrime police and threatens legal action "
        "to extort money. This is a known police impersonation scam. "
        "Real police never demand money via phone or SMS.",
        "Cyber Crime Department: A case has been filed against your number "
        "for illegal activity. Pay Rs 5000 fine immediately to avoid arrest.",
        "ai-engine"
    ),

    # ── SUSPICIOUS — Fake Job Offer ───────────────────────────────────────────
    (
        "message", "SUSPICIOUS", 52,
        "Message contains work-from-home job offer with unrealistic daily earnings. "
        "No experience or qualification mentioned. "
        "Verify this offer through official channels before proceeding.",
        "Part time work from home job. Earn Rs 5000 daily. "
        "No experience needed. WhatsApp your details to 9XXXXXXXXX.",
        "ai-engine"
    ),

    # ── SUSPICIOUS — Fake Government Scheme ───────────────────────────────────
    (
        "screenshot", "SUSPICIOUS", 48,
        "Screenshot contains an unverified government scheme offering free cash. "
        "The offer uses urgency language and limited time pressure. "
        "Verify through official government portals before applying.",
        "PM Jan Kalyan Yojana: Apply now and get Rs 25000 free in your account. "
        "Limited time offer. Click link before midnight tonight.",
        "rule-based-fallback"
    ),

    # ── SUSPICIOUS — Too Good To Be True Offer ────────────────────────────────
    (
        "link", "SUSPICIOUS", 44,
        "URL leads to a page offering unrealistic discounts on branded products. "
        "Domain name does not match the brand being advertised. "
        "High risk of payment fraud or data theft.",
        "http://amazon-special-offer-today.co/iphone-free-99percent-off",
        "ai-engine"
    ),

    # ── SUSPICIOUS — Advance Fee Fraud ───────────────────────────────────────
    (
        "message", "SUSPICIOUS", 55,
        "Message contains advance fee fraud indicators. "
        "Promises large reward in exchange for a small upfront payment. "
        "This is a classic 419 advance fee scam pattern.",
        "You have been selected for a Rs 2 lakh gift. "
        "Pay Rs 200 registration fee to claim. Offer expires today.",
        "ai-engine"
    ),

    # ── SAFE — Delivery Notification ─────────────────────────────────────────
    (
        "message", "SAFE", 4,
        "No scam indicators detected. Message appears to be a standard "
        "delivery update notification. No payment requests, no urgency tactics, "
        "no credential requests found.",
        "Your order #OD123456789 has been shipped. "
        "Expected delivery: Tomorrow between 10am and 2pm.",
        "ai-engine"
    ),

    # ── SAFE — Bank Transaction Alert ────────────────────────────────────────
    (
        "message", "SAFE", 3,
        "Standard bank transaction SMS. Contains masked account details "
        "and transaction amount. No suspicious links or payment requests found. "
        "This is a normal debit notification.",
        "Rs 500.00 debited from A/c XX1234 on 21-Feb-24. "
        "Available balance: Rs 12,450. Not you? Call 1800-XXX-XXXX.",
        "ai-engine"
    ),

    # ── SAFE — Official Website URL ───────────────────────────────────────────
    (
        "link", "SAFE", 2,
        "Domain is on the verified safe whitelist. "
        "No phishing patterns, suspicious TLD, or impersonation detected. "
        "This is an official government website.",
        "https://www.incometax.gov.in/iec/foportal",
        "ai-engine"
    ),

    # ── SAFE — OTP Confirmation ───────────────────────────────────────────────
    (
        "message", "SAFE", 6,
        "Standard OTP message from a known service. "
        "No external links, no payment requests, no urgency tactics. "
        "OTP messages with no links are generally safe.",
        "Your OTP for login is 847291. "
        "Valid for 10 minutes. Do not share with anyone.",
        "ai-engine"
    ),

    # ── SAFE — Screenshot of Normal Message ──────────────────────────────────
    (
        "screenshot", "SAFE", 5,
        "Screenshot contains a normal appointment reminder message. "
        "No scam indicators, payment requests, or suspicious links detected.",
        "Reminder: Your appointment at City Hospital is confirmed for "
        "22-Feb-2024 at 11:00 AM. Please carry your ID proof.",
        "ai-engine"
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# SAMPLE REPORTS DATA
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_REPORTS = [
    (
        "Received call from someone claiming to be RBI officer. "
        "Asked me to transfer money to verify my account. "
        "Number: +91-XXXXXXXXXX",
        "call"
    ),
    (
        "Got a WhatsApp message saying I won an iPhone in a lucky draw. "
        "They asked for Rs 1000 shipping fee. "
        "Message came from an unknown number.",
        "message"
    ),
    (
        "Received link http://sbi-kyc-verify.tk asking me to update KYC. "
        "Looks fake — real SBI website is sbi.co.in",
        "link"
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# SEED FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def seed_database():
    """
    Insert all sample scan and report records into the database.
    Records are spaced 25 minutes apart to look natural.
    """
    print("=" * 55)
    print("  SCAM SENSE AI — Database Seeder")
    print("=" * 55)

    # Check database exists
    if not os.path.exists(DB_PATH):
        print("\n[SEED ERROR] Database not found.")
        print("             Run first: python database/init_db.py")
        return False

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # ── Check if already seeded ───────────────────────────────────────────
        cursor.execute("SELECT COUNT(*) FROM scans")
        existing_count = cursor.fetchone()[0]

        if existing_count > 0:
            print(f"\n[SEED] Database already has {existing_count} scan records.")
            confirm = input("       Add sample data anyway? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("[SEED] Seeding cancelled.")
                conn.close()
                return False

        # ── Insert sample scans ───────────────────────────────────────────────
        print("\n[SEED] Inserting sample scan records...")

        for i, scan in enumerate(SAMPLE_SCANS):
            # Space timestamps 25 minutes apart going backwards
            # So records look like they happened over the past few hours
            timestamp = (
                datetime.now() - timedelta(minutes=25 * i)
            ).isoformat()

            cursor.execute(
                """
                INSERT INTO scans
                    (input_type, risk_level, risk_score,
                     explanation, content_preview, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (*scan, timestamp)
            )

        print(f"[SEED] {len(SAMPLE_SCANS)} scan records inserted.")

        # ── Insert sample reports ─────────────────────────────────────────────
        print("[SEED] Inserting sample report records...")

        for i, report in enumerate(SAMPLE_REPORTS):
            timestamp = (
                datetime.now() - timedelta(hours=2, minutes=30 * i)
            ).isoformat()

            cursor.execute(
                """
                INSERT INTO reports (content, report_type, timestamp)
                VALUES (?, ?, ?)
                """,
                (*report, timestamp)
            )

        print(f"[SEED] {len(SAMPLE_REPORTS)} report records inserted.")

        conn.commit()
        conn.close()

        # ── Summary ───────────────────────────────────────────────────────────
        dangerous  = sum(1 for s in SAMPLE_SCANS if s[1] == "DANGEROUS")
        suspicious = sum(1 for s in SAMPLE_SCANS if s[1] == "SUSPICIOUS")
        safe       = sum(1 for s in SAMPLE_SCANS if s[1] == "SAFE")

        print("\n[SEED] ── Summary ──────────────────────────────")
        print(f"[SEED] Total scans inserted : {len(SAMPLE_SCANS)}")
        print(f"[SEED] DANGEROUS            : {dangerous}")
        print(f"[SEED] SUSPICIOUS           : {suspicious}")
        print(f"[SEED] SAFE                 : {safe}")
        print(f"[SEED] Reports inserted     : {len(SAMPLE_REPORTS)}")
        print("[SEED] ────────────────────────────────────────")
        print("\n[SEED] Done. Visit /stats to see the data.")
        print("=" * 55)
        return True

    except sqlite3.OperationalError as e:
        print(f"\n[SEED ERROR] Table not found: {e}")
        print("             Run first: python database/init_db.py")
        return False

    except Exception as e:
        print(f"\n[SEED ERROR] {e}")
        return False


# ── Run directly ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    seed_database()
