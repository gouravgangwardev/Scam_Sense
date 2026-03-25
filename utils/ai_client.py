"""
SCAM SENSE AI — AI Client
Connects to:
  - message_ai server (port 5001) for text/message/screenshot scans
  - link_ai server    (port 5002) for URL scans
Falls back to rule-based detection if any AI server is offline.
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

# ── AI Engine URLs from .env ────────────────────────────────────────────────
MESSAGE_AI_URL = os.getenv("MESSAGE_AI_URL", "http://localhost:5001/predict")
LINK_AI_URL    = os.getenv("LINK_AI_URL",    "http://localhost:5002/predict/url")

# ── Risk Level Color Mapping ─────────────────────────────────────────────────
COLOR_MAP = {
    "DANGEROUS": "red",
    "SUSPICIOUS": "orange",
    "SAFE":      "green",
}

# ── Scam Keywords for Rule-Based Fallback ───────────────────────────────────
SCAM_KEYWORDS = [
    # Urgency / Pressure
    "urgent", "act now", "immediately", "last chance", "expire today",
    "limited time", "respond within 24 hours", "do not ignore",

    # Financial Fraud
    "send money", "transfer funds", "wire transfer", "pay now",
    "advance fee", "processing fee", "customs fee", "clearance fee",
    "kyc update", "kyc verification", "account blocked", "account suspended",
    "bank account update", "refund pending", "income tax refund",

    # Credential / OTP Theft
    "otp", "one time password", "share your otp", "enter your pin",
    "verify your identity", "confirm your details", "update your password",
    "click here to verify", "login to confirm",

    # Prize / Lottery Scam
    "you have won", "congratulations", "winner", "lottery",
    "claim your prize", "selected for reward", "free gift",
    "lucky winner", "you are selected",

    # Job Scam
    "work from home", "part time earning", "whatsapp job",
    "earn daily", "easy money", "no experience needed",
    "salary credited", "job offer", "online earning",

    # Impersonation
    "rbi", "police case", "arrest warrant", "court notice",
    "income tax department", "customs department", "cyber crime",
    "your account will be closed", "legal action",
]

# ── URL Risk Keywords for Link Fallback ─────────────────────────────────────
PHISHING_URL_KEYWORDS = [
    "verify", "secure", "login", "update", "confirm",
    "account", "banking", "otp", "password", "kyc",
    "free", "lucky", "winner", "prize", "claim",
]

SUSPICIOUS_DOMAINS = [".xyz", ".tk", ".ml", ".cf", ".gq", ".top", ".click"]
URL_SHORTENERS     = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.ly"]


# ════════════════════════════════════════════════════════════════════════════
# RULE-BASED FALLBACKS
# ════════════════════════════════════════════════════════════════════════════

def rule_based_message(content: str) -> dict:
    """
    Keyword-based fallback for message/screenshot scans
    when message_ai server is offline.
    """
    content_lower = content.lower()
    matched = [kw for kw in SCAM_KEYWORDS if kw in content_lower]
    score = min(len(matched) * 0.12, 1.0)

    if score >= 0.5:
        risk_level  = "DANGEROUS"
        explanation = [
            f"🚨 {len(matched)} high-risk scam indicator(s) found: {', '.join(matched[:5])}",
            "🚫 Do NOT click any links or make any payments.",
            "🔐 Always verify the sender before taking action.",
        ]
    elif score >= 0.24:
        risk_level  = "SUSPICIOUS"
        explanation = [
            f"⚠️ {len(matched)} suspicious indicator(s) found: {', '.join(matched[:3])}",
            "🔍 Verify the source before taking any action.",
        ]
    else:
        risk_level  = "SAFE"
        explanation = [
            "✅ No obvious scam indicators detected.",
            "💡 Always stay cautious and verify before clicking links.",
        ]

    return {
        "risk_level":       risk_level,
        "risk_score":       round(score * 100),
        "explanation":      explanation,
        "matched_patterns": matched,
        "color":            COLOR_MAP[risk_level],
        "source":           "rule-based-fallback",
    }


def rule_based_link(url: str) -> dict:
    """
    Pattern-based fallback for URL scans
    when link_ai server is offline.
    """
    import re
    url_lower  = url.lower()
    matched    = []
    score      = 0.0
    explanation = []

    # Check raw IP address
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        matched.append("raw IP address")
        explanation.append("🚨 URL uses a raw IP address instead of a domain name")
        score += 0.4

    # Check no HTTPS
    if url_lower.startswith("http://"):
        matched.append("no HTTPS")
        explanation.append("🔓 Connection is not secure — no HTTPS")
        score += 0.2

    # Check suspicious domain endings
    for domain in SUSPICIOUS_DOMAINS:
        if domain in url_lower:
            matched.append(f"suspicious domain: {domain}")
            explanation.append(f"⚠️ Suspicious domain ending detected: {domain}")
            score += 0.3
            break

    # Check URL shorteners
    for shortener in URL_SHORTENERS:
        if shortener in url_lower:
            matched.append(f"URL shortener: {shortener}")
            explanation.append(f"🔗 URL shortener detected: {shortener}")
            score += 0.25
            break

    # Check phishing keywords in URL
    kw_found = [kw for kw in PHISHING_URL_KEYWORDS if kw in url_lower]
    if kw_found:
        matched.extend(kw_found)
        explanation.append(f"⚠️ Sensitive keywords in URL: {', '.join(kw_found[:4])}")
        score += len(kw_found) * 0.08

    # Check unusually long URL
    if len(url) > 75:
        matched.append("long URL")
        explanation.append("📏 URL is unusually long — common in phishing")
        score += 0.1

    # Check @ symbol
    if "@" in url:
        matched.append("@ symbol")
        explanation.append("🚩 @ symbol in URL is a phishing indicator")
        score += 0.35

    score = min(score, 1.0)

    if score >= 0.5:
        risk_level = "DANGEROUS"
    elif score >= 0.25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"
        explanation.append("✅ No phishing indicators found in this URL")

    return {
        "risk_level":       risk_level,
        "risk_score":       round(score * 100),
        "explanation":      explanation,
        "matched_patterns": matched,
        "color":            COLOR_MAP[risk_level],
        "source":           "rule-based-fallback",
    }


# ════════════════════════════════════════════════════════════════════════════
# AI SERVER CALLERS
# ════════════════════════════════════════════════════════════════════════════

def call_message_ai(content: str, guardian: bool = False, lang: str = "en") -> dict:
    """
    Calls message_ai server on port 5001.
    Falls back to rule_based_message if server is offline.
    """
    payload = {
        "email":    content.strip(),
        "guardian": guardian,
        "lang":     lang,
    }

    try:
        response = requests.post(MESSAGE_AI_URL, json=payload, timeout=10)

        if response.status_code == 200:
            data  = response.json()
            level = data.get("risk", "SAFE").upper()
            return {
                "risk_level":       level,
                "risk_score":       round(data.get("score", 0.0) * 100),
                "explanation":      data.get("explanation", []),
                "matched_patterns": [],
                "color":            COLOR_MAP.get(level, "green"),
                "source":           "message-ai",
            }
        else:
            print(f"[AI CLIENT] message_ai returned {response.status_code}. Using fallback.")
            return rule_based_message(content)

    except requests.exceptions.ConnectionError:
        print("[AI CLIENT] message_ai offline. Using rule-based fallback.")
        return rule_based_message(content)

    except requests.exceptions.Timeout:
        print("[AI CLIENT] message_ai timed out. Using rule-based fallback.")
        return rule_based_message(content)

    except Exception as e:
        print(f"[AI CLIENT] message_ai error: {e}. Using fallback.")
        return rule_based_message(content)


def call_link_ai(url: str, lang: str = "en") -> dict:
    """
    Calls link_ai server on port 5002.
    Falls back to rule_based_link if server is offline.
    """
    payload = {
        "url":  url.strip(),
        "lang": lang,
    }

    try:
        response = requests.post(LINK_AI_URL, json=payload, timeout=10)

        if response.status_code == 200:
            data  = response.json()
            level = data.get("risk", "SAFE").upper()
            return {
                "risk_level":       level,
                "risk_score":       round(data.get("score", 0.0) * 100),
                "explanation":      data.get("explanation", []),
                "matched_patterns": [],
                "color":            COLOR_MAP.get(level, "green"),
                "source":           "link-ai",
            }
        else:
            print(f"[AI CLIENT] link_ai returned {response.status_code}. Using fallback.")
            return rule_based_link(url)

    except requests.exceptions.ConnectionError:
        print("[AI CLIENT] link_ai offline. Using rule-based fallback.")
        return rule_based_link(url)

    except requests.exceptions.Timeout:
        print("[AI CLIENT] link_ai timed out. Using rule-based fallback.")
        return rule_based_link(url)

    except Exception as e:
        print(f"[AI CLIENT] link_ai error: {e}. Using fallback.")
        return rule_based_link(url)


# ════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION — called by app.py
# ════════════════════════════════════════════════════════════════════════════

def analyze_with_ai(
    input_type: str,
    content:    str,
    metadata:   dict = None,
    guardian:   bool = False,
    lang:       str  = "en",
) -> dict:
    """
    Main function called by all scan routes in app.py.

    Args:
        input_type : "message", "link", or "screenshot"
        content    : Text or URL to analyze
        metadata   : Extra data (optional)
        guardian   : Guardian Mode flag (for message scans)
        lang       : Language code — "en", "hi", "es"

    Returns:
        dict with keys:
            risk_level       → "SAFE" / "SUSPICIOUS" / "DANGEROUS"
            risk_score       → 0 to 100
            explanation      → list of reason strings
            matched_patterns → list of matched keywords
            color            → "green" / "orange" / "red"
            source           → which engine produced the result
    """

    # Guard: empty content
    if not content or not content.strip():
        return {
            "risk_level":       "SAFE",
            "risk_score":       0,
            "explanation":      ["No content was provided to analyze."],
            "matched_patterns": [],
            "color":            "green",
            "source":           "empty-input",
        }

    # Route to correct AI server based on input type
    if input_type == "link":
        return call_link_ai(url=content, lang=lang)

    elif input_type in ("message", "screenshot"):
        return call_message_ai(content=content, guardian=guardian, lang=lang)

    else:
        # Unknown input type — use message fallback
        print(f"[AI CLIENT] Unknown input_type '{input_type}'. Defaulting to message scan.")
        return call_message_ai(content=content, guardian=guardian, lang=lang)
