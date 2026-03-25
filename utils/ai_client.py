"""
SCAM SENSE AI — AI Client
Connects to:
  - message_ai server (port 5001) for text/message scans
  - link_ai server    (port 5002) for URL scans

Screenshots are NOT sent to AI — use fallback_rules.full_fallback_result() instead.
Falls back to rule-based detection if any AI server is offline or times out.
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

# ── AI Engine URLs from .env ──────────────────────────────────────────────────
MESSAGE_AI_URL     = os.getenv("MESSAGE_AI_URL", "http://localhost:5001/predict")
LINK_AI_URL        = os.getenv("LINK_AI_URL",    "http://localhost:5002/predict/url")
AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", 10))

# ── Risk Level Color Mapping ──────────────────────────────────────────────────
COLOR_MAP = {
    "DANGEROUS":  "red",
    "SUSPICIOUS": "orange",
    "SAFE":       "green",
}

# ── Scam Keywords for Rule-Based Fallback ─────────────────────────────────────
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

# ── URL Risk Keywords for Link Fallback ───────────────────────────────────────
PHISHING_URL_KEYWORDS = [
    "verify", "secure", "login", "update", "confirm",
    "account", "banking", "otp", "password", "kyc",
    "free", "lucky", "winner", "prize", "claim",
]

SUSPICIOUS_DOMAINS = [".xyz", ".tk", ".ml", ".cf", ".gq", ".top", ".click"]
URL_SHORTENERS     = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.ly"]


# ── Response Normalizer ───────────────────────────────────────────────────────
def normalize_response(data: dict) -> dict:
    """
    Force a standard response structure regardless of AI output format.
    Prevents crashes if AI returns unexpected or partial data.
    """
    level = str(data.get("risk_level", data.get("risk", "SUSPICIOUS"))).upper()
    if level not in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        level = "SUSPICIOUS"

    raw_score = data.get("risk_score", data.get("score", 0.5))
    # Handle both 0-1 float and 0-100 int scores
    if isinstance(raw_score, float) and raw_score <= 1.0:
        score = round(raw_score * 100)
    else:
        score = int(raw_score)
    score = max(0, min(100, score))

    explanation = data.get("explanation", ["No explanation provided."])
    if not isinstance(explanation, list):
        explanation = [str(explanation)]

    return {
        "risk_level":       level,
        "risk_score":       score,
        "explanation":      explanation,
        "matched_patterns": data.get("matched_patterns", []),
        "color":            COLOR_MAP.get(level, "orange"),
        "source":           data.get("source", "ai"),
    }


# ════════════════════════════════════════════════════════════════════════════
# RULE-BASED FALLBACKS
# ════════════════════════════════════════════════════════════════════════════

def rule_based_message(content: str) -> dict:
    """
    Keyword-based fallback for message scans when message_ai server is offline.
    """
    content_lower = content.lower()
    matched = [kw for kw in SCAM_KEYWORDS if kw in content_lower]
    score   = min(len(matched) * 0.12, 1.0)

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
    Pattern-based fallback for URL scans when link_ai server is offline.
    """
    import re
    url_lower   = url.lower()
    matched     = []
    score       = 0.0
    explanation = []

    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        matched.append("raw IP address")
        explanation.append("🚨 URL uses a raw IP address instead of a domain name")
        score += 0.4

    if url_lower.startswith("http://"):
        matched.append("no HTTPS")
        explanation.append("🔓 Connection is not secure — no HTTPS")
        score += 0.2

    for domain in SUSPICIOUS_DOMAINS:
        if domain in url_lower:
            matched.append(f"suspicious domain: {domain}")
            explanation.append(f"⚠️ Suspicious domain ending detected: {domain}")
            score += 0.3
            break

    for shortener in URL_SHORTENERS:
        if shortener in url_lower:
            matched.append(f"URL shortener: {shortener}")
            explanation.append(f"🔗 URL shortener detected: {shortener}")
            score += 0.25
            break

    kw_found = [kw for kw in PHISHING_URL_KEYWORDS if kw in url_lower]
    if kw_found:
        matched.extend(kw_found)
        explanation.append(f"⚠️ Sensitive keywords in URL: {', '.join(kw_found[:4])}")
        score += len(kw_found) * 0.08

    if len(url) > 75:
        matched.append("long URL")
        explanation.append("📏 URL is unusually long — common in phishing")
        score += 0.1

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
    Falls back to rule_based_message if server is offline or returns bad data.
    """
    payload = {
        "email":    content.strip(),
        "guardian": guardian,
        "lang":     lang,
    }

    try:
        response = requests.post(MESSAGE_AI_URL, json=payload, timeout=AI_REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            data["source"] = "message-ai"
            return normalize_response(data)
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
    Falls back to rule_based_link if server is offline or returns bad data.
    """
    payload = {
        "url":  url.strip(),
        "lang": lang,
    }

    try:
        response = requests.post(LINK_AI_URL, json=payload, timeout=AI_REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            data["source"] = "link-ai"
            return normalize_response(data)
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
    Main function called by scan routes in app.py.

    IMPORTANT: Screenshots must NOT be sent here.
               Use fallback_rules.full_fallback_result() for screenshots.

    Args:
        input_type : "message" or "link" only
        content    : Text or URL to analyze
        metadata   : Extra data (optional, used for links)
        guardian   : Guardian Mode flag (for message scans)
        lang       : Language code — "en", "hi", "es"

    Returns:
        Normalized dict with keys:
            risk_level, risk_score, explanation, matched_patterns, color, source
    """

    # Hard block: AI must never be used for screenshots
    if input_type == "screenshot":
        raise ValueError(
            "[AI CLIENT] AI is disabled for screenshots. "
            "Use fallback_rules.full_fallback_result() instead."
        )

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

    # Route to correct AI server
    if input_type == "link":
        return call_link_ai(url=content, lang=lang)

    elif input_type == "message":
        return call_message_ai(content=content, guardian=guardian, lang=lang)

    else:
        print(f"[AI CLIENT] Unknown input_type '{input_type}'. Defaulting to message scan.")
        return call_message_ai(content=content, guardian=guardian, lang=lang)
