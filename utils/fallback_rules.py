"""
SCAM SENSE AI — Fallback Rules Engine
Keyword-based scam detection used when:
  1. AI server is offline or times out
  2. Screenshot scan (AI is intentionally disabled for images)

This is the survival brain of the system.
"""

# ── Keyword Categories ────────────────────────────────────────────────────────

# Highest severity — almost always scam
DANGER_KEYWORDS = [
    "otp",
    "one time password",
    "bank account",
    "account blocked",
    "account suspended",
    "kyc",
    "kyc update",
    "kyc verification",
    "password",
    "pin number",
    "credit card",
    "debit card",
    "cvv",
    "arrest warrant",
    "police case",
    "cyber crime",
    "income tax",
    "legal action",
    "court notice",
    "aadhaar",
    "pan card",
    "verify your account",
    "verify immediately",
    "share your otp",
    "do not share",          # classic "do not share OTP" phishing phrasing
]

# Medium severity — suspicious but not always scam
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "asap",
    "limited time",
    "offer expires",
    "click here",
    "click the link",
    "tap here",
    "verify",
    "confirm your",
    "update your",
    "win",
    "won",
    "winner",
    "lottery",
    "prize",
    "reward",
    "gift",
    "free",
    "lucky draw",
    "selected",
    "congratulations",
    "refund",
    "cashback",
    "earn",
    "income",
    "work from home",
    "part time",
    "investment",
    "double your money",
    "guaranteed",
    "no risk",
    "processing fee",
    "registration fee",
    "pay now",
    "transfer",
    "suspicious activity",
    "unusual activity",
    "blocked",
    "suspended",
    "deactivated",
]

# Urgency amplifiers — boost score when present
URGENCY_KEYWORDS = [
    "now",
    "today",
    "tonight",
    "before midnight",
    "24 hours",
    "48 hours",
    "immediately",
    "urgent",
    "asap",
    "do not delay",
    "act fast",
    "time sensitive",
    "expires",
    "last chance",
]

# Brand impersonation indicators
BRAND_KEYWORDS = [
    "sbi",
    "hdfc",
    "icici",
    "axis bank",
    "paytm",
    "phonepe",
    "google pay",
    "amazon",
    "flipkart",
    "rbi",
    "reserve bank",
    "income tax department",
    "epfo",
    "provident fund",
    "uidai",
    "npci",
    "irctc",
    "microsoft",
    "apple",
    "whatsapp",
]


# ── Scoring Logic ─────────────────────────────────────────────────────────────

def basic_fallback_analysis(text: str) -> tuple[str, int]:
    """
    Analyze text using keyword rules when AI is unavailable.

    Args:
        text: Raw or OCR-extracted text to analyze

    Returns:
        (risk_level, risk_score) tuple
        risk_level: "SAFE" | "SUSPICIOUS" | "DANGEROUS"
        risk_score: 0–100 integer
    """
    if not text or not text.strip():
        return "SAFE", 0

    lower = text.lower()
    score = 0
    matched = []

    # Danger keywords — high weight
    for word in DANGER_KEYWORDS:
        if word in lower:
            score += 25
            matched.append(word)

    # Suspicious keywords — medium weight
    for word in SUSPICIOUS_KEYWORDS:
        if word in lower:
            score += 10
            matched.append(word)

    # Urgency amplifiers — extra weight
    urgency_count = sum(1 for word in URGENCY_KEYWORDS if word in lower)
    score += urgency_count * 8

    # Brand impersonation — extra weight
    brand_count = sum(1 for word in BRAND_KEYWORDS if word in lower)
    score += brand_count * 12

    # Clamp score to 0–100
    score = min(score, 100)

    # ── Determine Risk Level ──────────────────────────────────────────────────
    if score >= 60:
        return "DANGEROUS", score
    elif score >= 25:
        return "SUSPICIOUS", score
    else:
        return "SAFE", score


def get_matched_keywords(text: str) -> list[str]:
    """
    Return list of all matched scam keywords found in the text.
    Used to populate matched_patterns in the result.

    Args:
        text: Input text to scan

    Returns:
        List of matched keyword strings (deduplicated)
    """
    if not text:
        return []

    lower     = text.lower()
    all_words = DANGER_KEYWORDS + SUSPICIOUS_KEYWORDS + URGENCY_KEYWORDS + BRAND_KEYWORDS
    matched   = list({word for word in all_words if word in lower})
    return matched


def full_fallback_result(text: str, source: str = "fallback") -> dict:
    """
    Full fallback analysis returning a normalized result dict.
    Use this when you need a complete result without AI.

    Args:
        text:   Input text to analyze
        source: Source label for the result (default: "fallback")

    Returns:
        dict ready to pass to normalize_ai_response()
    """
    level, score     = basic_fallback_analysis(text)
    matched_patterns = get_matched_keywords(text)

    if level == "DANGEROUS":
        explanation = [
            "⚠️ High-risk scam indicators detected.",
            "Sensitive keywords found: " + ", ".join(matched_patterns[:5]) if matched_patterns else "",
            "Do not share personal information or make any payments.",
        ]
    elif level == "SUSPICIOUS":
        explanation = [
            "⚠️ Suspicious patterns detected. Verify before taking action.",
            "Indicators found: " + ", ".join(matched_patterns[:5]) if matched_patterns else "",
            "Contact the organization directly using their official number.",
        ]
    else:
        explanation = [
            "✅ No obvious scam patterns detected.",
            "Always stay alert and verify before sharing personal information.",
        ]

    # Remove empty strings from explanation
    explanation = [e for e in explanation if e]

    return {
        "risk_level":       level,
        "risk_score":       score,
        "explanation":      explanation,
        "matched_patterns": matched_patterns,
        "source":           source,
    }
