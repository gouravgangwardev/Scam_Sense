"""
SCAM SENSE AI — Link Checker
Pattern-based URL risk analysis before sending to AI engine.
Detects phishing indicators, suspicious domains, and brand impersonation.
"""

import re
from urllib.parse import urlparse


# ── Known Safe Domains (Whitelist) ───────────────────────────────────────────
SAFE_DOMAINS = {
    # Global
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "amazon.com",
    "microsoft.com", "apple.com", "wikipedia.org", "github.com",

    # Indian Government
    "gov.in", "nic.in", "india.gov.in", "mca.gov.in",

    # Indian Banks (official)
    "rbi.org.in", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "bankofbaroda.in", "pnbindia.in", "canarabank.com",

    # Indian Payment Platforms (official)
    "paytm.com", "phonepe.com", "gpay.app", "bhimupi.org.in",
}

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = (
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".pw",
    ".top", ".click", ".gq", ".icu", ".fun",
)

# ── URL Shortener Domains ────────────────────────────────────────────────────
URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "rb.gy", "cutt.ly", "is.gd", "buff.ly", "short.io",
)

# ── Suspicious Keyword Patterns in URL ───────────────────────────────────────
SUSPICIOUS_URL_PATTERNS = [
    r"login[-_.]?verif",
    r"account[-_.]?update",
    r"secure[-_.]?bank",
    r"kyc[-_.]?update",
    r"kyc[-_.]?verif",
    r"verify[-_.]?otp",
    r"otp[-_.]?verif",
    r"prize[-_.]?claim",
    r"free[-_.]?gift",
    r"reward[-_.]?win",
    r"claim[-_.]?now",
    r"password[-_.]?reset",
    r"confirm[-_.]?payment",
    r"refund[-_.]?process",
]

# ── Brand Impersonation Patterns ─────────────────────────────────────────────
# Format: brand_keyword → list of fake domain patterns that impersonate it
IMPERSONATION_PATTERNS = {
    "sbi":      ["sbi-bank", "sbionline", "sbi-kyc", "sbi-login", "sbicard", "sbisecure"],
    "hdfc":     ["hdfc-secure", "hdfclogin", "hdfc-verify", "hdfcnet"],
    "icici":    ["icici-bank", "icicisecure", "icici-kyc"],
    "paytm":    ["paytm-reward", "paytmpayment", "paytm-win", "paytmkyc"],
    "amazon":   ["amazon-offer", "amaz0n", "amazone", "amazon-reward", "amazon-win"],
    "rbi":      ["rbi-refund", "rbionline", "rbi-kyc", "rbi-gov"],
    "uidai":    ["uidai-kyc", "aadhaar-update", "aadhaarupdate"],
    "income":   ["incometax-refund", "incometaxrefund", "itrefund"],
    "police":   ["cybercrime-complaint", "police-notice", "cyberpolice"],
}


def check_link(url: str) -> dict:
    """
    Perform pattern-based risk analysis on a URL.

    Args:
        url: The URL string to analyze

    Returns:
        dict containing:
            domain             - extracted domain
            is_ip_address      - True if domain is raw IP
            is_url_shortener   - True if URL shortener detected
            suspicious_tld     - True if suspicious top-level domain
            suspicious_keywords - list of matched suspicious patterns
            impersonates_brand - brand name if impersonation found, else None
            risk_indicators    - total risk score (higher = more suspicious)
            is_safe_domain     - True if domain is in whitelist
    """
    result = {
        "url": url,
        "domain": "",
        "is_ip_address": False,
        "is_url_shortener": False,
        "suspicious_tld": False,
        "suspicious_keywords": [],
        "impersonates_brand": None,
        "risk_indicators": 0,
        "is_safe_domain": False,
    }

    # Ensure URL has a scheme for urlparse to work correctly
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove www. prefix for cleaner matching
        if domain.startswith("www."):
            domain = domain[4:]

        result["domain"] = domain

        # ── Check 1: Safe domain whitelist ───────────────────────────────────
        if domain in SAFE_DOMAINS:
            result["is_safe_domain"] = True
            result["risk_indicators"] -= 2  # Reduce risk for known safe domains
            return result  # No need to check further

        # ── Check 2: Raw IP address as domain ────────────────────────────────
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, domain.split(":")[0]):
            result["is_ip_address"] = True
            result["risk_indicators"] += 3  # High risk signal

        # ── Check 3: URL shortener ────────────────────────────────────────────
        if any(shortener in domain for shortener in URL_SHORTENERS):
            result["is_url_shortener"] = True
            result["risk_indicators"] += 2

        # ── Check 4: Suspicious TLD ───────────────────────────────────────────
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            result["suspicious_tld"] = True
            result["risk_indicators"] += 2

        # ── Check 5: Suspicious keyword patterns in full URL ─────────────────
        full_url_lower = url.lower()
        for pattern in SUSPICIOUS_URL_PATTERNS:
            match = re.search(pattern, full_url_lower)
            if match:
                result["suspicious_keywords"].append(match.group())
                result["risk_indicators"] += 1

        # ── Check 6: Brand impersonation in domain ───────────────────────────
        for brand, fake_patterns in IMPERSONATION_PATTERNS.items():
            if brand in domain:
                for fake in fake_patterns:
                    if fake in domain:
                        result["impersonates_brand"] = brand
                        result["risk_indicators"] += 4  # Very high risk signal
                        break
            if result["impersonates_brand"]:
                break

    except Exception as e:
        print(f"[LINK CHECKER ERROR] {e}")
        result["error"] = str(e)

    return result