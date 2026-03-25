"""
SCAM SENSE AI — Response Formatter
Forces all AI / fallback responses into a standard structure.
Use this before passing any result to templates or the database.
"""


def normalize_ai_response(res: dict) -> dict:
    """
    Normalize any AI or fallback response into a guaranteed structure.

    Args:
        res: Raw dict from AI server or fallback logic

    Returns:
        dict with guaranteed keys: risk_level, risk_score,
        explanation, matched_patterns, source, color
    """

    # ── Risk Level ────────────────────────────────────────────────────────────
    raw_level = str(res.get("risk_level", "SUSPICIOUS")).upper().strip()

    if raw_level not in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        raw_level = "SUSPICIOUS"

    # ── Risk Score ────────────────────────────────────────────────────────────
    try:
        score = int(float(res.get("risk_score", 50)))
        score = max(0, min(100, score))          # clamp to 0–100
    except (TypeError, ValueError):
        score = 50

    # ── Explanation ───────────────────────────────────────────────────────────
    raw_explanation = res.get("explanation", [])

    if isinstance(raw_explanation, str):
        explanation = raw_explanation if raw_explanation else "No explanation provided."
    elif isinstance(raw_explanation, list):
        explanation = raw_explanation if raw_explanation else ["No explanation provided."]
    else:
        explanation = ["No explanation provided."]

    # ── Matched Patterns ──────────────────────────────────────────────────────
    raw_patterns = res.get("matched_patterns", [])
    matched_patterns = raw_patterns if isinstance(raw_patterns, list) else []

    # ── Source ────────────────────────────────────────────────────────────────
    source = str(res.get("source", "ai")).strip() or "ai"

    # ── Color (used by template) ──────────────────────────────────────────────
    color_map = {
        "SAFE":       "green",
        "SUSPICIOUS": "orange",
        "DANGEROUS":  "red",
    }
    color = color_map.get(raw_level, "orange")

    return {
        "risk_level":       raw_level,
        "risk_score":       score,
        "explanation":      explanation,
        "matched_patterns": matched_patterns,
        "source":           source,
        "color":            color,
    }


def explanation_as_string(explanation) -> str:
    """
    Convert explanation (list or string) to a single string for DB storage.

    Args:
        explanation: str or list of str

    Returns:
        Single string joined by newline
    """
    if isinstance(explanation, list):
        return "\n".join(str(e) for e in explanation)
    return str(explanation)
