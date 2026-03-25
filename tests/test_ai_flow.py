"""
SCAM SENSE AI — Test Suite
Covers all critical paths: fallback rules, response formatting,
input sanitization, file security, and error utilities.

Run with:
    python -m pytest tests/test_ai_flow.py -v
Or:
    python tests/test_ai_flow.py
"""

import sys
import os

# ── Make sure project root is on path ────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest


# ═════════════════════════════════════════════════════════════════════════════
# TEST 1 — Fallback Rules
# ═════════════════════════════════════════════════════════════════════════════
class TestFallbackRules(unittest.TestCase):

    def setUp(self):
        from utils.fallback_rules import basic_fallback_analysis, full_fallback_result
        self.analyze = basic_fallback_analysis
        self.full    = full_fallback_result

    def test_dangerous_otp_message(self):
        """High-risk message with OTP + bank keywords → DANGEROUS"""
        level, score = self.analyze("Your bank account is blocked. Share your OTP immediately.")
        self.assertEqual(level, "DANGEROUS")
        self.assertGreaterEqual(score, 60)

    def test_dangerous_police_threat(self):
        """Police impersonation with arrest warrant → DANGEROUS"""
        level, score = self.analyze("Cyber crime department: arrest warrant filed. Pay now urgently.")
        self.assertEqual(level, "DANGEROUS")

    def test_suspicious_lottery(self):
        """Lottery winning message → at least SUSPICIOUS"""
        level, score = self.analyze("Congratulations! You won a prize. Click here to claim.")
        self.assertIn(level, ("SUSPICIOUS", "DANGEROUS"))
        self.assertGreaterEqual(score, 25)

    def test_safe_delivery_message(self):
        """Normal delivery SMS → SAFE"""
        level, score = self.analyze("Your order has been shipped. Expected delivery: tomorrow 10am.")
        self.assertEqual(level, "SAFE")
        self.assertLess(score, 25)

    def test_empty_text_returns_safe(self):
        """Empty input → SAFE with score 0"""
        level, score = self.analyze("")
        self.assertEqual(level, "SAFE")
        self.assertEqual(score, 0)

    def test_score_clamped_to_100(self):
        """Extremely spammy text → score never exceeds 100"""
        spam = "otp bank kyc password urgent verify account blocked arrest warrant " * 5
        level, score = self.analyze(spam)
        self.assertLessEqual(score, 100)

    def test_full_fallback_result_structure(self):
        """full_fallback_result returns all required keys"""
        result = self.full("Urgent: verify your bank account now.")
        self.assertIn("risk_level",       result)
        self.assertIn("risk_score",       result)
        self.assertIn("explanation",      result)
        self.assertIn("matched_patterns", result)
        self.assertIn("source",           result)

    def test_full_fallback_explanation_is_list(self):
        """full_fallback_result explanation is always a list"""
        result = self.full("Normal message")
        self.assertIsInstance(result["explanation"], list)


# ═════════════════════════════════════════════════════════════════════════════
# TEST 2 — Response Formatter
# ═════════════════════════════════════════════════════════════════════════════
class TestResponseFormatter(unittest.TestCase):

    def setUp(self):
        from utils.response_formatter import normalize_ai_response, explanation_as_string
        self.normalize = normalize_ai_response
        self.to_string = explanation_as_string

    def test_valid_response_passthrough(self):
        """Valid AI response passes through unchanged"""
        res = {
            "risk_level":       "DANGEROUS",
            "risk_score":       85,
            "explanation":      ["Phishing detected"],
            "matched_patterns": ["otp"],
            "source":           "ai-engine",
        }
        out = self.normalize(res)
        self.assertEqual(out["risk_level"], "DANGEROUS")
        self.assertEqual(out["risk_score"], 85)

    def test_garbage_response_gets_defaults(self):
        """Garbage AI response (e.g. {'label': 'spam'}) returns safe defaults"""
        out = self.normalize({"label": "spam"})
        self.assertEqual(out["risk_level"], "SUSPICIOUS")
        self.assertEqual(out["risk_score"], 50)
        self.assertIsNotNone(out["explanation"])

    def test_invalid_risk_level_normalized(self):
        """Unknown risk level string → SUSPICIOUS"""
        out = self.normalize({"risk_level": "UNKNOWN"})
        self.assertEqual(out["risk_level"], "SUSPICIOUS")

    def test_score_clamped_below_zero(self):
        """Negative score → clamped to 0"""
        out = self.normalize({"risk_level": "SAFE", "risk_score": -10})
        self.assertEqual(out["risk_score"], 0)

    def test_score_clamped_above_100(self):
        """Score > 100 → clamped to 100"""
        out = self.normalize({"risk_level": "DANGEROUS", "risk_score": 999})
        self.assertEqual(out["risk_score"], 100)

    def test_string_explanation_preserved(self):
        """String explanation is kept as string"""
        out = self.normalize({"risk_level": "SAFE", "explanation": "All clear."})
        self.assertEqual(out["explanation"], "All clear.")

    def test_list_explanation_preserved(self):
        """List explanation is kept as list"""
        out = self.normalize({"risk_level": "SAFE", "explanation": ["All clear."]})
        self.assertIsInstance(out["explanation"], list)

    def test_missing_matched_patterns_defaults_to_list(self):
        """Missing matched_patterns → empty list, not None"""
        out = self.normalize({"risk_level": "SAFE"})
        self.assertIsInstance(out["matched_patterns"], list)

    def test_color_assigned_correctly(self):
        """Color field matches risk level"""
        self.assertEqual(self.normalize({"risk_level": "SAFE"})["color"],       "green")
        self.assertEqual(self.normalize({"risk_level": "SUSPICIOUS"})["color"], "orange")
        self.assertEqual(self.normalize({"risk_level": "DANGEROUS"})["color"],  "red")

    def test_explanation_as_string_from_list(self):
        """List explanation converts to newline-joined string"""
        result = self.to_string(["First point.", "Second point."])
        self.assertIn("First point.", result)
        self.assertIn("Second point.", result)

    def test_explanation_as_string_from_string(self):
        """String explanation passes through as-is"""
        result = self.to_string("Direct string.")
        self.assertEqual(result, "Direct string.")


# ═════════════════════════════════════════════════════════════════════════════
# TEST 3 — Request Guard (Input Sanitization)
# ═════════════════════════════════════════════════════════════════════════════
class TestRequestGuard(unittest.TestCase):

    def setUp(self):
        from utils.request_guard import sanitize_text, sanitize_url, is_empty, truncate_for_preview
        self.sanitize_text    = sanitize_text
        self.sanitize_url     = sanitize_url
        self.is_empty         = is_empty
        self.truncate_preview = truncate_for_preview

    def test_html_injection_removed(self):
        """< and > characters are stripped"""
        result = self.sanitize_text("<script>alert('xss')</script>")
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)

    def test_null_bytes_removed(self):
        """Null bytes are stripped"""
        result = self.sanitize_text("Hello\x00World")
        self.assertNotIn("\x00", result)

    def test_text_truncated_at_max_length(self):
        """Text longer than max_length is truncated"""
        long_text = "a" * 6000
        result    = self.sanitize_text(long_text)
        self.assertLessEqual(len(result), 5000)

    def test_url_prepends_https(self):
        """URL without scheme gets https:// prepended"""
        result = self.sanitize_url("example.com/phishing")
        self.assertTrue(result.startswith("https://"))

    def test_url_keeps_existing_http(self):
        """URL with http:// scheme is kept as-is"""
        result = self.sanitize_url("http://example.com")
        self.assertTrue(result.startswith("http://"))

    def test_url_keeps_existing_https(self):
        """URL with https:// scheme is kept as-is"""
        result = self.sanitize_url("https://example.com")
        self.assertEqual(result, "https://example.com")

    def test_is_empty_true_for_blank(self):
        """Blank or whitespace-only string → is_empty True"""
        self.assertTrue(self.is_empty(""))
        self.assertTrue(self.is_empty("   "))
        self.assertTrue(self.is_empty(None))

    def test_is_empty_false_for_content(self):
        """Non-empty string → is_empty False"""
        self.assertFalse(self.is_empty("Hello"))

    def test_truncate_for_preview(self):
        """Long text truncated at preview limit with ellipsis"""
        long  = "x" * 500
        result= self.truncate_preview(long, limit=300)
        self.assertLessEqual(len(result), 304)   # 300 + "..."
        self.assertTrue(result.endswith("..."))


# ═════════════════════════════════════════════════════════════════════════════
# TEST 4 — Security Utilities
# ═════════════════════════════════════════════════════════════════════════════
class TestSecurity(unittest.TestCase):

    def setUp(self):
        from utils.security import safe_filename, is_allowed_extension
        self.safe_filename        = safe_filename
        self.is_allowed_extension = is_allowed_extension

    def test_path_traversal_blocked(self):
        """../../etc/passwd style filenames are sanitized"""
        result = self.safe_filename("../../app.py")
        self.assertNotIn("..", result)
        self.assertNotIn("/",  result)

    def test_safe_filename_preserves_extension(self):
        """Safe filename keeps the file extension"""
        result = self.safe_filename("screenshot.png")
        self.assertTrue(result.endswith(".png"))

    def test_empty_filename_returns_fallback(self):
        """Empty filename returns a safe fallback string"""
        result = self.safe_filename("")
        self.assertTrue(len(result) > 0)

    def test_jpg_extension_allowed(self):
        self.assertTrue(self.is_allowed_extension("image.jpg"))

    def test_jpeg_extension_allowed(self):
        self.assertTrue(self.is_allowed_extension("image.jpeg"))

    def test_png_extension_allowed(self):
        self.assertTrue(self.is_allowed_extension("image.png"))

    def test_exe_extension_blocked(self):
        self.assertFalse(self.is_allowed_extension("malware.exe"))

    def test_py_extension_blocked(self):
        self.assertFalse(self.is_allowed_extension("virus.py"))

    def test_no_extension_blocked(self):
        self.assertFalse(self.is_allowed_extension("noextension"))


# ═════════════════════════════════════════════════════════════════════════════
# TEST 5 — Constants Integrity
# ═════════════════════════════════════════════════════════════════════════════
class TestConstants(unittest.TestCase):

    def test_risk_levels_complete(self):
        from utils.constants import VALID_RISK_LEVELS
        for level in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
            self.assertIn(level, VALID_RISK_LEVELS)

    def test_valid_input_types_complete(self):
        from utils.constants import VALID_INPUT_TYPES
        for t in ("message", "link", "screenshot"):
            self.assertIn(t, VALID_INPUT_TYPES)

    def test_valid_languages_complete(self):
        from utils.constants import VALID_LANGUAGES
        for lang in ("en", "hi", "es"):
            self.assertIn(lang, VALID_LANGUAGES)

    def test_score_thresholds_logical(self):
        from utils.constants import SCORE_DANGEROUS_MIN, SCORE_SUSPICIOUS_MIN, SCORE_SAFE_MAX
        self.assertGreater(SCORE_DANGEROUS_MIN,  SCORE_SUSPICIOUS_MIN)
        self.assertGreater(SCORE_SUSPICIOUS_MIN, SCORE_SAFE_MAX)

    def test_file_size_consistent(self):
        from utils.constants import MAX_FILE_SIZE_MB, MAX_FILE_SIZE_BYTES
        self.assertEqual(MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB * 1024 * 1024)


# ═════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  SCAM SENSE AI — Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
