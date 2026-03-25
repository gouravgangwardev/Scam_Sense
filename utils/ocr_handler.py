"""
SCAM SENSE AI — OCR Handler
Extracts text from uploaded screenshot images using Tesseract OCR.
"""

import pytesseract
from PIL import Image
import os


# ── Tesseract path for Windows (change if installed elsewhere) ───────────────
# On Linux/Mac this line is not needed — comment it out if not on Windows
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


# ── Allowed image modes for OCR ──────────────────────────────────────────────
VALID_MODES = ("RGB", "L", "RGBA")


def extract_text_from_image(filepath: str) -> str:
    """
    Extract readable text from an image file using Tesseract OCR.

    Args:
        filepath: Absolute or relative path to the image file

    Returns:
        Extracted text as a clean string.
        Returns empty string if extraction fails.
    """
    # Check file exists before opening
    if not os.path.exists(filepath):
        print(f"[OCR] File not found: {filepath}")
        return ""

    try:
        img = Image.open(filepath)

        # Convert image to RGB for consistent OCR results
        # Handles PNG with transparency (RGBA), grayscale, palette images
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # Tesseract config:
        # --oem 3  = Default OCR Engine Mode (LSTM neural net)
        # --psm 6  = Assume a single uniform block of text
        custom_config = r"--oem 3 --psm 6"

        extracted_text = pytesseract.image_to_string(
            img,
            lang="eng",
            config=custom_config,
        )

        cleaned_text = extracted_text.strip()

        if not cleaned_text:
            print("[OCR] No text detected in image.")
            return ""

        print(f"[OCR] Extracted {len(cleaned_text)} characters from image.")
        return cleaned_text

    except pytesseract.TesseractNotFoundError:
        print("[OCR ERROR] Tesseract is not installed or not found in PATH.")
        print("            Install from: https://github.com/tesseract-ocr/tesseract")
        return ""

    except Exception as e:
        print(f"[OCR ERROR] Failed to extract text: {e}")
        return ""


def extract_text_with_confidence(filepath: str) -> dict:
    """
    Extract text with per-word confidence scores.
    Useful for filtering low-quality OCR results.

    Args:
        filepath: Path to the image file

    Returns:
        dict with:
            text       - full extracted text
            confidence - average confidence percentage (0-100)
            word_count - number of words extracted
    """
    if not os.path.exists(filepath):
        return {"text": "", "confidence": 0, "word_count": 0}

    try:
        img = Image.open(filepath)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # Get detailed word-level OCR data
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

        words = []
        confidences = []

        for i, word in enumerate(data["text"]):
            word = word.strip()
            conf = int(data["conf"][i])

            # Only include words with confidence above 0
            # conf = -1 means non-text block
            if word and conf > 0:
                words.append(word)
                confidences.append(conf)

        avg_confidence = (
            round(sum(confidences) / len(confidences), 1)
            if confidences else 0
        )

        return {
            "text": " ".join(words),
            "confidence": avg_confidence,
            "word_count": len(words),
        }

    except Exception as e:
        print(f"[OCR ERROR] Confidence extraction failed: {e}")
        return {"text": "", "confidence": 0, "word_count": 0}