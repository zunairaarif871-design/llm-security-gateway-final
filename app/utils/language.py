# ============================================================
#  Language Detection and Translation Utility
#  Supports: English, Urdu, Korean (+ others via Google)
# ============================================================

import yaml
import os
from langdetect import detect, LangDetectException
from deep_translator import GoogleTranslator

# ── Load config ───────────────────────────────────────────────
_CONFIG_PATH = r"C:\Users\zunai\Desktop\AI_FinalLab\config\gateway_config.yaml"

with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
    _config = yaml.safe_load(f)

_lang_cfg   = _config["language"]
_FALLBACK   = _lang_cfg["fallback"]        # "en"
_TRANSLATE  = _lang_cfg["translate_to_english"]


# ── Main function ─────────────────────────────────────────────

def detect_and_translate(text: str) -> dict:
    """
    Detect language and translate to English if needed.

    Returns
    -------
    {
        "detected_lang"  : str   e.g. "ur", "ko", "en",
        "translated_text": str   English version (or original if already English),
        "was_translated" : bool
    }
    """

    # Step 1: Detect language
    try:
        detected = detect(text)
    except LangDetectException:
        detected = _FALLBACK

    # Step 2: Translate if not English
    translated_text = text
    was_translated  = False

    if _TRANSLATE and detected not in ("en", "unknown"):
        try:
            result = GoogleTranslator(
                source=detected,
                target="en"
            ).translate(text)

            if result and result.strip():
                translated_text = result
                was_translated  = True

        except Exception as e:
            print(f"[Language] Translation failed: {e}")
            translated_text = text

    return {
        "detected_lang"  : detected,
        "translated_text": translated_text,
        "was_translated" : was_translated,
    }