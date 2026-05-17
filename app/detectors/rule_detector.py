# ============================================================
#  Rule-Based Injection Detector
#  Reads all keywords and thresholds from gateway_config.yaml
#  Returns: score (0.0-1.0), matched keywords, is_flagged
# ============================================================

import yaml
import os
import re

# ── Load config once at import time ──────────────────────────
_CONFIG_PATH = r"C:\Users\zunai\Desktop\AI_FinalLab\config\gateway_config.yaml"

with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
    _config = yaml.safe_load(f)

_rule_cfg         = _config["rule_detector"]
_FLAG_THRESHOLD   = _rule_cfg["flag_threshold"]
_SUSPICIOUS_WORDS = _rule_cfg["suspicious_words"]  # dict: word -> weight


# ── Helpers ───────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace + remove punctuation for matching."""
    text = text.lower()
    text = re.sub(r"[!@#$%^&*(){}\[\]|\\<>?/]", " ", text)
    # de-obfuscate common leetspeak
    text = text.replace("0", "o").replace("1", "i").replace("3", "e").replace("@", "a")
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ── Main function ─────────────────────────────────────────────

def scan(text: str, translated_text: str = None) -> dict:
    """
    Scan text with rule-based keyword matching.

    Parameters
    ----------
    text            : original user input
    translated_text : English translation (if input was non-English)

    Returns
    -------
    {
        "rule_score"    : float  0.0 – 1.0  (capped),
        "matched_words" : list[str],
        "is_flagged"    : bool,
        "reason_codes"  : list[str]
    }
    """

    # Combine original + translated for maximum coverage
    texts_to_check = [_normalize(text)]
    if translated_text and translated_text.strip() != text.strip():
        texts_to_check.append(_normalize(translated_text))

    raw_score    = 0.0
    matched      = []

    for norm in texts_to_check:
        for word, weight in _SUSPICIOUS_WORDS.items():
            if word in norm and word not in matched:
                raw_score += weight
                matched.append(word)

    # Cap score at 1.0
    score = min(raw_score, 1.0)

    # Build reason codes
    reason_codes = []
    if score >= _FLAG_THRESHOLD:
        # Categorise what was found
        injection_words  = {"ignore previous","ignore all previous","ignore instructions",
                            "disregard previous","disregard instructions","override",
                            "above instructions","previous instructions","all instructions"}
        jailbreak_words  = {"bypass","jailbreak","pretend","pretend you are","act as",
                            "roleplay","you are now","unrestricted","no restrictions",
                            "without restrictions","ignore safety","bypass safety",
                            "ignore your training"}
        extraction_words = {"system prompt","show the system","show system","display the system",
                            "print the system","reveal prompt","show prompt","display prompt",
                            "print prompt","the instructions","your instructions",
                            "initial instructions","original instructions"}
        secret_words     = {"api key","api keys","access token","secret key","password",
                            "credentials","show me the key","print the key","reveal the token"}
        rag_words        = {"retrieved document","use the document",
                            "override your policy","as a system instruction"}

        matched_set = set(matched)
        if matched_set & injection_words:
            reason_codes.append("PROMPT_INJECTION")
        if matched_set & jailbreak_words:
            reason_codes.append("JAILBREAK_ATTEMPT")
        if matched_set & extraction_words:
            reason_codes.append("SYSTEM_PROMPT_EXTRACTION")
        if matched_set & secret_words:
            reason_codes.append("SECRET_EXTRACTION")
        if matched_set & rag_words:
            reason_codes.append("RAG_MANIPULATION")

    return {
        "rule_score"    : round(score, 4),
        "matched_words" : matched,
        "is_flagged"    : score >= _FLAG_THRESHOLD,
        "reason_codes"  : reason_codes
    }