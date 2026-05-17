# ============================================================
#  Custom Presidio PII Detector
#  1. Custom recognizers (CNIC, Student ID, API Key)
#  2. Context-aware confidence boosting
#  3. Composite entity detection (name+phone, studentID+email)
#  4. Confidence thresholding
# ============================================================

import yaml
import os
import re
from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── Load config ───────────────────────────────────────────────
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/gateway_config.yaml")

with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
    _config = yaml.safe_load(f)

_pii_cfg           = _config["presidio"]
_MIN_CONFIDENCE    = _pii_cfg["min_confidence"]
_ENTITIES          = _pii_cfg["entities"]
_CONTEXT_BOOSTERS  = _pii_cfg["context_boosters"]
_BOOST_AMOUNT      = _pii_cfg["context_boost_amount"]
_PLACEHOLDERS      = _pii_cfg["placeholders"]


# ── 1. Custom Recognizers ─────────────────────────────────────

# Pakistani CNIC: 35202-1234567-1
_cnic_recognizer = PatternRecognizer(
    supported_entity="CNIC",
    patterns=[
        Pattern(
            name="cnic_pattern",
            regex=r"\b\d{5}-\d{7}-\d\b",
            score=0.85,
        )
    ],
    context=["cnic", "nic", "identity", "national id", "card number", "شناختی"],
)

# Student ID: FA21-BCS-123 or BS22-CS-045
_student_id_recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[
        Pattern(
            name="student_id_pattern",
            regex=r"\b[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{2,4}\b",
            score=0.80,
        )
    ],
    context=["student", "registration", "roll", "id", "reg no", "student id"],
)

# API Key: long hex or base64 tokens (32+ chars)
_api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[
        Pattern(
            name="hex_api_key",
            regex=r"\b[a-fA-F0-9]{32,}\b",
            score=0.75,
        ),
        Pattern(
            name="bearer_token",
            regex=r"(?i)(bearer\s+)[A-Za-z0-9\-_\.]{20,}",
            score=0.85,
        ),
        Pattern(
            name="sk_key",
            regex=r"\bsk-[A-Za-z0-9]{20,}\b",
            score=0.90,
        ),
    ],
    context=["api", "key", "token", "secret", "bearer", "auth", "authorization"],
)

# Employee/Internal ID: EMP-XXXX (from midterm, kept)
_internal_id_recognizer = PatternRecognizer(
    supported_entity="INTERNAL_ID",
    patterns=[
        Pattern(
            name="emp_id_pattern",
            regex=r"\bEMP-\d{4}\b",
            score=0.80,
        )
    ],
    context=["employee", "emp", "staff", "id", "worker"],
)


# ── Build Analyzer ────────────────────────────────────────────

def _build_analyzer() -> AnalyzerEngine:
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    analyzer.registry.add_recognizer(_cnic_recognizer)
    analyzer.registry.add_recognizer(_student_id_recognizer)
    analyzer.registry.add_recognizer(_api_key_recognizer)
    analyzer.registry.add_recognizer(_internal_id_recognizer)
    return analyzer

_analyzer  = _build_analyzer()
_anonymizer = AnonymizerEngine()


# ── 2. Context-Aware Confidence Boosting ─────────────────────

def _boost_scores(
    text: str,
    results: list[RecognizerResult],
) -> list[RecognizerResult]:
    """
    Increase confidence score when context words appear
    near the detected entity (within 80 chars).
    """
    text_lower = text.lower()
    boosted = []

    for result in results:
        entity_type = result.entity_type
        boost       = 0.0

        if entity_type in _CONTEXT_BOOSTERS:
            # Check 80-char window around entity
            start = max(0, result.start - 80)
            end   = min(len(text), result.end + 80)
            window = text_lower[start:end]

            for ctx_word in _CONTEXT_BOOSTERS[entity_type]:
                if ctx_word in window:
                    boost = _BOOST_AMOUNT
                    break

        new_score = min(1.0, result.score + boost)

        boosted.append(RecognizerResult(
            entity_type=result.entity_type,
            start=result.start,
            end=result.end,
            score=new_score,
        ))

    return boosted


# ── 3. Composite Entity Detection ────────────────────────────

def _detect_composites(text: str, results: list) -> list[str]:
    """
    Detect dangerous combinations of entities.
    Returns list of composite reason codes.
    """
    found_types = {r.entity_type for r in results}
    composites  = []

    if "PERSON" in found_types and "PHONE_NUMBER" in found_types:
        composites.append("COMPOSITE_NAME_PHONE")

    if "STUDENT_ID" in found_types and "EMAIL_ADDRESS" in found_types:
        composites.append("COMPOSITE_STUDENT_EMAIL")

    if "API_KEY" in found_types and "EMAIL_ADDRESS" in found_types:
        composites.append("COMPOSITE_API_EMAIL")

    if "CNIC" in found_types and "PERSON" in found_types:
        composites.append("COMPOSITE_CNIC_NAME")

    return composites


# ── 4. Main scan function ─────────────────────────────────────

def scan(text: str) -> dict:
    """
    Run PII detection and anonymization on text.

    Returns
    -------
    {
        "pii_found"       : bool,
        "pii_entities"    : list of dicts with type/text/score,
        "sanitized_text"  : anonymized string,
        "has_secret"      : bool  (API key or password found),
        "composite_codes" : list[str],
        "pii_risk"        : float
    }
    """

    # Step 1: Analyze
    raw_results = _analyzer.analyze(
        text=text,
        language="en",
        entities=_ENTITIES,
    )

    # Step 2: Context boost (Customization 2)
    boosted_results = _boost_scores(text, raw_results)

    # Step 3: Threshold filter (Customization 4)
    filtered = [r for r in boosted_results if r.score >= _MIN_CONFIDENCE]

    # Step 4: Composite detection (Customization 3)
    composite_codes = _detect_composites(text, filtered)

    # Step 5: Anonymize
    if filtered:
        # Build operator config from placeholders
        operators = {}
        for entity in _ENTITIES:
            placeholder = _PLACEHOLDERS.get(entity, f"<{entity}>")
            operators[entity] = OperatorConfig(
                "replace", {"new_value": placeholder}
            )

        anonymized = _anonymizer.anonymize(
            text=text,
            analyzer_results=filtered,
            operators=operators,
        )
        sanitized_text = anonymized.text
    else:
        sanitized_text = text

    # Step 6: Build entity list for JSON response
    pii_entities = []
    for r in filtered:
        pii_entities.append({
            "type"  : r.entity_type,
            "text"  : text[r.start:r.end],
            "score" : round(r.score, 4),
            "start" : r.start,
            "end"   : r.end,
        })

    # Step 7: Check for secrets (API keys, passwords)
    secret_types = {"API_KEY"}
    has_secret   = any(r.entity_type in secret_types for r in filtered)

    # Step 8: PII risk score
    pii_risk = 0.0
    if filtered:
        pii_risk = _config["risk_weights"]["pii_weight"]
    if has_secret:
        pii_risk += _config["risk_weights"]["secret_weight"]
    pii_risk = min(pii_risk, 1.0)

    return {
        "pii_found"      : len(filtered) > 0,
        "pii_entities"   : pii_entities,
        "sanitized_text" : sanitized_text,
        "has_secret"     : has_secret,
        "composite_codes": composite_codes,
        "pii_risk"       : round(pii_risk, 4),
    }