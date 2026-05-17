# ============================================================
#  Audit Logger
#  Writes structured JSON logs for every request
# ============================================================

import json
import os
import yaml
import logging
from datetime import datetime

# ── Load config ───────────────────────────────────────────────
_CONFIG_PATH = r"C:\Users\zunai\Desktop\AI_FinalLab\config\gateway_config.yaml"

with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
    _config = yaml.safe_load(f)

_log_cfg  = _config["logging"]
_LOG_FILE = _log_cfg["log_file"]        # "logs/audit.log"
_LOG_LEVEL = _log_cfg["log_level"]      # "INFO"

# ── Create logs directory if not exists ──────────────────────
os.makedirs(os.path.dirname(_LOG_FILE), exist_ok=True)

# ── Setup Python logger ───────────────────────────────────────
_logger = logging.getLogger("llm_gateway")
_logger.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))

# File handler — writes to audit.log
_file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
_file_handler.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))
_logger.addHandler(_file_handler)

# Console handler — shows in terminal
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.DEBUG)
_logger.addHandler(_console_handler)


# ── Main function ─────────────────────────────────────────────

def log_request(
    input_id:        str,
    original_text:   str,
    lang_result:     dict,
    rule_result:     dict,
    semantic_result: dict,
    pii_result:      dict,
    policy_result:   dict,
    latency_ms:      float,
) -> dict:
    """
    Build and write a full audit log entry.

    Returns the log entry dict (also used as API response).
    """

    entry = {
        "timestamp"      : datetime.utcnow().isoformat() + "Z",
        "input_id"       : input_id,
        "language"       : lang_result["detected_lang"],
        "was_translated" : lang_result["was_translated"],

        # Detection scores
        "rule_score"     : rule_result["rule_score"],
        "matched_words"  : rule_result["matched_words"],
        "semantic_score" : semantic_result["semantic_score"],

        # PII
        "pii_found"      : pii_result["pii_found"],
        "pii_entities"   : pii_result["pii_entities"],
        "has_secret"     : pii_result["has_secret"],
        "composite_codes": pii_result["composite_codes"],

        # Policy
        "final_risk"     : policy_result["final_risk"],
        "decision"       : policy_result["decision"],
        "reason_codes"   : policy_result["reason_codes"],
        "safe_text"      : policy_result["safe_text"],

        # Performance
        "latency_ms"     : round(latency_ms, 2),
    }

    # Write to log file as JSON line
    _logger.info(json.dumps(entry, ensure_ascii=False))

    return entry