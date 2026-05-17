# ============================================================
#  Policy Engine
#  Combines rule_score + semantic_score + pii_risk
#  Returns one of three decisions: ALLOW, MASK, BLOCK
#  Formula:
#    final_risk = max(rule_score, semantic_score)
#                 + pii_weight (if pii found)
#                 + secret_weight (if secret found)
# ============================================================

import yaml
import os

# ── Load config ───────────────────────────────────────────────
_CONFIG_PATH = r"C:\Users\zunai\Desktop\AI_FinalLab\config\gateway_config.yaml"

with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
    _config = yaml.safe_load(f)

_policy_cfg      = _config["policy"]
_risk_weights    = _config["risk_weights"]

_BLOCK_THRESHOLD = _policy_cfg["block_threshold"]   # 0.65
_MASK_THRESHOLD  = _policy_cfg["mask_threshold"]    # 0.20
_PII_WEIGHT      = _risk_weights["pii_weight"]      # 0.10
_SECRET_WEIGHT   = _risk_weights["secret_weight"]   # 0.20


# ── Main function ─────────────────────────────────────────────

def decide(
    rule_result:     dict,
    semantic_result: dict,
    pii_result:      dict,
) -> dict:
    """
    Make final policy decision.

    Parameters
    ----------
    rule_result     : output of rule_detector.scan()
    semantic_result : output of semantic_detector.scan()
    pii_result      : output of presidio_custom.scan()

    Returns
    -------
    {
        "decision"    : "ALLOW" | "MASK" | "BLOCK",
        "final_risk"  : float,
        "reason_codes": list[str],
        "safe_text"   : str or None
    }
    """

    rule_score     = rule_result["rule_score"]
    semantic_score = semantic_result["semantic_score"]
    pii_risk       = pii_result["pii_risk"]

    # ── Risk Formula ──────────────────────────────────────────
    # Base: take the higher of rule vs semantic
    base_risk  = max(rule_score, semantic_score)

    # Add PII/secret weights on top
    final_risk = base_risk + pii_risk
    final_risk = min(final_risk, 1.0)   # cap at 1.0

    # ── Collect all reason codes ──────────────────────────────
    reason_codes = []
    reason_codes.extend(rule_result.get("reason_codes", []))
    reason_codes.extend(semantic_result.get("reason_codes", []))
    reason_codes.extend(pii_result.get("composite_codes", []))

    if pii_result["has_secret"]:
        reason_codes.append("SECRET_DETECTED")
    if pii_result["pii_found"]:
        reason_codes.append("PII_DETECTED")

    # Remove duplicates while preserving order
    seen = set()
    unique_codes = []
    for code in reason_codes:
        if code not in seen:
            seen.add(code)
            unique_codes.append(code)
    reason_codes = unique_codes

    # ── Decision Logic ────────────────────────────────────────
    #
    #  BLOCK  → injection/jailbreak detected (high risk)
    #  MASK   → benign but contains PII
    #  ALLOW  → clean input
    #
    injection_codes = {
        "PROMPT_INJECTION",
        "JAILBREAK_ATTEMPT",
        "SYSTEM_PROMPT_EXTRACTION",
        "SECRET_EXTRACTION",
        "RAG_MANIPULATION",
        "SEMANTIC_INJECTION",
        "SECRET_DETECTED",
    }

    has_injection = bool(set(reason_codes) & injection_codes)

    if final_risk >= _BLOCK_THRESHOLD or has_injection:
        decision  = "BLOCK"
        safe_text = None

    elif final_risk >= _MASK_THRESHOLD or pii_result["pii_found"]:
        decision  = "MASK"
        safe_text = pii_result["sanitized_text"]

    else:
        decision  = "ALLOW"
        safe_text = pii_result["sanitized_text"]

    return {
        "decision"    : decision,
        "final_risk"  : round(final_risk, 4),
        "reason_codes": reason_codes,
        "safe_text"   : safe_text,
    }