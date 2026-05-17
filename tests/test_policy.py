# ============================================================
#  Test: Policy Engine
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.policy.policy_engine import decide


def _make_rule(score, codes=[]):
    return {"rule_score": score, "reason_codes": codes, "matched_words": []}

def _make_semantic(score, flagged=False):
    codes = ["SEMANTIC_INJECTION"] if flagged else []
    return {"semantic_score": score, "is_flagged": flagged, "reason_codes": codes}

def _make_pii(found=False, secret=False, risk=0.0):
    return {
        "pii_found": found, "has_secret": secret,
        "pii_risk": risk, "pii_entities": [],
        "sanitized_text": "safe text", "composite_codes": []
    }


def test_block_on_injection():
    result = decide(
        _make_rule(1.0, ["PROMPT_INJECTION"]),
        _make_semantic(0.9, True),
        _make_pii()
    )
    assert result["decision"] == "BLOCK"
    print("✓ test_block_on_injection passed")


def test_mask_on_pii():
    result = decide(
        _make_rule(0.0),
        _make_semantic(0.1),
        _make_pii(found=True, risk=0.10)
    )
    assert result["decision"] == "MASK"
    print("✓ test_mask_on_pii passed")


def test_allow_on_benign():
    result = decide(
        _make_rule(0.0),
        _make_semantic(0.1),
        _make_pii()
    )
    assert result["decision"] == "ALLOW"
    print("✓ test_allow_on_benign passed")


def test_block_on_secret():
    result = decide(
        _make_rule(0.0),
        _make_semantic(0.1),
        _make_pii(found=True, secret=True, risk=0.30)
    )
    assert result["decision"] == "BLOCK"
    print("✓ test_block_on_secret passed")


def test_risk_formula():
    result = decide(
        _make_rule(0.5),
        _make_semantic(0.7),
        _make_pii(found=True, risk=0.10)
    )
    assert result["final_risk"] == round(0.7 + 0.10, 4)
    print("✓ test_risk_formula passed")


if __name__ == "__main__":
    test_block_on_injection()
    test_mask_on_pii()
    test_allow_on_benign()
    test_block_on_secret()
    test_risk_formula()
    print("\n✅ All policy tests passed!")