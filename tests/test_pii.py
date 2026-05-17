# ============================================================
#  Test: Presidio PII Detection
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pii.presidio_custom import scan as pii_scan


def test_cnic_detection():
    result = pii_scan("My CNIC is 35202-1234567-1")
    types = [e["type"] for e in result["pii_entities"]]
    assert "CNIC" in types, "Should detect CNIC"
    assert result["pii_found"] == True
    print("✓ test_cnic_detection passed")


def test_student_id_detection():
    result = pii_scan("My student ID is FA21-BCS-123")
    types = [e["type"] for e in result["pii_entities"]]
    assert "STUDENT_ID" in types, "Should detect Student ID"
    print("✓ test_student_id_detection passed")


def test_api_key_detection():
    result = pii_scan("My api key is sk-abc123def456ghi789jkl012mno345pqr678")
    assert result["has_secret"] == True, "Should detect API key"
    print("✓ test_api_key_detection passed")


def test_email_detection():
    result = pii_scan("Contact me at ali.khan@example.com")
    types = [e["type"] for e in result["pii_entities"]]
    assert "EMAIL_ADDRESS" in types, "Should detect email"
    print("✓ test_email_detection passed")


def test_pii_masking():
    result = pii_scan("My CNIC is 35202-1234567-1")
    assert "<CNIC>" in result["sanitized_text"], "Should mask CNIC"
    print("✓ test_pii_masking passed")


def test_benign_no_pii():
    result = pii_scan("What is machine learning?")
    assert result["pii_found"] == False, "Should not detect PII"
    print("✓ test_benign_no_pii passed")


def test_composite_detection():
    result = pii_scan("Student FA21-BCS-123 email is student@uni.edu")
    assert "COMPOSITE_STUDENT_EMAIL" in result["composite_codes"]
    print("✓ test_composite_detection passed")


if __name__ == "__main__":
    test_cnic_detection()
    test_student_id_detection()
    test_api_key_detection()
    test_email_detection()
    test_pii_masking()
    test_benign_no_pii()
    test_composite_detection()
    print("\n✅ All PII tests passed!")