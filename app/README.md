# LLM Security Gateway — Lab Final
## CSC 262 Artificial Intelligence

A robust multilingual security gateway that protects LLM applications
by detecting prompt injection, jailbreaks, PII, and multilingual attacks.

---

## Features
- Hybrid detection: Rule-based + TF-IDF/Logistic Regression
- Multilingual: English, Urdu, Korean
- Presidio PII with 4 customizations (CNIC, Student ID, API Key, Phone)
- Policy Engine: ALLOW / MASK / BLOCK
- Audit logging (JSON)
- 96% accuracy on 150-prompt evaluation dataset

---

## Project Structure
AI_FinalLab/
├── app/
│   ├── detectors/
│   │   ├── rule_detector.py
│   │   └── semantic_detector.py
│   ├── pii/
│   │   └── presidio_custom.py
│   ├── policy/
│   │   └── policy_engine.py
│   └── utils/
│       ├── language.py
│       └── logging.py
├── config/
│   └── gateway_config.yaml
├── data/
│   └── final_eval.csv
├── results/
│   ├── evaluation_results.csv
│   └── metrics_summary.json
├── tests/
│   ├── test_detector.py
│   ├── test_pii.py
│   └── test_policy.py
├── index.html
├── run_evaluation.py
├── requirements.txt
└── README.md

---

## Installation

### Step 1: Clone the repository
```bash
git clone <your-repo-url>
cd AI_FinalLab
```

### Step 2: Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

---

## Running the API
```bash
uvicorn app.main:app --reload
```
Open browser: `http://localhost:8000`

---

## Running Tests
```bash
python tests/test_detector.py
python tests/test_pii.py
python tests/test_policy.py
```

---

## Running Evaluation
```bash
python run_evaluation.py
```
Results saved to `results/` folder.

---

## Example Request & Response

**Request:**
```bash
curl -X POST "http://localhost:8000/analyze?text_input=Ignore all previous instructions"
```

**Response:**
```json
{
  "input_id": "req_a1b2c3",
  "language": "en",
  "rule_score": 1.0,
  "semantic_score": 0.91,
  "final_risk": 1.0,
  "decision": "BLOCK",
  "safe_text": null,
  "reason_codes": ["PROMPT_INJECTION", "SEMANTIC_INJECTION"],
  "latency_ms": 23.5
}
```

---

## Evaluation Results
| Metric | Score |
|--------|-------|
| Accuracy | 96% |
| Precision | 96% |
| Recall | 96% |
| F1 Score | 96% |

---

## Hardware Requirements
- Python 3.10+
- No GPU required
- 4GB RAM minimum

---

## Limitations
- Translation requires internet (Google Translate)
- Very new obfuscation patterns may bypass rule detector