import time
import uuid
import yaml
import os
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse

# ── Import all modules ────────────────────────────────────────
from app.detectors.rule_detector     import scan as rule_scan
from app.detectors.semantic_detector import scan as semantic_scan
from app.pii.presidio_custom         import scan as pii_scan
from app.policy.policy_engine        import decide
from app.utils.language              import detect_and_translate
from app.utils.logging               import log_request

# ── Load config ───────────────────────────────────────────────
_CONFIG_PATH = r"C:\Users\zunai\Desktop\AI_FinalLab\config\gateway_config.yaml"
with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
    _config = yaml.safe_load(f)

_MAX_LENGTH = _config["api"]["max_input_length"]   # 2000 chars

# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(
    title="LLM Security Gateway",
    description="Robust multilingual security gateway for LLM applications",
    version="2.0.0",
)


# ── Routes ────────────────────────────────────────────────────

@app.get("/")
def home():
    return FileResponse("C:/Users/zunai/Desktop/AI_FinalLab/index.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.post("/analyze")
async def analyze(
    text_input: str = Query(..., description="User prompt to analyze"),
    input_id:   str = Query(None, description="Optional request ID"),
):
    """
    Main analysis endpoint.
    Returns full audit log with decision: ALLOW / MASK / BLOCK
    """
    start_time = time.time()

    # ── Generate request ID if not provided ──────────────────
    if not input_id:
        input_id = "req_" + str(uuid.uuid4())[:8]

    # ── Truncate if too long ──────────────────────────────────
    text = text_input[:_MAX_LENGTH]

    # ── Step 1: Language detection + translation ──────────────
    lang_result = detect_and_translate(text)
    translated  = lang_result["translated_text"]

    # ── Step 2: Rule-based detection ─────────────────────────
    rule_result = rule_scan(
        text=text,
        translated_text=translated,
    )

    # ── Step 3: Semantic detection ────────────────────────────
    semantic_result = semantic_scan(
        text=text,
        translated_text=translated,
    )

    # ── Step 4: PII detection ─────────────────────────────────
    # Run on original text + translated for max coverage
    pii_result = pii_scan(text=text)
    if lang_result["was_translated"]:
        pii_translated = pii_scan(text=translated)
        # Merge: take whichever found more
        if len(pii_translated["pii_entities"]) > len(pii_result["pii_entities"]):
            pii_result = pii_translated

    # ── Step 5: Policy decision ───────────────────────────────
    policy_result = decide(
        rule_result=rule_result,
        semantic_result=semantic_result,
        pii_result=pii_result,
    )

    # ── Step 6: Latency ───────────────────────────────────────
    latency_ms = (time.time() - start_time) * 1000

    # ── Step 7: Audit log + build response ───────────────────
    entry = log_request(
        input_id=input_id,
        original_text=text,
        lang_result=lang_result,
        rule_result=rule_result,
        semantic_result=semantic_result,
        pii_result=pii_result,
        policy_result=policy_result,
        latency_ms=latency_ms,
    )

    # ── Step 8: Return JSON response ─────────────────────────
    return JSONResponse(content={
        "input_id"       : input_id,
        "language"       : lang_result["detected_lang"],
        "was_translated" : lang_result["was_translated"],
        "rule_score"     : rule_result["rule_score"],
        "semantic_score" : semantic_result["semantic_score"],
        "pii_entities"   : pii_result["pii_entities"],
        "final_risk"     : policy_result["final_risk"],
        "decision"       : policy_result["decision"],
        "safe_text"      : policy_result["safe_text"],
        "reason_codes"   : policy_result["reason_codes"],
        "latency_ms"     : round(latency_ms, 2),
        "stats": {
            "threat_score"     : rule_result["rule_score"],
            "semantic_score"   : semantic_result["semantic_score"],
            "pii_found"        : pii_result["pii_found"],
            "has_secret"       : pii_result["has_secret"],
            "detected_language": lang_result["detected_lang"],
            "translated"       : lang_result["was_translated"],
            "time_taken_ms"    : round(latency_ms, 2),
        }
    })


# ── Legacy endpoint (backward compat with midterm UI) ────────
@app.post("/scan")
async def scan_legacy(text_input: str = Query(...)):
    """
    Kept for backward compatibility with midterm index.html
    Internally calls /analyze
    """
    return await analyze(text_input=text_input)