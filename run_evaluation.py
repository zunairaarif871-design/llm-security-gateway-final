import csv
import json
import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from app.detectors.rule_detector     import scan as rule_scan
from app.detectors.semantic_detector import scan as semantic_scan, retrain_from_csv
from app.pii.presidio_custom         import scan as pii_scan
from app.policy.policy_engine        import decide
from app.utils.language              import detect_and_translate

# ── Paths ─────────────────────────────────────────────────────
DATA_PATH    = "data/final_eval.csv"
RESULTS_DIR  = "results"
RESULTS_CSV  = os.path.join(RESULTS_DIR, "evaluation_results.csv")
METRICS_JSON = os.path.join(RESULTS_DIR, "metrics_summary.json")

os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Helper: map expected_policy to binary ────────────────────
def is_attack(expected_policy: str) -> int:
    """BLOCK=1 (attack), ALLOW/MASK=0 (benign/pii)"""
    return 1 if expected_policy.strip().upper() == "BLOCK" else 0


def is_attack_pred(decision: str) -> int:
    return 1 if decision.strip().upper() == "BLOCK" else 0


# ── Run single prompt ─────────────────────────────────────────
def run_prompt(prompt: str) -> dict:
    start = time.time()

    lang_result     = detect_and_translate(prompt)
    translated      = lang_result["translated_text"]

    rule_result     = rule_scan(prompt, translated)
    semantic_result = semantic_scan(prompt, translated)
    pii_result      = pii_scan(prompt)

    if lang_result["was_translated"]:
        pii_t = pii_scan(translated)
        if len(pii_t["pii_entities"]) > len(pii_result["pii_entities"]):
            pii_result = pii_t

    policy_result   = decide(rule_result, semantic_result, pii_result)
    latency_ms      = (time.time() - start) * 1000

    return {
        "decision"      : policy_result["decision"],
        "final_risk"    : policy_result["final_risk"],
        "rule_score"    : rule_result["rule_score"],
        "semantic_score": semantic_result["semantic_score"],
        "reason_codes"  : "|".join(policy_result["reason_codes"]),
        "latency_ms"    : round(latency_ms, 2),
    }


# ── Metrics ───────────────────────────────────────────────────
def compute_metrics(tp, fp, tn, fn) -> dict:
    accuracy  = (tp + tn) / (tp + fp + tn + fn) if (tp+fp+tn+fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "accuracy"        : round(accuracy,  4),
        "precision"       : round(precision, 4),
        "recall"          : round(recall,    4),
        "f1_score"        : round(f1,        4),
        "false_positive_rate": round(fpr,    4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


# ── Main ──────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  LLM Security Gateway — Evaluation")
    print("=" * 60)

    # Step 1: Retrain semantic model on full dataset
    print("\n[Step 1] Retraining semantic model on full dataset...")
    retrain_from_csv(DATA_PATH)

    # Step 2: Load dataset
    print("\n[Step 2] Loading evaluation dataset...")
    rows = []
    with open(DATA_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    print(f"         Loaded {len(rows)} prompts.")

    # Step 3: Run evaluation
    print("\n[Step 3] Running evaluation...\n")

    results      = []
    latencies    = []

    # For overall metrics
    tp = fp = tn = fn = 0

    # Per-language tracking
    lang_stats = {}

    # Per-category tracking
    cat_stats = {}

    for i, row in enumerate(rows, 1):
        prompt          = row["prompt"]
        expected_policy = row["expected_policy"]
        language        = row["language"]
        attack_type     = row["attack_type"]

        print(f"  [{i:3d}/{len(rows)}] {prompt[:55]:<55} ...", end=" ")

        try:
            out = run_prompt(prompt)
        except Exception as e:
            print(f"ERROR: {e}")
            out = {
                "decision": "ALLOW", "final_risk": 0,
                "rule_score": 0, "semantic_score": 0,
                "reason_codes": "ERROR", "latency_ms": 0,
            }

        predicted = out["decision"]
        correct   = (predicted.strip().upper() == expected_policy.strip().upper())

        # Also compute BLOCK vs non-BLOCK binary metrics
        y_true = is_attack(expected_policy)
        y_pred = is_attack_pred(predicted)

        if y_true == 1 and y_pred == 1:   tp += 1
        elif y_true == 0 and y_pred == 1: fp += 1
        elif y_true == 0 and y_pred == 0: tn += 1
        else:                              fn += 1

        latencies.append(out["latency_ms"])

        # Per-language
        if language not in lang_stats:
            lang_stats[language] = {"correct": 0, "total": 0, "fn": 0}
        lang_stats[language]["total"]  += 1
        lang_stats[language]["correct"] += int(correct)
        if y_true == 1 and y_pred == 0:
            lang_stats[language]["fn"] += 1

        # Per-category
        if attack_type not in cat_stats:
            cat_stats[attack_type] = {"correct": 0, "total": 0}
        cat_stats[attack_type]["total"]   += 1
        cat_stats[attack_type]["correct"] += int(correct)

        status = "✓" if correct else "✗"
        print(f"{status}  [{predicted:<5}] risk={out['final_risk']:.2f}  {out['latency_ms']:.0f}ms")

        results.append({
            "id"              : row["id"],
            "prompt"          : prompt[:80],
            "language"        : language,
            "attack_type"     : attack_type,
            "expected_policy" : expected_policy,
            "predicted_policy": predicted,
            "correct"         : correct,
            "rule_score"      : out["rule_score"],
            "semantic_score"  : out["semantic_score"],
            "final_risk"      : out["final_risk"],
            "reason_codes"    : out["reason_codes"],
            "latency_ms"      : out["latency_ms"],
        })

    # Step 4: Compute metrics
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)

    metrics = compute_metrics(tp, fp, tn, fn)

    print(f"\n  Overall Accuracy : {metrics['accuracy']*100:.1f}%")
    print(f"  Precision        : {metrics['precision']*100:.1f}%")
    print(f"  Recall           : {metrics['recall']*100:.1f}%")
    print(f"  F1 Score         : {metrics['f1_score']*100:.1f}%")
    print(f"  False Positives  : {metrics['fp']}")
    print(f"  False Negatives  : {metrics['fn']}")

    # Latency
    sorted_lat = sorted(latencies)
    p95_idx    = int(0.95 * len(sorted_lat))
    latency_summary = {
        "mean_ms"  : round(sum(latencies) / len(latencies), 2),
        "median_ms": round(sorted_lat[len(sorted_lat)//2], 2),
        "p95_ms"   : round(sorted_lat[p95_idx], 2),
        "min_ms"   : round(min(latencies), 2),
        "max_ms"   : round(max(latencies), 2),
    }

    print(f"\n  Latency — mean: {latency_summary['mean_ms']}ms  "
          f"p95: {latency_summary['p95_ms']}ms")

    # Per-language recall
    print("\n  Per-Language Recall:")
    lang_recall = {}
    for lang, stat in lang_stats.items():
        acc = stat["correct"] / stat["total"] if stat["total"] > 0 else 0
        lang_recall[lang] = round(acc, 4)
        print(f"    {lang:<8} {acc*100:.1f}%  ({stat['correct']}/{stat['total']})")

    # Per-category accuracy
    print("\n  Per-Category Accuracy:")
    cat_accuracy = {}
    for cat, stat in cat_stats.items():
        acc = stat["correct"] / stat["total"] if stat["total"] > 0 else 0
        cat_accuracy[cat] = round(acc, 4)
        print(f"    {cat:<25} {acc*100:.1f}%  ({stat['correct']}/{stat['total']})")

    # Step 5: Save results CSV
    with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\n  Results saved → {RESULTS_CSV}")

    # Step 6: Save metrics JSON
    summary = {
        "overall_metrics" : metrics,
        "latency"         : latency_summary,
        "per_language"    : lang_recall,
        "per_category"    : cat_accuracy,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }
    with open(METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"  Metrics saved  → {METRICS_JSON}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()