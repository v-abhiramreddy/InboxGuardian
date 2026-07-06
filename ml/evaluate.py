"""
ml/evaluate.py
--------------
Evaluates the trained ML classifier and compares against:
- LogisticRegression baseline
- Rule engine (scoring_agent.score_email)

Generates ml/eval/model_eval_report.md with:
- Per-class precision/recall/F1
- Confusion matrices
- Leakage check results
- Known-hard-case sanity tests (KITSW, Unstop, Sreenidhi)
- Real vs synthetic breakdown
"""

import csv
import sys
from pathlib import Path

import numpy as np
import joblib
from scipy.sparse import load_npz
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# -- Path setup --
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.scoring_agent import score_email

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).resolve().parent
MODELS_DIR = ML_DIR / "models"
EVAL_DIR = ML_DIR / "eval"
DATA_PATH = ML_DIR / "data" / "processed" / "labeled_emails.csv"


# ---------------------------------------------------------------------------
# Known-hard-case sanity test emails
# ---------------------------------------------------------------------------
# These are the exact cases that historically broke the rule engine.
# We test whether the ML model classifies them correctly.

KNOWN_HARD_CASES = [
    {
        "name": "KITSW mailing-list forwarded email",
        "email": {
            "id": "hard-kitsw",
            "sender": '"Head, Centre for I2RE KITSW" <i2re@kitsw.ac.in>',
            "subject": "Lyncc Tech Solutions Internship Opportunity - Application Form",
            "body_text": "If interested, apply through Google form by 9am on Monday 6th July 2026.",
            "links": ["https://forms.google.com/example"],
            "headers": {"spf": "softfail", "dkim": "pass", "dmarc": "none", "arc": "pass"},
        },
        "expected_label": "safe",
    },
    {
        "name": "Unstop event platform email",
        "email": {
            "id": "hard-unstop",
            "sender": "Unstop <notifications@unstop.com>",
            "subject": "New Opportunity: Register now for the coding challenge",
            "body_text": "Registration is open for the national coding challenge. Submit your entry before the deadline.",
            "links": ["https://unstop.com/challenge/example"],
            "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        "expected_label": "safe",
    },
    {
        "name": "Sreenidhi college email",
        "email": {
            "id": "hard-sreenidhi",
            "sender": "Sreenidhi Institute <placements@sreenidhi.edu.in>",
            "subject": "Campus Placement Drive - Update",
            "body_text": "All eligible students must register for the upcoming placement drive. Deadline for registration is this Friday.",
            "links": ["https://sreenidhi.edu.in/placements"],
            "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        "expected_label": "safe",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_test_data():
    """Load the dataset rows corresponding to the test split."""
    # Load full dataset
    rows = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    # Load split indices
    idx_test = np.load(MODELS_DIR / "idx_test.npy")
    is_synthetic = np.load(MODELS_DIR / "is_synthetic.npy")

    test_rows = [rows[i] for i in idx_test]
    test_synthetic = is_synthetic[idx_test]
    return test_rows, test_synthetic


def rule_engine_predict(test_rows: list[dict]) -> list[str]:
    """Run score_email on each test row and return predicted categories."""
    predictions = []
    for row in test_rows:
        email_obj = {
            "id": row.get("email_id", ""),
            "sender": row.get("sender", ""),
            "subject": row.get("subject", ""),
            "body_text": row.get("body_text", ""),
            "links": [l.strip() for l in row.get("links", "").split(",") if l.strip()],
            "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "arc": "pass"},
        }
        result = score_email(email_obj)
        predictions.append(result["category"])
    return predictions


def predict_hard_cases(model, tfidf, le):
    """Run the ML model on known-hard-case emails."""
    from ml.feature_engineering import extract_structural_features
    from scipy.sparse import hstack, csr_matrix

    results = []
    for case in KNOWN_HARD_CASES:
        row = {
            "sender": case["email"]["sender"],
            "subject": case["email"]["subject"],
            "body_text": case["email"]["body_text"],
            "links": ",".join(case["email"].get("links", [])),
        }

        # Build features
        text = f"{row['subject']} {row['body_text']}"
        X_tfidf = tfidf.transform([text])

        feats = extract_structural_features(row)
        struct_names = [
            "has_lookalike_domain", "num_links", "has_url_shortener",
            "urgency_keyword_count", "credential_keyword_count",
            "offer_keyword_count", "body_length", "subject_length",
            "has_sender_domain_mismatch",
        ]
        struct_vec = csr_matrix(np.array([[feats[n] for n in struct_names]], dtype=np.float64))
        X = hstack([X_tfidf, struct_vec])

        pred_idx = model.predict(X)[0]
        pred_label = le.inverse_transform([pred_idx])[0]

        # Also get rule engine result
        rule_result = score_email(case["email"])

        results.append({
            "name": case["name"],
            "expected": case["expected_label"],
            "ml_predicted": pred_label,
            "rule_engine_category": rule_result["category"],
            "rule_engine_score": rule_result["score"],
            "correct_ml": pred_label == case["expected_label"],
            "correct_rule": rule_result["category"] == case["expected_label"],
        })
    return results


def format_confusion_matrix(cm, classes):
    """Format a confusion matrix as a markdown table."""
    header = "| Actual \\ Predicted | " + " | ".join(classes) + " |"
    sep = "|" + "---|" * (len(classes) + 1)
    rows = []
    for i, cls in enumerate(classes):
        row_vals = " | ".join(str(cm[i, j]) for j in range(len(classes)))
        rows.append(f"| **{cls}** | {row_vals} |")
    return "\n".join([header, sep] + rows)


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ML MODEL EVALUATION")
    print("=" * 60)

    EVAL_DIR.mkdir(parents=True, exist_ok=True)

    # --- Load models and data ---
    gbm = joblib.load(MODELS_DIR / "classifier.joblib")
    lr = joblib.load(MODELS_DIR / "baseline_lr.joblib")
    le = joblib.load(MODELS_DIR / "label_encoder.joblib")
    tfidf = joblib.load(MODELS_DIR / "tfidf_vectorizer.joblib")
    training_results = joblib.load(MODELS_DIR / "training_results.joblib")

    X = load_npz(MODELS_DIR / "X_features.npz")
    y = np.load(MODELS_DIR / "y_labels.npy")
    idx_test = np.load(MODELS_DIR / "idx_test.npy")
    idx_train = np.load(MODELS_DIR / "idx_train.npy")

    X_test = X[idx_test]
    y_test = y[idx_test]
    classes = list(le.classes_)

    test_rows, test_synthetic = load_test_data()

    # --- ML Model predictions ---
    print("\n--- RandomForest predictions ---")
    y_pred_rf = gbm.predict(X_test)
    acc_rf = accuracy_score(y_test, y_pred_rf)
    report_rf = classification_report(y_test, y_pred_rf, target_names=classes, output_dict=True)
    cm_rf = confusion_matrix(y_test, y_pred_rf)
    print(f"  Accuracy: {acc_rf:.4f}")

    # --- LR Baseline predictions ---
    print("\n--- LogisticRegression predictions ---")
    y_pred_lr = lr.predict(X_test)
    acc_lr = accuracy_score(y_test, y_pred_lr)
    report_lr = classification_report(y_test, y_pred_lr, target_names=classes, output_dict=True)
    cm_lr = confusion_matrix(y_test, y_pred_lr)
    print(f"  Accuracy: {acc_lr:.4f}")

    # --- Rule Engine predictions ---
    print("\n--- Rule Engine predictions ---")
    rule_preds = rule_engine_predict(test_rows)
    y_true_labels = le.inverse_transform(y_test)
    acc_rule = accuracy_score(y_true_labels, rule_preds)
    report_rule = classification_report(
        y_true_labels, rule_preds,
        target_names=classes, output_dict=True,
        labels=classes, zero_division=0,
    )
    cm_rule = confusion_matrix(y_true_labels, rule_preds, labels=classes)
    print(f"  Accuracy: {acc_rule:.4f}")

    # --- Known-hard-case sanity test ---
    print("\n--- Known-Hard-Case Sanity Test ---")
    hard_case_results = predict_hard_cases(gbm, tfidf, le)
    for hc in hard_case_results:
        status = "PASS" if hc["correct_ml"] else "FAIL"
        print(f"  [{status}] {hc['name']}: ML={hc['ml_predicted']}, Rule={hc['rule_engine_category']} (expected {hc['expected']})")

    # --- 4. Report Real vs Synthetic Accuracy Breakdown ---
    print("\n--- Real vs Synthetic Breakdown ---")
    
    # Exclude entirely synthetic rows (scam class) from "Real-World Accuracy"
    real_mask = ~test_synthetic
    real_y_test = y_test[real_mask]
    real_y_pred_rf = y_pred_rf[real_mask]
    
    if len(real_y_test) > 0:
        real_acc = accuracy_score(real_y_test, real_y_pred_rf)
    else:
        real_acc = 0.0
        
    syn_mask = test_synthetic
    syn_y_test = y_test[syn_mask]
    syn_y_pred_rf = y_pred_rf[syn_mask]
    
    if len(syn_y_test) > 0:
        syn_acc = accuracy_score(syn_y_test, syn_y_pred_rf)
    else:
        syn_acc = 0.0
        
    print(f"  Real data accuracy: {real_acc:.4f} ({np.sum(real_mask)} rows)")
    print(f"  Synthetic data accuracy: {syn_acc:.4f} ({np.sum(syn_mask)} rows)")

    # --- Generate report ---
    _write_report(
        classes, training_results,
        acc_rf, report_rf, cm_rf,
        acc_lr, report_lr, cm_lr,
        acc_rule, report_rule, cm_rule,
        hard_case_results,
        real_acc, syn_acc,
        np.sum(real_mask), np.sum(syn_mask),
    )

    print(f"\n{'=' * 60}")
    print(f"Report saved to: {EVAL_DIR / 'model_eval_report.md'}")
    print(f"{'=' * 60}")


def _write_report(
    classes, training_results,
    acc_rf, report_rf, cm_rf,
    acc_lr, report_lr, cm_lr,
    acc_rule, report_rule, cm_rule,
    hard_case_results,
    real_acc, syn_acc,
    real_count, syn_count,
):
    """Generate the evaluation report markdown."""
    from datetime import datetime
    report_path = EVAL_DIR / "model_eval_report.md"

    leakage = training_results.get("leakage_overlap", -1)

    def fmt_report_table(report_dict, classes):
        header = "| Class | Precision | Recall | F1-Score | Support |"
        sep = "|---|---|---|---|---|"
        rows = []
        for cls in classes:
            if cls in report_dict:
                r = report_dict[cls]
                rows.append(f"| **{cls}** | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1-score']:.4f} | {int(r['support'])} |")
        # Add weighted avg
        if "weighted avg" in report_dict:
            wa = report_dict["weighted avg"]
            rows.append(f"| **weighted avg** | {wa['precision']:.4f} | {wa['recall']:.4f} | {wa['f1-score']:.4f} | {int(wa['support'])} |")
        return "\n".join([header, sep] + rows)

    content = f"""# ML Classifier â€” Evaluation Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M")}

## Data Integrity

### Train/Test Leakage Check
Overlap (exact `body_text` match between train and test splits): **{leakage} rows**

{"âœ… No leakage detected." if leakage == 0 else f"âš ï¸ WARNING: {leakage} rows overlap between train and test sets. Metrics may be inflated."}

### Real vs Synthetic Data in Test Set
| Data Type | Rows | RF Accuracy |
|---|---|---|
| Real | {real_count} | {f"{real_acc:.4f}" if real_acc is not None else "N/A"} |
| Synthetic | {syn_count} | {f"{syn_acc:.4f}" if syn_acc is not None else "N/A"} |

## Cross-Validation Results (Training Set)

| Model | CV Accuracy (mean) | CV Std | Train Acc | Test Acc |
|---|---|---|---|---|
| **RandomForest** | {training_results['rf_cv_mean']:.4f} | {training_results['rf_cv_std']:.4f} | {training_results['rf_train_acc']:.4f} | {training_results['rf_test_acc']:.4f} |
| **LogisticRegression** | {training_results['lr_cv_mean']:.4f} | {training_results['lr_cv_std']:.4f} | {training_results['lr_train_acc']:.4f} | {training_results['lr_test_acc']:.4f} |

## Overall Real-World Accuracy (Excluding Synthetic Data)

| Model | Test Accuracy (Real Data Only) |
|---|---|
| **RandomForest (ML)** | {real_acc:.4f} ({real_count} rows) |

> [!NOTE]
> Synthetic data metrics (Scam class) are excluded from the real-world accuracy metric to avoid circularity claims. The synthetic data accuracy was {syn_acc:.4f} ({syn_count} rows).

## Overall Accuracy Comparison (Full Test Set)

| Model | Test Accuracy |
|---|---|
| **RandomForest (ML)** | {acc_rf:.4f} |
| **LogisticRegression (Baseline)** | {acc_lr:.4f} |
| **Rule Engine (scoring_agent)** | {acc_rule:.4f} |

## Per-Class Metrics: RandomForest

{fmt_report_table(report_rf, classes)}

### Confusion Matrix (RandomForest)

{format_confusion_matrix(cm_rf, classes)}

## Per-Class Metrics: LogisticRegression

{fmt_report_table(report_lr, classes)}

### Confusion Matrix (LogisticRegression)

{format_confusion_matrix(cm_lr, classes)}

## Per-Class Metrics: Rule Engine

{fmt_report_table(report_rule, classes)}

### Confusion Matrix (Rule Engine)

{format_confusion_matrix(cm_rule, classes)}

## Where ML Underperforms the Rule Engine

"""
    # Honest comparison per class
    underperforms = []
    for cls in classes:
        gbm_f1 = report_rf.get(cls, {}).get("f1-score", 0)
        rule_f1 = report_rule.get(cls, {}).get("f1-score", 0)
        if gbm_f1 < rule_f1:
            underperforms.append(f"- **{cls}**: ML F1={gbm_f1:.4f} vs Rule F1={rule_f1:.4f} (rule engine is better by {rule_f1 - gbm_f1:.4f})")

    if underperforms:
        content += "\n".join(underperforms) + "\n"
    else:
        content += "The ML model matches or exceeds the rule engine on all categories.\n"

    # Known-hard-case results
    content += f"""
## Known-Hard-Case Sanity Test

These are the exact emails that historically caused false positives in the rule engine
(KITSW mailing-list, Unstop event platform, Sreenidhi college).

| Email | Expected | ML Predicted | Rule Engine | ML Correct? | Rule Correct? |
|---|---|---|---|---|---|
"""
    for hc in hard_case_results:
        ml_ok = "âœ…" if hc["correct_ml"] else "âŒ"
        rule_ok = "âœ…" if hc["correct_rule"] else "âŒ"
        content += f"| {hc['name']} | {hc['expected']} | {hc['ml_predicted']} | {hc['rule_engine_category']} (score={hc['rule_engine_score']}) | {ml_ok} | {rule_ok} |\n"

    content += """
## Methodology Notes

- **Train/test split:** 80/20, stratified by class
- **Cross-validation:** 5-fold stratified on training set
- **RandomForest:** n_estimators=100, max_depth=10 (to prevent overfitting)
- **LogisticRegression:** max_iter=1000, lbfgs solver
- **Features:** TF-IDF (max_features=5000, bigrams) + 9 structural features
- **Rule engine comparison:** `score_email()` called with valid auth headers (`spf/dkim/dmarc=pass`)
  for the test dataset rows so the rule engine is judged fairly on content-detection,
  rather than failing automatically due to missing authentication.
- **Hard Cases:** Evaluated using their actual historical auth headers.
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  Report written to {report_path}")


if __name__ == "__main__":
    main()

