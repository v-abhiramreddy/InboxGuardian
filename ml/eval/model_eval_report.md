# ML Classifier â€” Evaluation Report

**Generated:** 2026-07-06 10:35

## Data Integrity

### Train/Test Leakage Check
Overlap (exact `body_text` match between train and test splits): **0 rows**

âœ… No leakage detected.

### Real vs Synthetic Data in Test Set
| Data Type | Rows | RF Accuracy |
|---|---|---|
| Real | 324 | 0.8951 |
| Synthetic | 150 | 0.9867 |

## Cross-Validation Results (Training Set)

| Model | CV Accuracy (mean) | CV Std | Train Acc | Test Acc |
|---|---|---|---|---|
| **RandomForest** | 0.9098 | 0.0071 | 0.9335 | 0.9241 |
| **LogisticRegression** | 0.8877 | 0.0320 | 0.8518 | 0.8354 |

## Overall Real-World Accuracy (Excluding Synthetic Data)

| Model | Test Accuracy (Real Data Only) |
|---|---|
| **RandomForest (ML)** | 0.8951 (324 rows) |

> [!NOTE]
> Synthetic data metrics (Scam class) are excluded from the real-world accuracy metric to avoid circularity claims. The synthetic data accuracy was 0.9867 (150 rows).

## Overall Accuracy Comparison (Full Test Set)

| Model | Test Accuracy |
|---|---|
| **RandomForest (ML)** | 0.9241 |
| **LogisticRegression (Baseline)** | 0.8354 |
| **Rule Engine (scoring_agent)** | 0.3165 |

## Per-Class Metrics: RandomForest

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **phishing** | 1.0000 | 0.5750 | 0.7302 | 40 |
| **safe** | 0.8418 | 1.0000 | 0.9141 | 149 |
| **scam** | 1.0000 | 0.9867 | 0.9933 | 150 |
| **spam** | 0.9365 | 0.8741 | 0.9042 | 135 |
| **weighted avg** | 0.9322 | 0.9241 | 0.9208 | 474 |

### Confusion Matrix (RandomForest)

| Actual \ Predicted | phishing | safe | scam | spam |
|---|---|---|---|---|
| **phishing** | 23 | 9 | 0 | 8 |
| **safe** | 0 | 149 | 0 | 0 |
| **scam** | 0 | 2 | 148 | 0 |
| **spam** | 0 | 17 | 0 | 118 |

## Per-Class Metrics: LogisticRegression

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **phishing** | 0.8077 | 0.5250 | 0.6364 | 40 |
| **safe** | 0.7711 | 0.8591 | 0.8127 | 149 |
| **scam** | 1.0000 | 1.0000 | 1.0000 | 150 |
| **spam** | 0.7348 | 0.7185 | 0.7266 | 135 |
| **weighted avg** | 0.8363 | 0.8354 | 0.8326 | 474 |

### Confusion Matrix (LogisticRegression)

| Actual \ Predicted | phishing | safe | scam | spam |
|---|---|---|---|---|
| **phishing** | 21 | 4 | 0 | 15 |
| **safe** | 1 | 128 | 0 | 20 |
| **scam** | 0 | 0 | 150 | 0 |
| **spam** | 4 | 34 | 0 | 97 |

## Per-Class Metrics: Rule Engine

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **phishing** | 0.0000 | 0.0000 | 0.0000 | 40 |
| **safe** | 0.3172 | 0.7047 | 0.4375 | 149 |
| **scam** | 0.3214 | 0.3000 | 0.3103 | 150 |
| **spam** | 0.0000 | 0.0000 | 0.0000 | 135 |
| **weighted avg** | 0.2014 | 0.3165 | 0.2357 | 474 |

### Confusion Matrix (Rule Engine)

| Actual \ Predicted | phishing | safe | scam | spam |
|---|---|---|---|---|
| **phishing** | 0 | 26 | 14 | 0 |
| **safe** | 0 | 105 | 44 | 0 |
| **scam** | 0 | 102 | 45 | 3 |
| **spam** | 0 | 98 | 37 | 0 |

## Where ML Underperforms the Rule Engine

The ML model matches or exceeds the rule engine on all categories.

## Known-Hard-Case Sanity Test

These are the exact emails that historically caused false positives in the rule engine
(KITSW mailing-list, Unstop event platform, Sreenidhi college).

| Email | Expected | ML Predicted | Rule Engine | ML Correct? | Rule Correct? |
|---|---|---|---|---|---|
| KITSW mailing-list forwarded email | safe | safe | safe (score=0) | âœ… | âœ… |
| Unstop event platform email | safe | safe | safe (score=0) | âœ… | âœ… |
| Sreenidhi college email | safe | safe | safe (score=0) | âœ… | âœ… |

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
