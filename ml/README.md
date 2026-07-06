# ML Email Classifier

Supervised ML classifier trained as a third detection signal alongside the
existing rule engine (`scoring_agent.py`) and Gemini LLM (`llm_analysis_agent.py`).

## Reproduction Steps

Run from the project root (`InboxGuardian/`):

```bash
# Step 1: Collect and prepare dataset
python ml/collect_data.py

# Step 2: Extract features (TF-IDF + structural)
python ml/feature_engineering.py

# Step 3: Train models (GBM + LogisticRegression)
python ml/train_model.py

# Step 4: Evaluate and generate report
python ml/evaluate.py
```

## Output Files

| File | Description |
|---|---|
| `data/processed/labeled_emails.csv` | Unified dataset with `is_synthetic` column |
| `data/README.md` | Dataset provenance documentation |
| `models/classifier.joblib` | Best model (GradientBoostingClassifier) |
| `models/baseline_lr.joblib` | LogisticRegression baseline |
| `models/tfidf_vectorizer.joblib` | Fitted TF-IDF vectorizer |
| `models/label_encoder.joblib` | Label encoder (phishing/scam/spam/safe) |
| `eval/model_eval_report.md` | Full evaluation report with metrics |

## Data Sources

- **spam/safe:** SpamAssassin public corpus (Apache License, direct HTTP download)
- **phishing/scam:** Synthetic data from `scoring_agent.py` keyword patterns (clearly flagged)

See `data/README.md` for full provenance details.

## Dependencies

- scikit-learn >= 1.0
- scipy
- joblib (included with sklearn)
- numpy
