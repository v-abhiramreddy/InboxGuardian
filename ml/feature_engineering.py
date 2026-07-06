"""
ml/feature_engineering.py
-------------------------
Extracts features from the labeled email CSV for ML training.

Imports keyword constants directly from scoring_agent.py — no duplication.
Reuses helper functions from scoring_agent.py and email_utils.py.
"""

import csv
import os
import re
import sys
from pathlib import Path

import numpy as np
import joblib
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

# -- Path setup --
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import keyword constants from scoring_agent (no duplication!)
from agents.scoring_agent import (
    URGENCY_KEYWORDS,
    CREDENTIAL_KEYWORDS_STRONG,
    CREDENTIAL_KEYWORDS_WEAK,
    OFFER_KEYWORDS,
    SHORTENER_DOMAINS,
    LEGITIMATE_DOMAINS,
    check_lookalike,
    is_shortener,
)
from agents.email_utils import extract_links

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).resolve().parent
DATA_PATH = ML_DIR / "data" / "processed" / "labeled_emails.csv"
MODELS_DIR = ML_DIR / "models"
TFIDF_MAX_FEATURES = 5000


# ---------------------------------------------------------------------------
# Feature extraction functions
# ---------------------------------------------------------------------------

def count_keyword_matches(text: str, keywords: list[str]) -> int:
    """Count how many distinct keywords from the list appear in text."""
    text_lower = text.lower()
    count = 0
    for kw in keywords:
        if re.search(r'\b' + re.escape(kw) + r'\b', text_lower):
            count += 1
    return count


def extract_domain_from_sender(sender: str) -> str:
    """Extract domain from a sender string like 'Name <email@domain.com>'."""
    match = re.search(r'@([\w.-]+)', sender)
    return match.group(1).lower() if match else ""


def extract_structural_features(row: dict) -> dict:
    """Extract hand-engineered features from a single email row."""
    sender = row.get("sender", "")
    subject = row.get("subject", "")
    body = row.get("body_text", "")
    links_str = row.get("links", "")
    combined = (subject + " " + body).lower()

    # Parse links from body text (reusing email_utils)
    body_links = extract_links(body)
    if isinstance(links_str, list):
        body_links.extend(links_str)
    elif links_str:
        body_links.extend(links_str.split(","))
    body_links = list(set(body_links))

    # Domain analysis
    domain = extract_domain_from_sender(sender)
    has_lookalike = check_lookalike(domain) is not None if domain else False
    has_shortener = any(is_shortener(link) for link in body_links) if body_links else False

    # Keyword counts (imported from scoring_agent — single source of truth)
    urgency_count = count_keyword_matches(combined, URGENCY_KEYWORDS)
    credential_count = count_keyword_matches(combined, CREDENTIAL_KEYWORDS_STRONG + CREDENTIAL_KEYWORDS_WEAK)
    offer_count = count_keyword_matches(combined, OFFER_KEYWORDS)

    return {
        "has_lookalike_domain": int(has_lookalike),
        "num_links": len(body_links),
        "has_url_shortener": int(has_shortener),
        "urgency_keyword_count": urgency_count,
        "credential_keyword_count": credential_count,
        "offer_keyword_count": offer_count,
        "body_length": len(body),
        "subject_length": len(subject),
        "has_sender_domain_mismatch": 0,  # Can't reliably compute without display name parsing on all rows
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def load_dataset() -> list[dict]:
    """Load the labeled CSV dataset."""
    rows = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    print(f"Loaded {len(rows)} rows from {DATA_PATH}")
    return rows


def build_features(rows: list[dict]):
    """
    Build feature matrix from raw rows.

    Returns:
        X: sparse feature matrix (TF-IDF + structural)
        y: encoded label array
        label_encoder: fitted LabelEncoder
        tfidf: fitted TfidfVectorizer
        feature_names: list of feature names
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # --- Text features (TF-IDF) ---
    print("Building TF-IDF features...")
    texts = [f"{r.get('subject', '')} {r.get('body_text', '')}" for r in rows]
    tfidf = TfidfVectorizer(
        max_features=TFIDF_MAX_FEATURES,
        ngram_range=(1, 2),
        stop_words="english",
        min_df=2,
        max_df=0.95,
    )
    X_tfidf = tfidf.fit_transform(texts)
    print(f"  TF-IDF shape: {X_tfidf.shape}")

    # --- Structural features ---
    print("Extracting structural features...")
    struct_feature_names = [
        "has_lookalike_domain", "num_links", "has_url_shortener",
        "urgency_keyword_count", "credential_keyword_count",
        "offer_keyword_count", "body_length", "subject_length",
        "has_sender_domain_mismatch",
    ]
    struct_matrix = []
    for i, row in enumerate(rows):
        feats = extract_structural_features(row)
        struct_matrix.append([feats[name] for name in struct_feature_names])
        if (i + 1) % 500 == 0:
            print(f"  Processed {i + 1}/{len(rows)}")

    X_struct = csr_matrix(np.array(struct_matrix, dtype=np.float64))
    print(f"  Structural shape: {X_struct.shape}")

    # --- Combine ---
    X = hstack([X_tfidf, X_struct])
    feature_names = list(tfidf.get_feature_names_out()) + struct_feature_names
    print(f"  Combined shape: {X.shape}")

    # --- Labels ---
    labels = [r["label"] for r in rows]
    le = LabelEncoder()
    y = le.fit_transform(labels)
    print(f"  Classes: {list(le.classes_)}")

    # --- Save artifacts ---
    joblib.dump(tfidf, MODELS_DIR / "tfidf_vectorizer.joblib")
    joblib.dump(le, MODELS_DIR / "label_encoder.joblib")
    print(f"  Saved tfidf_vectorizer.joblib and label_encoder.joblib to {MODELS_DIR}")

    return X, y, le, tfidf, feature_names


def main():
    print("=" * 60)
    print("ML FEATURE ENGINEERING")
    print("=" * 60)

    rows = load_dataset()

    # --- Strict Deduplication ---
    unique_rows = []
    seen_bodies = set()
    for r in rows:
        body = r.get("body_text", "").strip()
        if body not in seen_bodies:
            seen_bodies.add(body)
            unique_rows.append(r)
    
    print(f"Deduplicated dataset: {len(rows)} -> {len(unique_rows)} rows (removed {len(rows) - len(unique_rows)} duplicates)")
    rows = unique_rows

    X, y, le, tfidf, feature_names = build_features(rows)

    # Save processed arrays for training
    from scipy.sparse import save_npz
    save_npz(MODELS_DIR / "X_features.npz", X)
    np.save(MODELS_DIR / "y_labels.npy", y)

    # Save is_synthetic flags for eval
    is_synthetic = np.array([r.get("is_synthetic", "False") == "True" for r in rows])
    np.save(MODELS_DIR / "is_synthetic.npy", is_synthetic)

    # Save raw text for leakage checking
    body_texts = [r.get("body_text", "") for r in rows]
    joblib.dump(body_texts, MODELS_DIR / "body_texts.joblib")

    print(f"\nSaved X_features.npz ({X.shape}), y_labels.npy ({y.shape})")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
