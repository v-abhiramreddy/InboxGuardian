import logging
_ML_LIBS_AVAILABLE = False
try:
    import joblib
    import numpy as np
    from scipy.sparse import hstack, csr_matrix
    _ML_LIBS_AVAILABLE = True
except ImportError:
    pass
from pathlib import Path

# Add project root to path for imports
import sys
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml.feature_engineering import extract_structural_features

# Global singletons for models
_model = None
_tfidf = None
_label_encoder = None
_models_loaded = False
_missing_warned = False

def _load_models():
    """Load models once at module level, handling missing files gracefully."""
    global _model, _tfidf, _label_encoder, _models_loaded, _missing_warned
    
    if not _ML_LIBS_AVAILABLE:
        if not _missing_warned:
            logging.warning("ML Classifier libraries are missing. ML integration will be disabled.")
            _missing_warned = True
        return False
        
    if _models_loaded:
        return True
        
    models_dir = _PROJECT_ROOT / "ml" / "models"
    try:
        _model = joblib.load(models_dir / "classifier.joblib")
        _tfidf = joblib.load(models_dir / "tfidf_vectorizer.joblib")
        _label_encoder = joblib.load(models_dir / "label_encoder.joblib")
        _models_loaded = True
        return True
    except (FileNotFoundError, EOFError, ImportError, NameError) as e:
        if not _missing_warned:
            logging.warning(f"ML Classifier models could not be loaded: {e}. ML integration will be disabled.")
            _missing_warned = True
        return False

# Attempt to load right away for performance, but don't crash if missing
_load_models()

def predict_category(email: dict) -> dict:
    """
    Predict the email category using the trained ML model.
    Returns: {"category": str, "confidence": float}
    Returns None if models failed to load.
    """
    if not _load_models():
        return None
        
    subject = email.get("subject", "")
    body_text = email.get("body_text", "")
    
    # 1. TF-IDF features
    text = f"{subject} {body_text}"
    X_tfidf = _tfidf.transform([text])
    
    # 2. Structural features
    feats = extract_structural_features(email)
    struct_names = [
        "has_lookalike_domain", "num_links", "has_url_shortener",
        "urgency_keyword_count", "credential_keyword_count",
        "offer_keyword_count", "body_length", "subject_length",
        "has_sender_domain_mismatch",
    ]
    struct_vec = csr_matrix(np.array([[feats[n] for n in struct_names]], dtype=np.float64))
    
    # 3. Combine
    X = hstack([X_tfidf, struct_vec])
    
    # 4. Predict
    proba = _model.predict_proba(X)[0]
    pred_idx = np.argmax(proba)
    confidence = float(proba[pred_idx])
    
    category = _label_encoder.inverse_transform([pred_idx])[0]
    
    return {
        "category": category,
        "confidence": confidence
    }
