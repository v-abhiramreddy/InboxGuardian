"""
audit_log.py
------------
Append-only audit logger for email scoring decisions.
Logs ONLY the decision metadata (email_id, score, category, confidence)
with a timestamp. No PII (subject, sender, body) is ever written to the log.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Audit log lives at the project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
AUDIT_LOG_PATH = _PROJECT_ROOT / "audit-log.jsonl"


def log_decision(
    email_id: str,
    score: int | float,   # FIX Bug 16: was typed as int; widened to int|float
    category: str,
    confidence: float,
) -> None:
    """
    Append a single scoring decision to audit-log.jsonl.

    Each line is a self-contained JSON object with:
        timestamp, email_id, score, category, confidence

    Intentionally omits subject, sender, body_text, and any other PII
    to keep the audit trail free of personal data.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email_id": email_id,
        "score": score,
        "category": category,
        "confidence": confidence,
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        # Audit logging should never crash the pipeline
        print(f"[audit_log] WARNING: Failed to write audit entry: {exc}")
