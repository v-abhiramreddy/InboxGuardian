"""
main.py
-------
Runs the full email safety analysis pipeline end-to-end:
1. Fetches real recent emails from Gmail via the connector agent.
2. Scores each email using the scoring agent's threat detection model.
3. Updates results.json with the generated scoring objects.
4. Prints a console summary of the results.
"""

import json
import os
from collections import Counter
from pathlib import Path

from agents.audit_log import log_decision
from agents.connector_agent import fetch_recent_emails
from agents.scoring_agent import score_email

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
RESULTS_PATH = PROJECT_ROOT / "results.json"


def main():
    print("=" * 60)
    print("Email Safety Pipeline - End-to-End Execution")
    print("=" * 60)

    # 1. Fetch real emails from Gmail
    print("\n[1/3] Fetching recent emails from Gmail...")
    try:
        real_emails = fetch_recent_emails(count=15)
        print(f"      [OK] Successfully fetched {len(real_emails)} real email(s).")
    except Exception as exc:
        print(f"      [ERROR] Failed to fetch emails: {exc}")
        return

    if not real_emails:
        print("      [WARNING] No emails were retrieved. Exiting.")
        return

    # 2. Score all retrieved emails
    print("\n[2/3] Running threat analysis & scoring on emails...")
    new_results = []
    category_counts = Counter()

    for email in real_emails:
        try:
            score_obj = score_email(email)
            # Audit log — PII-free decision record (no subject/sender/body)
            log_decision(
                email_id=score_obj["email_id"],
                score=score_obj["score"],
                category=score_obj["category"],
                confidence=score_obj["confidence"],
            )
            score_obj["subject"] = email.get("subject", "")
            score_obj["sender"] = email.get("sender", "")
            new_results.append(score_obj)
            category_counts[score_obj["category"]] += 1
        except Exception as exc:
            print(f"      [WARNING] Failed to score email {email.get('id')}: {exc}")

    # 3. Save results.json
    try:
        with open(RESULTS_PATH, "w", encoding="utf-8") as f:
            json.dump(new_results, f, indent=2, ensure_ascii=False)
        print("      [OK] Scoring results saved to results.json.")
    except Exception as exc:
        print(f"      [ERROR] Could not save results: {exc}")
        return

    # 4. Summary Report
    print("\n" + "=" * 60)
    print("Pipeline Execution Summary")
    print("=" * 60)
    print(f"Total Emails Scanned: {len(new_results)}")
    print("Breakdown by Safety Category:")
    for cat in ["safe", "spam", "scam", "phishing"]:
        count = category_counts.get(cat, 0)
        print(f"  - {cat.upper():<10}: {count}")
    print("=" * 60)
    print("\nAll done! You can now start the dashboard to view the real data:")
    print("streamlit run dashboard/app.py\n")


if __name__ == "__main__":
    main()
