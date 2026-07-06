import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.scoring_agent import score_email
from agents.ml_classifier_agent import predict_category

def evaluate_ensemble(email_obj):
    scored = score_email(email_obj)
    ml_scored = predict_category(email_obj)
    
    rule_cat = scored.get("category", "safe").lower()
    if ml_scored:
        ml_cat = ml_scored.get("category", "unknown").lower()
        ml_conf = ml_scored.get("confidence", 0.0)
    else:
        ml_cat = rule_cat
        ml_conf = 0.0
        
    force_escalation = False
    if rule_cat != ml_cat and ml_conf >= 0.60:
        force_escalation = True
        
    return rule_cat, ml_cat, ml_conf, force_escalation

def test_kitsw_safe():
    email = {
        "id": "kitsw-test",
        "sender": "Some Teacher <teacher@kitsw.ac.in>",
        "subject": "Important update about exam schedule",
        "body_text": "Please note that the final exam has been rescheduled to next Monday.",
        "links": [],
        "headers": {
            "spf": "softfail",
            "dkim": "pass",
            "dmarc": "none",
            "arc": "pass"
        }
    }
    rule_cat, ml_cat, ml_conf, escalated = evaluate_ensemble(email)
    assert not escalated, f"False escalation on KITSW! Rule: {rule_cat}, ML: {ml_cat} ({ml_conf})"

def test_unstop_safe():
    email = {
        "id": "unstop-test",
        "sender": "Unstop Team <hello@unstop.com>",
        "subject": "Hackathon registration closes soon",
        "body_text": "Hurry up and register for the upcoming coding challenge.",
        "links": [],
        "headers": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass"
        }
    }
    rule_cat, ml_cat, ml_conf, escalated = evaluate_ensemble(email)
    assert not escalated, f"False escalation on Unstop! Rule: {rule_cat}, ML: {ml_cat} ({ml_conf})"

def test_sreenidhi_safe():
    email = {
        "id": "sreenidhi-test",
        "sender": "Admin <admin@sreenidhi.edu.in>",
        "subject": "Campus placement drive",
        "body_text": "The placement drive for final year students starts next week.",
        "links": [],
        "headers": {
            "spf": "neutral",
            "dkim": "pass",
            "dmarc": "none",
            "arc": "pass"
        }
    }
    rule_cat, ml_cat, ml_conf, escalated = evaluate_ensemble(email)
    assert not escalated, f"False escalation on Sreenidhi! Rule: {rule_cat}, ML: {ml_cat} ({ml_conf})"

def test_bec_phishing():
    # Existing BEC case
    email = {
        "id": "bec-test",
        "sender": "CEO <ceo-exec-office@gmail.com>",
        "subject": "URGENT: Wire Transfer Required",
        "body_text": "I need you to process a wire transfer immediately. Please reply.",
        "links": [],
        "headers": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass"
        }
    }
    rule_cat, ml_cat, ml_conf, escalated = evaluate_ensemble(email)
    # It should either be flagged as phishing by rule engine, or escalated
    assert rule_cat in ("phishing", "scam") or escalated, f"Missed BEC! Rule: {rule_cat}, ML: {ml_cat}"

def test_gap_phishing_1():
    # Modelled on "Dear Valued Customer" gap analysis
    email = {
        "id": "gap-1",
        "sender": "Support <support@amazn-update.com>",
        "subject": "Confirm Your Identity",
        "body_text": "Dear Valued Customer, please confirm your identity to prevent account suspension.",
        "links": ["http://amazn-update.com/login"],
        "headers": {
            "spf": "softfail",
            "dkim": "none",
            "dmarc": "none"
        }
    }
    rule_cat, ml_cat, ml_conf, escalated = evaluate_ensemble(email)
    assert rule_cat in ("phishing", "scam") or escalated, f"Missed Gap 1! Rule: {rule_cat}, ML: {ml_cat}"

def test_gap_phishing_2():
    # Modelled on generic corporate notification with stripped html
    email = {
        "id": "gap-2",
        "sender": "Security <alert@paypal-secure-auth.net>",
        "subject": "Important Notification !!!",
        "body_text": "eBay Fraud Mediation Request\n\n\n  \n Dear Member, we noticed unusual activity.",
        "links": ["http://paypal-secure-auth.net/verify"],
        "headers": {
            "spf": "none",
            "dkim": "none",
            "dmarc": "none"
        }
    }
    rule_cat, ml_cat, ml_conf, escalated = evaluate_ensemble(email)
    assert rule_cat in ("phishing", "scam") or escalated, f"Missed Gap 2! Rule: {rule_cat}, ML: {ml_cat}"

if __name__ == "__main__":
    print("Testing Ensemble ML + Rule Engine Logic...")
    tests = [
        test_kitsw_safe, test_unstop_safe, test_sreenidhi_safe,
        test_bec_phishing, test_gap_phishing_1, test_gap_phishing_2
    ]
    
    passed = 0
    for t in tests:
        try:
            t()
            print(f" [PASS] {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f" [FAIL] {t.__name__}: {e}")
            
    if passed == len(tests):
        print("\nAll ensemble tests passed successfully!")
    else:
        print(f"\n{len(tests) - passed} tests failed.")
        sys.exit(1)
