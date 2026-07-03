import json
import os
import re
from urllib.parse import urlparse

# Standard/Legitimate brands and their official domains
LEGITIMATE_DOMAINS = {
    "netflix": "netflix.com",
    "chase": "chase.com",
    "paypal": "paypal.com",
    "docusign": "docusign.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "office 365": "office.com",
    "amazon": "amazon.com",
    "fedex": "fedex.com",
    "venmo": "venmo.com",
    "zoom": "zoom.us",
    "google": "google.com",
    "github": "github.com",
    "spotify": "spotify.com",
    "adobe": "adobe.com",
    "linkedin": "linkedin.com",
}

# Lookalike/typosquatted character replacements for detection
LOOKALIKES = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
}

# URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
}

def clean_domain(domain: str) -> str:
    """Helper to clean and normalize a domain string."""
    # FIX Bug 3: lstrip("www.") stripped any leading char in the SET {'w','.'}
    # e.g. "windows.example.com" → "indows.example.com". Use startswith instead.
    d = domain.strip().lower()
    if d.startswith("www."):
        d = d[4:]
    return d

def is_subdomain_of(domain: str, parent: str) -> bool:
    """Check if domain is parent domain or a subdomain of parent."""
    return domain == parent or domain.endswith("." + parent)

def is_sender_self_identified(display_name: str, sender_domain: str) -> bool:
    """
    Check if the display name openly and honestly identifies the sender domain.
    E.g. display name 'Kaggle' for domain 'kaggle.com' is self-identified.
    """
    if not display_name:
        return False
    dn = re.sub(r'[^a-zA-Z0-9]', '', display_name.lower())
    sd = re.sub(r'[^a-zA-Z0-9]', '', sender_domain.split('.')[0].lower())
    return dn == sd or sd in dn or dn in sd

def is_shortener(url: str) -> bool:
    """Check if the given URL uses a known link shortener."""
    try:
        parsed = urlparse(url)
        netloc = clean_domain(parsed.netloc or parsed.path.split("/")[0])
        return netloc in SHORTENER_DOMAINS
    except Exception:
        return False

def check_lookalike(domain: str) -> str | None:
    """
    Check if a domain is a lookalike/typosquatted version of a trusted brand.
    Returns the brand name if lookalike is detected, otherwise None.
    """
    domain = clean_domain(domain)
    # Normalize lookalike characters
    normalized = domain
    for char, replacement in LOOKALIKES.items():
        normalized = normalized.replace(char, replacement)
    
    for brand, legit_domain in LEGITIMATE_DOMAINS.items():
        # If the domain contains lookalike characters of the brand
        # Or if the brand name is in the domain but the domain is not the legitimate one/subdomain
        if brand in normalized and not is_subdomain_of(domain, legit_domain):
            return brand
    return None

def score_email(email: dict) -> dict:
    """
    Analyze and score an email for phishing and fraud risk.
    
    Args:
        email (dict): The email object containing:
            - id (str)
            - sender (str)
            - subject (str)
            - body_text (str)
            - links (list[str])
            - headers (dict) with keys 'spf', 'dkim', 'dmarc'
            
    Returns:
        dict: The score object containing:
            - email_id (str)
            - score (int): 0-100
            - category (str): "phishing" | "scam" | "spam" | "safe"
            - confidence (float): 0.0 - 1.0
            - explanation (str)
    """
    # 1. Input validation & basic error handling
    required_fields = ["id", "sender", "subject", "body_text", "links", "headers"]
    for field in required_fields:
        if field not in email:
            raise KeyError(f"Missing required field: '{field}'")
            
    headers = email["headers"]
    required_headers = ["spf", "dkim", "dmarc"]
    for header in required_headers:
        if header not in headers:
            raise KeyError(f"Missing required header: '{header}'")

    email_id = email["id"]
    sender = email["sender"]
    subject = email["subject"]
    body_text = email["body_text"]
    links = email["links"]

    # Parse sender email
    display_name = ""
    email_address = sender
    sender_match = re.match(r'(.*?)\s*<(.*)>', sender)
    if sender_match:
        display_name = sender_match.group(1).strip()
        email_address = sender_match.group(2).strip()

    sender_parts = email_address.split("@")
    sender_local = sender_parts[0] if len(sender_parts) > 1 else ""
    sender_domain = clean_domain(sender_parts[1]) if len(sender_parts) > 1 else ""

    # Short-circuit: If the email is from a verified legitimate brand (passing SPF, DKIM, and DMARC)
    # we know for a fact it is authentic and should be marked safe immediately.
    spf = headers.get("spf", "").lower()
    dkim = headers.get("dkim", "").lower()
    dmarc = headers.get("dmarc", "").lower()
    
    is_verified_brand = False
    for brand, legit in LEGITIMATE_DOMAINS.items():
        if is_subdomain_of(sender_domain, legit):
            if spf == "pass" and dkim == "pass" and dmarc == "pass":
                is_verified_brand = True
                break
                
    if is_verified_brand:
        return {
            "email_id": email_id,
            "score": 0,
            "category": "safe",
            "confidence": 1.0,
            "explanation": f"Verified authentic email from {sender_domain} (SPF/DKIM/DMARC passed)."
        }

    # Keep track of triggered signals
    signals_sender = []
    signals_links = []
    signals_language = []
    signals_attachment = []

    # Keep track of confidence components
    # FIX Bug 8: These were never updated (except conf_links for shorteners),
    # so confidence was always 0.3+0.3+0.2+0.2 = 1.0 and thus meaningless.
    # Now each component starts at full weight and is reduced when signals are
    # ambiguous (e.g., zero signals in a category means that category gives 0
    # evidence, so its confidence contribution is halved).
    conf_auth = 0.3
    conf_links = 0.3
    conf_lang = 0.2
    conf_attach = 0.2

    # --- CATEGORY 1: Sender Authenticity ---
    # Signal A: Display Name / Local Part vs Actual Email Mismatch
    # If the local part or display name claims a brand, but the domain doesn't match
    for brand, legit in LEGITIMATE_DOMAINS.items():
        if brand in sender_local.lower() or brand in display_name.lower():
            if not is_subdomain_of(sender_domain, legit):
                signals_sender.append("Display Name / Local Part vs. Actual Email Mismatch")
                break

    # Signal B: Domain Mismatch (Claimed Org vs Actual Domain)
    # If the subject claims a brand, but the sender domain does not match.
    # We do NOT trigger this if the sender's display name openly and honestly matches their sender domain
    # (e.g. 'Kaggle' sending an email with 'Google' in the subject is not spoofing Google).
    if not is_sender_self_identified(display_name, sender_domain):
        for brand, legit in LEGITIMATE_DOMAINS.items():
            # Check if the brand is mentioned in the subject line (stronger claim of sender identity)
            if re.search(r'\b' + re.escape(brand) + r'\b', subject.lower()):
                if not is_subdomain_of(sender_domain, legit):
                    signals_sender.append("Domain Mismatch (Claimed Org vs. Actual Domain)")
                    break

    # Signal C: Failed Authentication
    spf = headers.get("spf", "").lower()
    dkim = headers.get("dkim", "").lower()
    dmarc = headers.get("dmarc", "").lower()
    # FIX Bug 2: "fail" in (spf, dkim, dmarc) only matched the exact string "fail".
    # Use substring check so "softfail" (a real SPF result) is also caught.
    if any("fail" in v for v in (spf, dkim, dmarc)):
        signals_sender.append("Failed Authentication (SPF/DKIM/DMARC)")

    # --- CATEGORY 2: Link Analysis ---
    # Signal A: Display Text vs URL Destination Mismatch
    # We look for a brand name domain mentioned in body_text, but the actual links list has a different domain.
    body_mentions_brand_domain = False
    for brand, legit in LEGITIMATE_DOMAINS.items():
        if legit in body_text.lower():
            # Only trigger if the email contains links, but does NOT link to the claimed brand domain at all
            has_legit_link = any(is_subdomain_of(clean_domain(urlparse(link).netloc or urlparse(link).path.split("/")[0]), legit) for link in links)
            if not has_legit_link:
                for link in links:
                    try:
                        parsed = urlparse(link)
                        link_domain = clean_domain(parsed.netloc or parsed.path.split("/")[0])
                        if not is_subdomain_of(link_domain, legit):
                            signals_links.append("Display Text vs. URL Destination Mismatch")
                            body_mentions_brand_domain = True
                            break
                    except Exception:
                        pass
            if body_mentions_brand_domain:
                break

    # Signal B: Use of URL Shorteners
    has_shortener = False
    for link in links:
        if is_shortener(link):
            signals_links.append("Use of URL Shorteners")
            has_shortener = True
            conf_links = 0.0  # Link resolution failed due to short URL (cannot expand offline)
            break

    # Signal C: Lookalike Domains (Typosquatting)
    for link in links:
        try:
            parsed = urlparse(link)
            link_domain = clean_domain(parsed.netloc or parsed.path.split("/")[0])
            # Check lookalike domain
            if check_lookalike(link_domain):
                signals_links.append("Lookalike Domain (Typosquatting)")
                break
        except Exception:
            pass

    # --- CATEGORY 3: Language and Psychological Pressure ---
    # Signal A: Urgency and Threats
    urgency_keywords = [
        "urgent", "suspension", "suspended", "expire", "expiring", 
        "restrict", "restriction", "restricted", "action required", 
        "immediately", "within 24 hours", "within 12 hours", 
        "deactivated", "lock", "locked", "compromised", "unauthorized",
        "suspicious login", "billing-support"
    ]
    if any(re.search(r'\b' + re.escape(kw) + r'\b', (subject + " " + body_text).lower()) for kw in urgency_keywords):
        signals_language.append("Urgency and Threats")

    # Signal B: Requests for Credentials or Payment
    credential_keywords = [
        "verify your identity", "verify your credentials", "verify bank details",
        "recovery seed phrase", "payment details", "billing details",
        "update your login", "change your password", "processing fee", "surcharge",
        "registration fee", "recovery seed", "recovery phrase"
    ]
    credential_patterns = [
        r"\bverify\b.*\bbank\b",
        r"\bbank\b.*\bdetails\b"
    ]
    has_credential_signal = any(re.search(r'\b' + re.escape(kw) + r'\b', (subject + " " + body_text).lower()) for kw in credential_keywords) or \
                             any(re.search(pat, (subject + " " + body_text).lower()) for pat in credential_patterns)
    if has_credential_signal:
        signals_language.append("Requests for Credentials or Payment")

    # Signal C: Too-Good-To-Be-True Offers
    offer_keywords = [
        "congratulations", "won", "selected as the winner", "sweepstakes",
        "cash prize", "gift card", "free gift", "scholarship award"
    ]
    if any(re.search(r'\b' + re.escape(kw) + r'\b', (subject + " " + body_text).lower()) for kw in offer_keywords):
        signals_language.append("Too-Good-To-Be-True Offers")

    # --- CATEGORY 4: Attachment and Content Risk ---
    # Checked via body text references for simplicity (since schema has no attachments field)
    # Signal A: Unexpected Attachments
    attachment_keywords = ["attached file", "attached invoice", "attached receipt", "shipping document"]
    attachment_patterns = [
        r"\battached\b.*\binvoice\b",
        r"\battached\b.*\breceipt\b"
    ]
    has_attachment_signal = any(kw in body_text.lower() for kw in attachment_keywords) or \
                            any(re.search(pat, body_text.lower()) for pat in attachment_patterns)
    if has_attachment_signal:
        signals_attachment.append("Unexpected Attachments")

    # Signal B: Dangerous File Extensions
    dangerous_exts = [r"\.exe\b", r"\.js\b", r"\.vbs\b", r"\.bat\b", r"\.scr\b", r"\.zip\b"]
    
    link_match = any(any(re.search(ext, link.lower()) for ext in dangerous_exts) for link in links)
    body_match = any(re.search(ext, body_text.lower()) for ext in dangerous_exts)
    
    if link_match or body_match:
        signals_attachment.append("Dangerous File Extensions")

    # Signal C: Request to Enable Macros
    macro_keywords = ["enable editing", "enable content", "enable macros"]
    if any(kw in body_text.lower() for kw in macro_keywords):
        signals_attachment.append("Request to Enable Macros")

    # --- CALCULATE CATEGORY SCORES ---
    # Sender Authenticity (Max 30 pts)
    score_sender = 0
    if len(signals_sender) > 0:
        score_sender = 25 + (len(signals_sender) - 1) * 10
    score_sender = min(score_sender, 30)

    # Link Analysis (Max 30 pts)
    score_links = 0
    if len(signals_links) > 0:
        score_links = 25 + (len(signals_links) - 1) * 10
    score_links = min(score_links, 30)

    # Language and Psychological Pressure (Max 27 pts)
    score_language = 0
    if len(signals_language) > 0:
        score_language = 15 + (len(signals_language) - 1) * 12
    score_language = min(score_language, 27)

    # Attachment and Content Risk (Max 20 pts)
    score_attachment = 0
    if len(signals_attachment) > 0:
        score_attachment = 15 + (len(signals_attachment) - 1) * 5
    score_attachment = min(score_attachment, 20)

    total_score = score_sender + score_links + score_language + score_attachment
    # FIX Bug 9: Max possible before clamping was 30+30+27+20=107, exceeding the
    # advertised 0-100 range. Clamp to 100.
    total_score = min(total_score, 100)

    # --- DETERMINING CATEGORY BAND ---
    # FIX Bug 10: Previously a high-scoring email (95+) with any lottery/prize
    # language was labelled "scam" instead of "phishing", allowing phishing
    # attempts with offer-hooks to evade the phishing label.
    # Rule: phishing always wins over scam when score > 50 AND sender/link
    # signals are present (i.e., the email is actively impersonating a brand).
    is_scam_offer = "Too-Good-To-Be-True Offers" in signals_language
    has_impersonation = bool(signals_sender or signals_links)

    if total_score <= 20:
        category = "safe"
    elif total_score <= 50:
        category = "scam" if is_scam_offer else "spam"
    else:
        # At high scores, phishing takes priority if impersonation signals exist
        if is_scam_offer and not has_impersonation:
            category = "scam"
        else:
            category = "phishing"

    # --- EXPLANATION FIELD ---
    all_signals = signals_sender + signals_links + signals_language + signals_attachment
    if all_signals:
        explanation = f"Risk signals detected: {', '.join(all_signals)}."
    else:
        explanation = "No suspicious phishing or fraud risk signals were detected."

    # --- CONFIDENCE SCORE ---
    # FIX Bug 8 (continued): Reduce confidence contribution of any category that
    # produced zero signals — we have less certainty about that dimension.
    if not signals_sender:
        conf_auth *= 0.5
    if not signals_links:
        conf_links *= 0.5
    if not signals_language:
        conf_lang *= 0.5
    if not signals_attachment:
        conf_attach *= 0.5
    confidence = round(conf_auth + conf_links + conf_lang + conf_attach, 2)

    return {
        "email_id": email_id,
        "score": total_score,
        "category": category,
        "confidence": confidence,
        "explanation": explanation
    }

def main():
    mock_data_path = os.path.join("mock-data", "sample-emails.json")
    results_path = "results-demo.json"

    if not os.path.exists(mock_data_path):
        print(f"Error: Mock data file not found at {mock_data_path}")
        return

    try:
        with open(mock_data_path, "r", encoding="utf-8") as f:
            emails = json.load(f)
    except Exception as e:
        print(f"Error loading mock data: {e}")
        return

    results = []
    for email in emails:
        try:
            res = score_email(email)
            res["subject"] = email.get("subject", "")
            res["sender"] = email.get("sender", "")
            results.append(res)
            print(f"ID: {res['email_id']} | Score: {res['score']} | Category: {res['category']}")
        except KeyError as e:
            print(f"Warning: Skipping email due to missing key. {e}")
        except Exception as e:
            print(f"Warning: Skipping email {email.get('id', 'Unknown')} due to unexpected error. {e}")

    try:
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nAll results saved to {results_path} successfully.")
    except Exception as e:
        print(f"Error saving results to {results_path}: {e}")

if __name__ == "__main__":
    main()
