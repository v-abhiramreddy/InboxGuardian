import json
import os
import re
from urllib.parse import urlparse
from pathlib import Path

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
    "infosys": "infosys.com",
    "wipro": "wipro.com",
    "tcs": "tcs.com",
    "hcl": "hcltech.com",
    "accenture": "accenture.com",
    "naukri": "naukri.com",
    "internshala": "internshala.com",
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

# Language signal keyword lists (module-level for reuse by ML pipeline)
# Signal A: Urgency and Threats
URGENCY_KEYWORDS = [
    "urgent", "suspension", "suspended", "expire", "expiring",
    "restrict", "restriction", "restricted", "action required",
    "immediately", "within 24 hours", "within 12 hours",
    "deactivated", "lock", "locked", "compromised", "unauthorized",
    "suspicious login", "billing-support",
]

# Signal B: Requests for Credentials or Payment
CREDENTIAL_KEYWORDS_STRONG = [
    "verify your identity", "verify your credentials", "verify bank details",
    "recovery seed phrase", "payment details", "billing details",
    "update your login", "change your password",
    "recovery seed", "recovery phrase", "security deposit", "refundable deposit",
    "surcharge",
]
CREDENTIAL_PATTERNS = [
    r"\bverify\b.*\bbank\b",
    r"\bbank\b.*\bdetails\b",
]
CREDENTIAL_KEYWORDS_WEAK = ["registration fee", "processing fee", "training fee", "joining fee"]

# Signal C: Too-Good-To-Be-True Offers
OFFER_KEYWORDS = [
    "congratulations", "won", "selected as the winner", "sweepstakes",
    "cash prize", "gift card", "free gift", "scholarship award", "grant",
    "received a payment",
]

# Category 4: Attachment and Content Risk
ATTACHMENT_KEYWORDS = ["attached file", "attached invoice", "attached receipt", "shipping document"]
ATTACHMENT_PATTERNS = [
    r"\battached\b.*\binvoice\b",
    r"\battached\b.*\breceipt\b",
]
DANGEROUS_EXTENSIONS = [r"\.exe\b", r"\.js\b", r"\.vbs\b", r"\.bat\b", r"\.scr\b", r"\.zip\b"]
MACRO_KEYWORDS = ["enable editing", "enable content", "enable macros"]

# Path for local caching
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THREAT_CACHE_FILE = os.path.join(PROJECT_ROOT, "threat_feed_cache.txt")

_THREAT_DOMAINS = None
_THREAT_LAST_UPDATE = 0.0
_THREAT_STATUS = "Offline"
_THREAT_COUNT = 0

def fetch_threat_feed() -> set:
    """Fetch live phishing domains from OpenPhish feed with 60-min TTL and offline cache."""
    global _THREAT_LAST_UPDATE, _THREAT_STATUS, _THREAT_COUNT
    domains = set()
    import time
    import urllib.request
    import logging
    
    current_time = time.time()
    ttl_seconds = 3600  # 60 minutes
    
    # Check if we need to download (file missing or older than TTL)
    needs_download = True
    if os.path.exists(THREAT_CACHE_FILE):
        mtime = os.path.getmtime(THREAT_CACHE_FILE)
        if (current_time - mtime) < ttl_seconds:
            needs_download = False
            _THREAT_STATUS = "Healthy (Cached)"
            _THREAT_LAST_UPDATE = mtime

    if needs_download:
        try:
            url = "https://openphish.com/feed.txt"
            req = urllib.request.Request(
                url, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            # Strict 5-second timeout
            with urllib.request.urlopen(req, timeout=5.0) as response:
                content = response.read().decode('utf-8')
                if content.strip():
                    # Safely write using temp file
                    temp_filepath = f"{THREAT_CACHE_FILE}.tmp"
                    with open(temp_filepath, "w", encoding="utf-8") as f:
                        f.write(content)
                    os.replace(temp_filepath, THREAT_CACHE_FILE)
                    
                    _THREAT_STATUS = "Healthy (Live)"
                    _THREAT_LAST_UPDATE = time.time()
        except Exception as e:
            logging.warning(f"Failed to fetch OpenPhish threat feed: {e}. Falling back to cache.")
            if not os.path.exists(THREAT_CACHE_FILE):
                _THREAT_STATUS = "Offline (No Cache)"

    # Load from cache file
    if os.path.exists(THREAT_CACHE_FILE):
        try:
            with open(THREAT_CACHE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line:
                        if "://" in line:
                            parsed = urlparse(line)
                            domain = clean_domain(parsed.netloc or parsed.path.split("/")[0])
                        else:
                            domain = clean_domain(line.split("/")[0])
                        if domain:
                            domains.add(domain)
            _THREAT_COUNT = len(domains)
            if _THREAT_STATUS.startswith("Offline"):
                _THREAT_STATUS = "Warning (Stale Cache)"
            return domains
        except Exception as e:
            logging.error(f"Failed to parse threat feed cache: {e}")

    # Ultimate fallback if no network and no cache
    fallback_threats = [
        "infosys-training-hr.info",
        "wipro-verification-portal.net",
        "tcs-careers-india.com",
        "internshala-verify.click"
    ]
    for d in fallback_threats:
        domains.add(clean_domain(d))
    _THREAT_COUNT = len(domains)
    return domains

def get_threat_domains() -> set:
    global _THREAT_DOMAINS
    if _THREAT_DOMAINS is None:
        _THREAT_DOMAINS = fetch_threat_feed()
    return _THREAT_DOMAINS

def get_threat_stats() -> dict:
    return {
        "status": _THREAT_STATUS,
        "last_update": _THREAT_LAST_UPDATE,
        "count": _THREAT_COUNT
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
    # Require substring matches to be at least 4 characters to prevent tiny words
    # (like "go", "co", "in") from triggering false self-identification trust.
    if dn == sd:
        return True
    if len(sd) >= 4 and sd in dn:
        return True
    if len(dn) >= 4 and dn in sd:
        return True
    return False

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

    # --- AUTHENTICATION ASSESSMENT ---
    spf = headers.get("spf", "").lower()
    dkim = headers.get("dkim", "").lower()
    dmarc = headers.get("dmarc", "").lower()
    arc = headers.get("arc", "none").lower()

    auth_all_pass = (spf == "pass" and dkim == "pass" and dmarc == "pass")
    
    # Valid forwarding (Mailing lists like Google Groups, etc.)
    # Forwarders break SPF (softfail/fail) but DKIM and ARC should pass
    is_valid_forward = (dkim == "pass" and arc == "pass" and spf in ["fail", "softfail", "none"])

    # Direct senders with missing/weak SPF but valid DKIM
    is_dkim_verified_direct = (
        dkim == "pass"
        and dmarc in ("pass", "none")
        and spf in ("softfail", "none", "neutral")
    )
    
    auth_has_failure = False
    if not (auth_all_pass or is_valid_forward or is_dkim_verified_direct):
        # Escalate risk if DKIM fails, or if ARC fails alongside SPF failure
        # A hard SPF fail without ARC remains an auth failure even if DKIM passes
        if "fail" in dkim or ("fail" in spf and "pass" not in arc):
            auth_has_failure = True
        elif "fail" in dmarc:
            auth_has_failure = True

    # Short-circuit: If the email is from a verified legitimate brand (passing SPF, DKIM, and DMARC)
    # we know for a fact it is authentic and should be marked safe immediately.
    is_verified_brand = False
    for brand, legit in LEGITIMATE_DOMAINS.items():
        if is_subdomain_of(sender_domain, legit):
            if auth_all_pass:
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

    # --- SENDER TRUST BASELINE (not a short-circuit, a score modifier) ---
    # Institutional/government TLD patterns that require verified registration
    INSTITUTIONAL_TLD_PATTERNS = (
        ".edu", ".edu.in", ".ac.in", ".ac.uk",
        ".gov", ".gov.in", ".nic.in", ".gov.uk",
        ".mil", ".int", ".ac.", ".edu.", ".gov.",
    )
    is_institutional_tld = any(tld in sender_domain or sender_domain.endswith(tld) for tld in INSTITUTIONAL_TLD_PATTERNS)
    is_self_identified = is_sender_self_identified(display_name, sender_domain)

    # Compute a trust reduction applied AFTER scoring.
    # This shifts the baseline for authenticated-but-unknown senders without
    # creating a blind spot (verified + strong scam signals can still score high).
    #   - auth_all_pass/is_valid_forward alone:      reduce by 15 pts
    #   - is_dkim_verified_direct alone:             reduce by 7 pts
    #   - + institutional TLD:                       reduce by 25 pts (or 17)
    #   - + self-identified sender:                  reduce by 20 pts (or 12)
    #   - + institutional + self-id:                 reduce by 30 pts (or 22)
    # None of these reductions apply if authentication fails completely.
    trust_reduction = 0
    if auth_all_pass or is_valid_forward:
        trust_reduction = 15
        if is_institutional_tld:
            trust_reduction += 10
        if is_self_identified:
            trust_reduction += 5
    elif is_dkim_verified_direct:
        trust_reduction = 7
        if is_institutional_tld:
            trust_reduction += 10
        if is_self_identified:
            trust_reduction += 5

    # Keep track of triggered signals
    signals_sender = []
    signals_links = []
    signals_language = []
    signals_attachment = []

    # Keep track of confidence components
    conf_auth = 0.3
    conf_links = 0.3
    conf_lang = 0.2
    conf_attach = 0.2

    # --- CATEGORY 1: Sender Authenticity ---
    # Signal A: Display Name / Local Part vs Actual Email Mismatch
    for brand, legit in LEGITIMATE_DOMAINS.items():
        if brand in sender_local.lower() or brand in display_name.lower():
            if not is_subdomain_of(sender_domain, legit):
                signals_sender.append("Display Name / Local Part vs. Actual Email Mismatch")
                break

    # Signal B: Domain Mismatch (Claimed Org vs Actual Domain)
    if not is_self_identified:
        for brand, legit in LEGITIMATE_DOMAINS.items():
            if re.search(r'\b' + re.escape(brand) + r'\b', subject.lower()):
                if not is_subdomain_of(sender_domain, legit):
                    signals_sender.append("Domain Mismatch (Claimed Org vs. Actual Domain)")
                    break

    # Signal C: Failed Authentication
    if auth_has_failure:
        signals_sender.append("Failed Authentication (SPF/DKIM/DMARC)")

    # Signal D: Lookalike Sender Domain (Typosquatting)
    if check_lookalike(sender_domain):
        signals_sender.append("Lookalike Sender Domain (Typosquatting)")

    # --- CATEGORY 2: Link Analysis ---
    # Signal A: Display Text vs URL Destination Mismatch
    body_mentions_brand_domain = False
    for brand, legit in LEGITIMATE_DOMAINS.items():
        if legit in body_text.lower():
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
            conf_links = 0.0
            break

    # Signal C: Lookalike Domains and Live Threat Feeds
    for link in links:
        try:
            parsed = urlparse(link)
            link_domain = clean_domain(parsed.netloc or parsed.path.split("/")[0])
            
            if link_domain in get_threat_domains():
                signals_links.append("Known Malicious Domain (Threat Database)")
                break
                
            if check_lookalike(link_domain):
                signals_links.append("Lookalike Domain (Typosquatting)")
                break
        except Exception:
            pass

    # --- CATEGORY 3: Language and Psychological Pressure ---
    combined_text = (subject + " " + body_text).lower()

    # Signal A: Urgency and Threats
    # TIGHTENED: Removed overly generic words ("deadline", "work from home",
    # "offer letter attached") that fire on legitimate institutional/college emails.
    has_urgency = any(re.search(r'\b' + re.escape(kw) + r'\b', combined_text) for kw in URGENCY_KEYWORDS)
    if has_urgency:
        signals_language.append("Urgency and Threats")

    # Signal B: Requests for Credentials or Payment
    # TIGHTENED: Split into strong and weak signals.
    # Strong signals always trigger. Weak signals require corroboration.
    has_credential_strong = (
        any(re.search(r'\b' + re.escape(kw) + r'\b', combined_text) for kw in CREDENTIAL_KEYWORDS_STRONG)
        or any(re.search(pat, combined_text) for pat in CREDENTIAL_PATTERNS)
    )

    # Weak credential signals: only trigger if accompanied by another risk factor
    has_credential_weak = any(re.search(r'\b' + re.escape(kw) + r'\b', combined_text) for kw in CREDENTIAL_KEYWORDS_WEAK)
    weak_corroborated = has_credential_weak and (
        auth_has_failure or has_shortener or bool(signals_sender) or bool(signals_links)
    )

    if has_credential_strong or weak_corroborated:
        signals_language.append("Requests for Credentials or Payment")

    # Signal C: Too-Good-To-Be-True Offers
    if any(re.search(r'\b' + re.escape(kw) + r'\b', combined_text) for kw in OFFER_KEYWORDS):
        signals_language.append("Too-Good-To-Be-True Offers")

    # --- CATEGORY 4: Attachment and Content Risk ---
    has_attachment_signal = any(kw in body_text.lower() for kw in ATTACHMENT_KEYWORDS) or \
                            any(re.search(pat, body_text.lower()) for pat in ATTACHMENT_PATTERNS)
    if has_attachment_signal:
        signals_attachment.append("Unexpected Attachments")

    link_match = any(any(re.search(ext, link.lower()) for ext in DANGEROUS_EXTENSIONS) for link in links)
    body_match = any(re.search(ext, body_text.lower()) for ext in DANGEROUS_EXTENSIONS)
    if link_match or body_match:
        signals_attachment.append("Dangerous File Extensions")

    if any(kw in body_text.lower() for kw in MACRO_KEYWORDS):
        signals_attachment.append("Request to Enable Macros")

    # --- CALCULATE CATEGORY SCORES ---
    score_sender = min(25 + (len(signals_sender) - 1) * 10, 30) if signals_sender else 0
    score_links = min(25 + (len(signals_links) - 1) * 10, 30) if signals_links else 0
    score_language = min(15 + (len(signals_language) - 1) * 12, 27) if signals_language else 0
    score_attachment = min(15 + (len(signals_attachment) - 1) * 5, 20) if signals_attachment else 0

    total_score = min(score_sender + score_links + score_language + score_attachment, 100)

    # --- APPLY SENDER TRUST BASELINE REDUCTION ---
    # Reduce score for authenticated senders. This rewards passing SPF/DKIM/DMARC
    # and institutional TLDs, but does NOT zero-out the score.
    # The reduction is NOT applied if:
    #   - the sender has impersonation signals (lookalike, brand mismatch, failed auth)
    #   - multiple language signals fired (co-occurring urgency + credential request
    #     indicates genuinely suspicious content regardless of authentication)
    if trust_reduction > 0 and not signals_sender and len(signals_language) <= 1:
        total_score = max(0, total_score - trust_reduction)

    # --- DETERMINING CATEGORY BAND ---
    is_scam_offer = "Too-Good-To-Be-True Offers" in signals_language
    has_impersonation = bool(signals_sender or signals_links)

    # Force a minimum threshold if we detect a classic scam offer to avoid categorizing it as safe.
    if is_scam_offer:
        total_score = max(total_score, 35)

    if total_score <= 20:
        category = "safe"
    elif total_score <= 50:
        category = "scam" if is_scam_offer else "spam"
    else:
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
    """Run scoring on mock data, followed by false-positive regression tests."""
    # Resolve relative paths from project root to allow execution from any working directory
    agent_dir = Path(__file__).resolve().parent
    project_root = agent_dir.parent
    mock_data_path = project_root / "mock-data" / "sample-emails.json"
    results_path = project_root / "results-demo.json"

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
            print(f"Skipping malformed entry: {e}")

    try:
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"\nAll results saved to {results_path} successfully.")
    except Exception as e:
        print(f"Error saving results: {e}")

    # --- FALSE-POSITIVE REGRESSION TESTS ---
    print("\n" + "=" * 60)
    print("FALSE-POSITIVE REGRESSION TESTS")
    print("=" * 60)

    test_cases = [
        # --- Tests that MUST score LOW / SAFE ---
        {
            "name": "College .ac.in event email with deadline",
            "email": {
                "id": "fp-test-college-event",
                "sender": "Events Cell <events@iitb.ac.in>",
                "subject": "TechFest 2026 Registration Deadline Extended",
                "body_text": "Dear students, the registration deadline for TechFest 2026 has been extended to July 15th. Join us for workshops, competitions, and keynote talks. Register at our portal.",
                "links": ["https://techfest.iitb.ac.in/register"],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
            "expect_safe": True,
        },
        {
            "name": "Government .gov.in routine update",
            "email": {
                "id": "fp-test-gov-update",
                "sender": "NPTEL <no-reply@nptel.gov.in>",
                "subject": "Course Registration Update",
                "body_text": "Your course registration for the July 2026 semester is confirmed. Complete remaining steps before the closing date. Visit the NPTEL portal for details.",
                "links": ["https://nptel.gov.in/courses"],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
            "expect_safe": True,
        },
        {
            "name": "Small org (not whitelisted) with legit event",
            "email": {
                "id": "fp-test-small-org-event",
                "sender": "Devfolio <hello@devfolio.co>",
                "subject": "Hackathon Registration Now Open",
                "body_text": "We are excited to announce HackWithIndia 2026! Registration is now open. Build, learn, and win prizes. Submit your project before the closing date.",
                "links": ["https://devfolio.co/hackwithindia"],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
            "expect_safe": True,
        },
        {
            "name": "University professor with passing auth",
            "email": {
                "id": "fp-test-professor",
                "sender": "Professor <prof@state-university.edu>",
                "subject": "Project Extension Approved",
                "body_text": "Your extension request is approved. Submissions close next week.",
                "links": [],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
            "expect_safe": True,
        },
        {
            "name": "Fictional university mailing list (SPF softfail, ARC pass)",
            "email": {
                "id": "fp-test-mailing-list",
                "sender": "Student Council <announcements@fictional-uni.edu>",
                "subject": "Mandatory Registration Event",
                "body_text": "Please note the upcoming registration event for all students. Update your details before the deadline.",
                "links": ["https://fictional-uni.edu/register"],
                "headers": {"spf": "softfail", "dkim": "pass", "dmarc": "none", "arc": "pass"},
            },
            "expect_safe": True,
        },
        {
            "name": "Fictional government agency update",
            "email": {
                "id": "fp-test-fic-gov",
                "sender": "Department of Transport <info@transport-dept.gov.in>",
                "subject": "License Renewal Update",
                "body_text": "Your application is under review. Visit the portal for the latest update.",
                "links": ["https://transport-dept.gov.in/status"],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "arc": "none"},
            },
            "expect_safe": True,
        },
        {
            "name": "Self-identified small business event",
            "email": {
                "id": "fp-test-fic-biz",
                "sender": "CloudConf <hello@cloudconf.com>",
                "subject": "Join now for CloudConf 2026",
                "body_text": "Registration is open! Join us for the biggest cloud event of the year.",
                "links": ["https://cloudconf.com/register"],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "arc": "none"},
            },
            "expect_safe": True,
        },
        {
            "name": "Direct sender weak SPF with valid DKIM",
            "email": {
                "id": "fp-test-dkim-direct",
                "sender": "Local Org <info@local-community-org.org>",
                "subject": "Community Meeting Update",
                "body_text": "Please join us for the community meeting on Friday.",
                "links": [],
                "headers": {"spf": "softfail", "dkim": "pass", "dmarc": "none", "arc": "none"},
            },
            "expect_safe": True,
        },
        # --- Tests that MUST score HIGH / PHISHING/SCAM ---
        {
            "name": "Spoofed email with no signing (genuine spoof)",
            "email": {
                "id": "tp-test-no-signing",
                "sender": "IT Helpdesk <admin@your-company.com>",
                "subject": "Action Required: Update your login",
                "body_text": "Your account is compromised. Please verify your identity immediately.",
                "links": [],
                "headers": {"spf": "fail", "dkim": "none", "dmarc": "fail", "arc": "none"},
            },
            "expect_safe": False,
        },
        {
            "name": "Borderline hard SPF fail with valid DKIM",
            "email": {
                "id": "tp-test-dkim-spf-hardfail",
                "sender": "Security <alerts@secure-platform.net>",
                "subject": "Suspicious login attempt",
                "body_text": "We detected an unauthorized login. Action required immediately to lock your account.",
                "links": [],
                "headers": {"spf": "fail", "dkim": "pass", "dmarc": "none", "arc": "none"},
            },
            "expect_safe": False,
        },
        {
            "name": "Spoofed Netflix billing phishing",
            "email": {
                "id": "tp-test-netflix-phish",
                "sender": "Netflix Alert <billing-update@customer-netfl1x-support.com>",
                "subject": "Your Netflix membership is about to be suspended",
                "body_text": "Please update your credentials immediately at http://bit.ly/netflix-suspend",
                "links": ["http://bit.ly/netflix-suspend"],
                "headers": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            },
            "expect_safe": False,
        },
        {
            "name": "Lottery scam with bank detail request",
            "email": {
                "id": "tp-test-lottery-scam",
                "sender": "Lottery Office <claims@freelotto-rewards.net>",
                "subject": "Congratulations! You won the $50,000 sweepstakes prize",
                "body_text": "Verify your identity and bank details to claim your free reward.",
                "links": [],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
            "expect_safe": False,
        },
        {
            "name": "Fake Infosys HR training fee scam",
            "email": {
                "id": "tp-test-infosys-hr-scam",
                "sender": "Infosys HR <careers@infosys-training-hr.info>",
                "subject": "Infosys Immediate Joining - Training Fee Required",
                "body_text": "Congratulations on your selection. Please pay the training fee of Rs 15,000 as a refundable deposit to confirm your joining.",
                "links": ["https://infosys-training-hr.info/pay"],
                "headers": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            },
            "expect_safe": False,
        },
        {
            "name": "BEC: Authenticated sender with strong scam signals",
            "email": {
                "id": "tp-test-bec-check",
                "sender": "Admin <admin@legit-company.com>",
                "subject": "Urgent: Wire Transfer Required Immediately",
                "body_text": "This is urgent. Please verify your identity and send the security deposit immediately. Your account will be locked within 24 hours.",
                "links": [],
                "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
            "expect_safe": False,
        },
    ]

    passed = 0
    failed = 0
    for tc in test_cases:
        res = score_email(tc["email"])
        is_safe = (res["category"] == "safe")
        ok = (is_safe == tc["expect_safe"])
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        expect_label = "safe" if tc["expect_safe"] else "risky"
        print(f"  [{status}] {tc['name']}: score={res['score']} cat={res['category']} (expected {expect_label})")

    print(f"\nRegression: {passed} passed, {failed} failed out of {len(test_cases)} tests.")
    if failed > 0:
        print("WARNING: Some regression tests failed!")
    print("=" * 60)

if __name__ == "__main__":
    main()

