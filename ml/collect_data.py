"""
ml/collect_data.py
------------------
Dataset collection script for the email classifier.

Strategy (Option C):
- spam/safe: Real data from SpamAssassin public corpus (direct HTTP)
- phishing: Real data from SpamAssassin + synthetic augmentation
- scam: Synthetic data generated from scoring_agent.py keyword patterns

Every row has an is_synthetic boolean column for full transparency.
"""

import csv
import io
import os
import random
import sys
import tarfile
import urllib.request
import email
from email import policy
from pathlib import Path

# -- Path setup so we can import from agents/ --
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.scoring_agent import (
    URGENCY_KEYWORDS,
    CREDENTIAL_KEYWORDS_STRONG,
    CREDENTIAL_KEYWORDS_WEAK,
    OFFER_KEYWORDS,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
TARGET_PER_CLASS = 750

SPAMASSASSIN_URLS = {
    "spam":     "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
    "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
    "spam_2":   "https://spamassassin.apache.org/old/publiccorpus/20030228_spam_2.tar.bz2",
    "easy_ham_2": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2",
}

NAZARIO_URL = "https://monkey.org/~jose/phishing/phishing0.mbox"

random.seed(42)  # Reproducibility


# ---------------------------------------------------------------------------
# SpamAssassin Download & Parse
# ---------------------------------------------------------------------------

def download_spamassassin(name: str, url: str) -> Path:
    """Download a SpamAssassin tar.bz2 archive. Returns path to saved file."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest = RAW_DIR / f"{name}.tar.bz2"
    if dest.exists():
        print(f"  [cached] {dest.name}")
        return dest
    print(f"  [downloading] {url}")
    try:
        urllib.request.urlretrieve(url, str(dest))
        print(f"  [saved] {dest.name} ({dest.stat().st_size / 1024:.0f} KB)")
        return dest
    except Exception as e:
        print(f"  [FAILED] {name}: {e}")
        return None


def parse_spamassassin_archive(archive_path: Path) -> list[dict]:
    """Parse emails from a SpamAssassin tar.bz2 archive."""
    emails = []
    try:
        with tarfile.open(str(archive_path), "r:bz2") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                # Skip non-email files (e.g. cmds, README)
                basename = os.path.basename(member.name)
                if basename.startswith(".") or basename in ("cmds", "README"):
                    continue
                try:
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    raw_bytes = f.read()
                    msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

                    # Extract subject
                    subject = ""
                    raw_subject = msg.get("Subject", "")
                    if raw_subject:
                        try:
                            decoded_parts = email.header.decode_header(raw_subject)
                            subject = " ".join(
                                part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else part
                                for part, enc in decoded_parts
                            )
                        except Exception:
                            subject = str(raw_subject)

                    # Extract sender
                    sender = msg.get("From", "")

                    # Extract body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            ct = part.get_content_type()
                            if ct == "text/plain":
                                payload = part.get_payload(decode=True)
                                if payload:
                                    charset = part.get_content_charset() or "utf-8"
                                    body = payload.decode(charset, errors="replace")
                                    break
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            charset = msg.get_content_charset() or "utf-8"
                            body = payload.decode(charset, errors="replace")

                    if body or subject:
                        emails.append({
                            "sender": sender[:200],
                            "subject": subject[:300],
                            "body_text": body[:3000],
                        })
                except Exception:
                    pass
    except Exception as e:
        print(f"  [ERROR] parsing {archive_path.name}: {e}")
    print(f"  [parsed] {archive_path.name.split('.')[0]}: {len(emails)} emails")
    return emails

def download_and_parse_nazario() -> list[dict]:
    """Download and parse Nazario phishing mbox."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest = RAW_DIR / "phishing0.mbox"
    if not dest.exists():
        print(f"  [downloading] {NAZARIO_URL}")
        try:
            req = urllib.request.Request(NAZARIO_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response, open(dest, 'wb') as out_file:
                out_file.write(response.read())
            print(f"  [saved] {dest.name} ({dest.stat().st_size / 1024:.0f} KB)")
        except Exception as e:
            print(f"  [FAILED] Nazario: {e}")
            return []
    
    print("  [parsing] Nazario mbox...")
    import mailbox
    emails = []
    try:
        mbox = mailbox.mbox(str(dest))
        for msg in mbox:
            subject = str(msg.get("Subject", ""))
            sender = str(msg.get("From", ""))
            
            body_text = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body_text = part.get_payload(decode=True)
                        break
            else:
                body_text = msg.get_payload(decode=True)
                
            if isinstance(body_text, bytes):
                body_text = body_text.decode("utf-8", errors="ignore")
                
            if body_text.strip():
                emails.append({
                    "email_id": f"nazario-{len(emails):04d}",
                    "sender": sender[:100],
                    "subject": subject[:150],
                    "body_text": body_text[:2000],
                    "links": "",
                    "label": "phishing",
                    "is_synthetic": False,
                })
    except Exception as e:
        print(f"  [ERROR] parsing Nazario: {e}")
    
    print(f"  [parsed] Nazario: {len(emails)} emails")
    return emails

# ---------------------------------------------------------------------------
# Synthetic Data Generation
# ---------------------------------------------------------------------------

PHISHING_TEMPLATES = [
    {
        "sender": "Security Team <security@{domain}>",
        "subject": "Urgent: Your account has been {action}",
        "body": "We detected {event} on your account. Please {request} immediately to avoid {consequence}. Click here: {link}",
    },
    {
        "sender": "IT Support <support@{domain}>",
        "subject": "Action Required: {action} your credentials",
        "body": "Your password will expire {timeframe}. You must {request} to maintain access. Verify at: {link}",
    },
    {
        "sender": "Admin <admin@{domain}>",
        "subject": "Suspicious login detected on your account",
        "body": "An unauthorized login was detected from {location}. If this wasn't you, {request} now: {link}",
    },
    {
        "sender": "Help Desk <helpdesk@{domain}>",
        "subject": "Your account will be {action} within 24 hours",
        "body": "Due to {reason}, your account is scheduled for {action}. To prevent this, {request}: {link}",
    },
    {
        "sender": "Billing <billing@{domain}>",
        "subject": "Payment failed - update your billing details",
        "body": "Your recent payment of {amount} failed. Update your payment details immediately to avoid {consequence}: {link}",
    },
]

SCAM_TEMPLATES = [
    {
        "sender": "Prize Office <claims@{domain}>",
        "subject": "Congratulations! You won {prize} (Ref: {ref_id})",
        "body": "You have been selected as the winner of our {contest}. To claim your {prize}, send your bank details to: {email_addr}. Reference code: {ref_id}",
    },
    {
        "sender": "Lottery Commission <lottery@{domain}>",
        "subject": "You won the {amount} sweepstakes prize",
        "body": "Congratulations! Your email was selected in our lottery. Cash prize of {amount}. Send processing fee of {fee} to claim.",
    },
    {
        "sender": "HR Department <careers@{domain}>",
        "subject": "Job Offer - Immediate Joining with {company}",
        "body": "Congratulations on your selection. Please pay the training fee of {fee} as a refundable deposit to confirm your joining at {company}.",
    },
    {
        "sender": "Grant Office <grants@{domain}>",
        "subject": "Scholarship award notification",
        "body": "You have received a grant of {amount}. To receive this scholarship award, verify your identity and bank account details.",
    },
    {
        "sender": "Investment <invest@{domain}>",
        "subject": "Exclusive offer: {return_pct} returns guaranteed",
        "body": "Risk-free investment opportunity. Guaranteed {return_pct} returns. Free gift card for early investors. Limited time offer.",
    },
]

FAKE_DOMAINS = [
    "secure-verify-now.com", "account-update-center.net", "login-verify.org",
    "mail-security-alert.com", "support-ticket-center.net", "billing-update.org",
    "freelotto-rewards.net", "prize-claims-office.com", "instant-cash-prize.net",
    "career-offer-portal.com", "grant-awards-intl.org", "invest-returns-plus.com",
    "help-desk-portal.net", "secure-banking-update.com", "auth-verification.org",
]

FILL_DATA = {
    "action": ["suspended", "locked", "restricted", "deactivated", "compromised"],
    "event": ["suspicious activity", "unauthorized access", "a security breach", "multiple failed logins"],
    "request": ["verify your identity", "update your login", "change your password", "confirm your credentials"],
    "consequence": ["permanent account loss", "data deletion", "service interruption", "account termination"],
    "link": ["http://bit.ly/verify-now", "https://tinyurl.com/secure-login", "http://is.gd/update-acct"],
    "timeframe": ["within 24 hours", "within 12 hours", "today", "immediately"],
    "location": ["Moscow, Russia", "Lagos, Nigeria", "Unknown IP 185.x.x.x", "Shenzhen, China"],
    "reason": ["security policy update", "suspicious activity", "compliance requirements"],
    "amount": ["$500", "$1,000", "Rs 15,000", "$50,000", "£10,000"],
    "prize": ["$100,000", "a new car", "£50,000", "a luxury vacation"],
    "contest": ["International Email Lottery", "Global Prize Draw", "Annual Sweepstakes"],
    "email_addr": ["claims@lottery-intl.com", "verify@prize-office.net"],
    "fee": ["$50", "Rs 5,000", "$100", "£25"],
    "company": ["TechCorp Global", "DataSync Solutions", "CloudForce Inc"],
    "return_pct": ["500%", "300%", "1000%"],
    "ref_id": [str(random.randint(100000, 999999)) for _ in range(5000)],
}


def generate_synthetic(template_list: list, label: str, count: int) -> list[dict]:
    """Generate synthetic email rows from templates."""
    rows = []
    for i in range(count):
        tmpl = random.choice(template_list)
        domain = random.choice(FAKE_DOMAINS)

        def fill(text):
            result = text.replace("{domain}", domain)
            for key, values in FILL_DATA.items():
                placeholder = "{" + key + "}"
                if placeholder in result:
                    result = result.replace(placeholder, random.choice(values), 1)
            return result

        rows.append({
            "email_id": f"syn-{label}-{i:04d}",
            "sender": fill(tmpl["sender"]),
            "subject": fill(tmpl["subject"]),
            "body_text": fill(tmpl["body"]),
            "links": "",
            "label": label,
            "is_synthetic": True,
        })
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ML DATA COLLECTION")
    print("=" * 60)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    dataset = []
    source_log = {}  # For README generation

    # ----- 1. Download SpamAssassin -----
    print("\n--- Step 1: Downloading SpamAssassin corpus ---")
    spam_emails = []
    safe_emails = []
    download_success = True

    for name, url in SPAMASSASSIN_URLS.items():
        archive = download_spamassassin(name, url)
        if archive is None:
            download_success = False
            continue
        parsed = parse_spamassassin_archive(archive)
        if "spam" in name:
            spam_emails.extend(parsed)
        else:
            safe_emails.extend(parsed)

    # ----- 2. Build spam rows (real from SpamAssassin) -----
    print(f"\n--- Step 2: Building SPAM rows (have {len(spam_emails)} raw) ---")
    random.shuffle(spam_emails)
    spam_rows = []
    for i, em in enumerate(spam_emails[:TARGET_PER_CLASS]):
        spam_rows.append({
            "email_id": f"sa-spam-{i:04d}",
            "sender": em["sender"],
            "subject": em["subject"],
            "body_text": em["body_text"],
            "links": "",
            "label": "spam",
            "is_synthetic": False,
        })
    source_log["spam_real"] = len(spam_rows)
    dataset.extend(spam_rows)

    # ----- 3. Build safe rows (real from SpamAssassin ham) -----
    print(f"\n--- Step 3: Building SAFE rows (have {len(safe_emails)} raw) ---")
    random.shuffle(safe_emails)
    safe_rows = []
    for i, em in enumerate(safe_emails[:TARGET_PER_CLASS]):
        safe_rows.append({
            "email_id": f"sa-safe-{i:04d}",
            "sender": em["sender"],
            "subject": em["subject"],
            "body_text": em["body_text"],
            "links": "",
            "label": "safe",
            "is_synthetic": False,
        })
    source_log["safe_real"] = len(safe_rows)
    dataset.extend(safe_rows)
    source_log["safe_synthetic"] = 0

    # ----- 4. Build phishing rows (Nazario) -----
    print(f"\n--- Step 4: Building PHISHING rows (Nazario) ---")
    nazario_raw = download_and_parse_nazario()
    if len(nazario_raw) > TARGET_PER_CLASS:
        phishing_rows = random.sample(nazario_raw, TARGET_PER_CLASS)
    else:
        phishing_rows = nazario_raw
    dataset.extend(phishing_rows)
    source_log["phishing_real"] = len(phishing_rows)
    source_log["phishing_synthetic"] = 0

    # ----- 5. Build scam rows (synthetic) -----
    print(f"\n--- Step 5: Building SCAM rows (synthetic) ---")
    # Generate 5x more synthetic rows so we have enough after deduplication
    scam_rows = generate_synthetic(SCAM_TEMPLATES, "scam", TARGET_PER_CLASS * 5)
    
    # Deduplicate based on body text
    unique_scam = {r["body_text"]: r for r in scam_rows}.values()
    final_scam = list(unique_scam)[:TARGET_PER_CLASS]
    dataset.extend(final_scam)
    source_log["scam_real"] = 0
    source_log["scam_synthetic"] = len(final_scam)

    # ----- 6. Combine and save -----
    all_rows = dataset
    random.shuffle(all_rows)

    output_path = PROCESSED_DIR / "labeled_emails.csv"
    fieldnames = ["email_id", "sender", "subject", "body_text", "links", "label", "is_synthetic"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n--- DATASET SAVED ---")
    print(f"  Path: {output_path}")
    print(f"  Total rows: {len(all_rows)}")
    for label in ["safe", "spam", "phishing", "scam"]:
        count = len([r for r in all_rows if r["label"] == label])
        real_count = len([r for r in all_rows if r["label"] == label and not r["is_synthetic"]])
        syn_count = count - real_count
        print(f"    {label:10s}: {count:4d} ({real_count} real, {syn_count} synthetic)")

    # ----- 7. Generate data README -----
    _write_data_readme(source_log, len(all_rows))

    print(f"\n{'=' * 60}")
    return output_path


def _write_data_readme(source_log: dict, total: int):
    """Generate ml/data/README.md documenting data provenance."""
    readme_path = DATA_DIR / "README.md"
    from datetime import datetime
    date_str = datetime.now().strftime("%Y-%m-%d")

    content = f"""# ML Training Data — Provenance Documentation

## Collection Date
{date_str}

## Sources

### SpamAssassin Public Corpus (Real Data)
- **URL:** https://spamassassin.apache.org/old/publiccorpus/
- **License:** Apache License 2.0 / Public Domain
- **Archives used:** 20030228_spam.tar.bz2, 20030228_easy_ham.tar.bz2,
  20030228_hard_ham.tar.bz2, 20030228_spam_2.tar.bz2, 20030228_easy_ham_2.tar.bz2
- **Label mapping:** spam → spam, easy_ham/hard_ham → safe

### Nazario Phishing Corpus (Real Data)
- **URL:** https://monkey.org/~jose/phishing/phishing0.mbox
- **Label mapping:** phishing → phishing

### Synthetic Data
- **Generated by:** `ml/collect_data.py` using keyword patterns from
  `agents/scoring_agent.py` (URGENCY_KEYWORDS, CREDENTIAL_KEYWORDS_STRONG,
  OFFER_KEYWORDS, etc.)
- **Used for:** Scam class only
- **Scam templates:** 5 templates with randomized fill values

## Row Counts Per Class

| Class | Real | Synthetic | Total |
|-------|------|-----------|-------|
| safe | {source_log.get('safe_real', 0)} | {source_log.get('safe_synthetic', 0)} | {source_log.get('safe_real', 0) + source_log.get('safe_synthetic', 0)} |
| spam | {source_log.get('spam_real', 0)} | {source_log.get('spam_synthetic', 0)} | {source_log.get('spam_real', 0) + source_log.get('spam_synthetic', 0)} |
| phishing | {source_log.get('phishing_real', 0)} | {source_log.get('phishing_synthetic', 0)} | {source_log.get('phishing_real', 0) + source_log.get('phishing_synthetic', 0)} |
| scam | {source_log.get('scam_real', 0)} | {source_log.get('scam_synthetic', 0)} | {source_log.get('scam_real', 0) + source_log.get('scam_synthetic', 0)} |
| **Total** | | | **{total}** |

## Transparency

Every row in `processed/labeled_emails.csv` has an `is_synthetic` boolean
column. The evaluation report (`ml/eval/model_eval_report.md`) breaks
metrics by real vs synthetic rows.

## Label Mapping Decisions

- SpamAssassin `spam` → `spam` (commercial unsolicited bulk email)
- SpamAssassin `easy_ham` / `hard_ham` → `safe` (legitimate email)
- Synthetic phishing → `phishing` (credential theft, account takeover)
- Synthetic scam → `scam` (419/lottery fraud, fake job offers, investment scams)
"""
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [wrote] {readme_path}")


if __name__ == "__main__":
    main()
