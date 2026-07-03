# Email Scorer Performance Evaluation Report

This report evaluates the scoring agent's accuracy and performance on a combined dataset of mock student emails and real-world phishing samples.

## Binary Classification Metrics
- **Positive Class**: Phishing or Scam (High risk)
- **Negative Class**: Safe or Spam (Low risk / Benign)

| Metric | Value | Details |
| :--- | :--- | :--- |
| **Total Emails Evaluated** | 37 | Combined mock-data datasets |
| **True Positives (TP)** | 24 | Phishing/scam correctly flagged |
| **True Negatives (TN)** | 10 | Safe/spam correctly identified as low risk |
| **False Positives (FP)** | 0 | Benign emails incorrectly flagged as phishing/scam |
| **False Negatives (FN)** | 3 | Phishing/scam missed by the filter |
| **Accuracy** | 91.89% | (34/37) |
| **Precision** | 100.00% | (24/24) |
| **Recall** | 88.89% | (24/27) |
| **F1 Score** | 94.12% | Harmonic mean of precision & recall |

## Detailed Category Breakdown
This table shows how individual ground truth categories were classified by the scorer.

| Ground Truth \ Predicted | Phishing | Scam | Spam | Safe |
| :--- | :---: | :---: | :---: | :---: |
| **phishing** | 20 | 2 | 0 | 0 |
| **borderline_phishing** | 2 | 0 | 3 | 0 |
| **safe** | 0 | 0 | 0 | 10 |

## Performance Interpretation

**Strengths**: The scorer performs well at:
- correctly identifying unambiguous phishing attempts (TP = 24), successfully catching emails with clear threat signals (lookalike domains, SPF/DKIM/DMARC failures, and high-urgency language combined with credential requests).
- correctly classifying legitimate university communications as safe (TN = 10), ensuring standard institutional mail is ignored by the filter.
- avoiding false alarms entirely (FP = 0), which guarantees that safe emails do not trigger warnings for users.

**Weaknesses**: The scorer struggles with:
- detecting borderline or sophisticated phishing emails (FN = 3). These emails often lack obvious triggers: they might pass SPF or DKIM checks, omit overt urgency keywords, or avoid malicious links entirely, relying instead on pure text manipulation or attachments that fail to accumulate enough threat points to trigger a high-risk classification.

## Incorrectly Classified Examples

### Example 1: False Negative
- **Email ID**: `border-011`
- **Sender**: `scholarships@educate-future-foundation.org`
- **Subject**: "Reminder: Deadline for the Educate Future Grant is approaching"
- **Ground Truth**: `borderline_phishing`
- **Predicted Category**: `spam` (Score: 25/100)
- **Explanation**: *Risk signals detected: Failed Authentication (SPF/DKIM/DMARC).*

**Analysis of Failure Cause**:
This email was an attack (`borderline_phishing`) but was classified as benign (`spam`). This occurred because the email's score (between 21 and 50) was not high enough to cross the high-risk threshold (50) for a phishing classification, and it did not contain a too-good-to-be-true offer to be classified as a scam. This led it to be categorized as spam (which is treated as benign/negative for this evaluation).
Specifically:
- The email has failing authentication headers which triggered the scorer's authenticity penalties.
- It did not contain lookalike domain links, so it missed lookalike-based flags.
- The email body content: *"This is a reminder that the application deadline for our yearly academic grant is tomorrow. Apply now to secure funding. Note: please make sure to use..."* relies on subtle context that the rule-based scanner does not recognize as high risk.

### Example 2: False Negative
- **Email ID**: `border-013`
- **Sender**: `careers-notice@linkedin-student-recruiting.com`
- **Subject**: "You have 3 new matching internship suggestions"
- **Ground Truth**: `borderline_phishing`
- **Predicted Category**: `spam` (Score: 50/100)
- **Explanation**: *Risk signals detected: Failed Authentication (SPF/DKIM/DMARC), Lookalike Domain (Typosquatting).*

**Analysis of Failure Cause**:
This email was an attack (`borderline_phishing`) but was classified as benign (`spam`). This occurred because the email's score (between 21 and 50) was not high enough to cross the high-risk threshold (50) for a phishing classification, and it did not contain a too-good-to-be-true offer to be classified as a scam. This led it to be categorized as spam (which is treated as benign/negative for this evaluation).
Specifically:
- The email has failing authentication headers which triggered the scorer's authenticity penalties.
- It contained lookalike domain links, which triggered domain flags.
- It triggered a Display Name/Domain mismatch because it referenced a brand in the sender local part but used a different sender domain.
- The email body content: *"Based on your student profile, recruiters from tech companies have matched with you. Check out these positions and apply through our portal link...."* relies on subtle context that the rule-based scanner does not recognize as high risk.

