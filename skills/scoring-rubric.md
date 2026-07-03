# Phishing Risk Scoring Rubric

This document explains how the signals defined in [phishing-heuristics.md](file:///c:/Users/umesh%20chandra/capstone-Agent/skills/phishing-heuristics.md) are combined to produce a single risk score (0-100) and a data completeness confidence value (0.0–1.0).

---

## 1. Weighted Scoring Approach

The overall risk score is calculated by summing the scores of four categories. Each category has a maximum point cap to ensure that a single category triggering multiple signals does not disproportionately skew the score compared to an email showing diverse, high-risk behaviors across multiple categories.

| Category | Max Points (Weight) |
| :--- | :---: |
| **Sender Authenticity** | 30 points |
| **Link Analysis** | 30 points |
| **Language and Psychological Pressure** | 20 points |
| **Attachment and Content Risk** | 20 points |
| **Total Maximum Score** | **100 points** |

### How Signals Combine (Category Capping)

To prevent minor or repetitive triggers from inflating the score, points are awarded non-linearly within each category. The first triggered signal carries the highest weight, and subsequent signals add diminishing points up to the category cap.

#### A. Sender Authenticity (Max 30 pts)
*   **First signal triggered:** 20 points
*   **Each additional signal:** +10 points
*   *Example:* If Display Name Mismatch and Failed DMARC both trigger: `20 + 10 = 30 points`.

#### B. Link Analysis (Max 30 pts)
*   **First signal triggered:** 20 points
*   **Each additional signal:** +10 points
*   *Example:* If Lookalike Domain and Use of URL Shorteners both trigger: `20 + 10 = 30 points`.

#### C. Language and Psychological Pressure (Max 20 pts)
*   **First signal triggered:** 12 points
*   **Each additional signal:** +8 points
*   *Example:* If both Urgency and Requests for Credentials trigger: `12 + 8 = 20 points`.

#### D. Attachment and Content Risk (Max 20 pts)
*   **First signal triggered:** 15 points
*   **Each additional signal:** +5 points
*   *Example:* If unexpected attachment is found: `15 points`. If it also has an executable file extension: `15 + 5 = 20 points`.

---

## 2. Score Band Definitions

Once the cumulative score is calculated, the email is classified into one of the following four risk bands:

| Score Range | Risk Band | Description | Recommended Action |
| :---: | :--- | :--- | :--- |
| **0 - 20** | **Safe** | The email is highly likely to be legitimate. No major red flags were detected. | Deliver to inbox normally. |
| **21 - 50** | **Low Risk / Spam** | The email has minor anomalies or generic spam-like characteristics, but lacks targeted phishing markers. | Mark as spam or deliver to Junk folder. |
| **51 - 80** | **Likely Phishing** | Multiple dangerous indicators (like sender mismatches or deceptive links) suggest an active phishing attempt. | Flag with a warning banner or move to quarantine. |
| **81 - 100** | **High-Confidence Phishing** | High-severity signals triggered across multiple categories. Almost certainly malicious fraud. | Block delivery and alert the security operations team. |

---

## 3. Confidence Score Calculation (0.0 to 1.0)

The **Confidence Score** represents how complete and reliable the input data was for the analysis. It is separate from the risk score: an email can be highly suspicious but have a low confidence score if key technical checks could not be completed.

Confidence is calculated by summing the weights of successfully executed analysis checks:

| Analysis Check | Weight | Description |
| :--- | :---: | :--- |
| **Authentication Check** | `0.3` | Successfully retrieved and parsed SPF, DKIM, and DMARC headers. |
| **Link Resolution Check** | `0.3` | Extracted links and resolved redirect chains (e.g., expanded short URLs). |
| **Language/Semantic Parsing** | `0.2` | Successfully parsed the text body and extracted intent/tone. |
| **Attachment Inspection** | `0.2` | Successfully scanned attachments (or verified the email has 0 attachments). |
| **Total Max Confidence** | **`1.0`** | All analyses ran successfully with complete data. |

*If a check cannot be executed (e.g., network failure during link expansion or headers were stripped by a forwarding server), its weight is excluded from the final confidence sum.*

---

## 4. Worked Example

### Scenario
An analyst agent processes an email claiming to be from "DocuSign Security".
*   The email is sent from `docusign@verification-portal.net` (fails SPF/DKIM validation).
*   The email body contains a button labeled "Review Document" linking to a shortened URL `https://bit.ly/3xYz7A`.
*   The message warns: "You must review and sign this urgent document within 12 hours or your account access will be terminated."
*   There are no attachments.
*   **Technical issue:** The link resolver tool failed to connect to the internet to expand the shortened URL.

### 1. Risk Score Calculation
*   **Sender Authenticity:**
    *   *Triggered:* Failed Authentication (SPF/DKIM fail) $\rightarrow$ **20 points**
*   **Link Analysis:**
    *   *Triggered:* Use of URL Shorteners $\rightarrow$ **20 points**
*   **Language and Psychological Pressure:**
    *   *Triggered:* Urgency and Threats, Requests for Credentials $\rightarrow$ `12 + 8` = **20 points**
*   **Attachment and Content Risk:**
    *   *Triggered:* None $\rightarrow$ **0 points**

**Total Cumulative Risk Score:** $20 + 20 + 20 + 0 = 60$

### 2. Confidence Calculation
*   **Authentication Check:** Successful $\rightarrow$ **0.3**
*   **Link Resolution Check:** Failed (Short URL could not be expanded due to connection failure) $\rightarrow$ **0.0**
*   **Language/Semantic Parsing:** Successful $\rightarrow$ **0.2**
*   **Attachment Inspection:** Successful (Confirmed 0 attachments) $\rightarrow$ **0.2**

**Total Confidence Score:** $0.3 + 0.0 + 0.2 + 0.2 = 0.7$

### 3. Final Assessment Output
*   **Risk Score:** `60`
*   **Risk Band:** `Likely Phishing` (Score is between 51 and 80)
*   **Confidence:** `0.7` (High completeness, with some link resolution details missing)
