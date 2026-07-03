# Phishing and Fraud Heuristics Checklist

This reference checklist documents the key phishing and fraud red flags that an email-analysis agent should check for. It is organized into four main categories, each containing concrete signals and examples.

---

## 1. Sender Authenticity

These signals evaluate whether the sender is who they claim to be or if they are spoofing a trusted identity.

*   **Display Name vs. Actual Email Mismatch**
    *   *Description:* The sender's display name shows a well-known organization or person, but the actual email address in the `From` header belongs to an unrelated external domain.
    *   *Example:* Display Name: `Netflix Support` | Email Address: `support@customer-verification-portal-982.com`
*   **Domain Mismatch (Claimed Org vs. Actual Domain)**
    *   *Description:* The email body or signature claims to represent a specific brand, but the sender domain is unrelated.
    *   *Example:* The email claims to be from `Google Security Team`, but the email is sent from `security-notice@gmail-alert-system.org` instead of `@google.com`.
*   **Failed Authentication (SPF / DKIM / DMARC)**
    *   *Description:* The sending server fails key email validation standards, indicating that the sender address may have been spoofed.
    *   *Example:* A `dmarc=fail` or `spf=fail` status in the email header check for a message claiming to be from `paypal.com`.

---

## 2. Link Analysis

These signals inspect hyperlinks within the email body to identify deceptive redirect behavior or suspicious destinations.

*   **Display Text vs. URL Destination Mismatch**
    *   *Description:* The text shown to the user (anchor text) displays a legitimate, trusted website, but the underlying hyperlink (`href` attribute) points to a completely different, unassociated address.
    *   *Example:* The email shows [www.chase.com](http://www.chase-login-verify-account.com) but the actual link destination points to `http://www.chase-login-verify-account.com`.
*   **Use of URL Shorteners**
    *   *Description:* The email uses link-shortening services to hide the final destination of a URL, preventing immediate detection by the user.
    *   *Example:* The email prompts the user to click a button pointing to `https://bit.ly/3xYz7A` to "verify their identity."
*   **Lookalike Domains (Typosquatting)**
    *   *Description:* The destination URL uses subtle misspellings, homoglyphs (lookalike characters from different alphabets), or extra subdomains to mimic a trusted brand.
    *   *Example:* A link pointing to `http://www.micros0ft.com` (using a zero instead of the letter 'o') or `http://www.amazon.pay-support.com`.

---

## 3. Language and Psychological Pressure

These signals analyze the semantic content and emotional triggers used in the email to manipulate the recipient into acting quickly without thinking.

*   **Urgency and Threats**
    *   *Description:* The email creates a false sense of urgency, warning of negative consequences (such as account suspension, legal action, or financial loss) if immediate action is not taken.
    *   *Example:* "Your bank account will be suspended within 24 hours unless you log in and verify your details immediately."
*   **Requests for Credentials or Payment**
    *   *Description:* The email asks the user to provide sensitive information (passwords, PINs, social security numbers) or initiate an unexpected financial transaction (wire transfer, gift card purchase).
    *   *Example:* "We need to verify your credentials. Please click here to enter your current password and update your security questions."
*   **Too-Good-To-Be-True Offers**
    *   *Description:* The email promises unsolicited financial gain, free gifts, lottery wins, or exclusive job offers with high pay and little effort.
    *   *Example:* "Congratulations! You have been selected as the winner of our $1,000,000 summer sweepstakes. Click here to claim your cash prize."

---

## 4. Attachment and Content Risk

These signals evaluate the risk level of attachments or specific embedded media within the email body.

*   **Unexpected or Out-of-Context Attachments**
    *   *Description:* The email contains an attachment that the recipient did not request or expect, often disguised as an invoice, receipt, or shipping document.
    *   *Example:* An email from an unknown sender with the subject "Overdue Invoice #89283" containing an attached PDF or ZIP file.
*   **Dangerous or Executable File Extensions**
    *   *Description:* The attachment is an executable program, script, or system file that can run code on the recipient's computer if opened.
    *   *Example:* An attached file named `shipping_document.pdf.exe` or `refund_form.js`.
*   **Requests to Enable Macros**
    *   *Description:* The email contains a document (such as a Word or Excel file) that instructs the user to enable macros or content upon opening, which can trigger malicious scripts.
    *   *Example:* An attached spreadsheet displaying a blurry image with a message saying: "This document is encrypted. Click 'Enable Editing' and then 'Enable Content' to decrypt and view."
