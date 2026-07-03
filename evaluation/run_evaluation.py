import json
import os
import sys

# Add project root to path to allow importing agents
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.scoring_agent import score_email

def inject_ground_truth():
    sample_path = os.path.join("mock-data", "sample-emails.json")
    real_path = os.path.join("mock-data", "real-phishing-samples.json")
    
    modified = False
    
    if os.path.exists(sample_path):
        try:
            with open(sample_path, "r", encoding="utf-8") as f:
                sample_emails = json.load(f)
            
            # Check if ground_truth is already there in all objects
            if any("ground_truth" not in email for email in sample_emails):
                for i, email in enumerate(sample_emails):
                    if i < 10:
                        email["ground_truth"] = "phishing"
                    elif i < 15:
                        email["ground_truth"] = "borderline_phishing"
                    else:
                        email["ground_truth"] = "safe"
                with open(sample_path, "w", encoding="utf-8") as f:
                    json.dump(sample_emails, f, indent=2)
                print("Added ground_truth to mock-data/sample-emails.json on disk.")
                modified = True
        except Exception as e:
            print(f"Error updating sample-emails.json: {e}")
            
    if os.path.exists(real_path):
        try:
            with open(real_path, "r", encoding="utf-8") as f:
                real_emails = json.load(f)
            
            if any("ground_truth" not in email for email in real_emails):
                for email in real_emails:
                    email["ground_truth"] = "phishing"
                with open(real_path, "w", encoding="utf-8") as f:
                    json.dump(real_emails, f, indent=2)
                print("Added ground_truth to mock-data/real-phishing-samples.json on disk.")
                modified = True
        except Exception as e:
            print(f"Error updating real-phishing-samples.json: {e}")
            
    return modified

def main():
    # 1. Inject ground truth on disk if needed
    inject_ground_truth()
    
    # 2. Load the datasets
    sample_path = os.path.join("mock-data", "sample-emails.json")
    real_path = os.path.join("mock-data", "real-phishing-samples.json")
    
    all_emails = []
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            all_emails.extend(json.load(f))
            
    if os.path.exists(real_path):
        with open(real_path, "r", encoding="utf-8") as f:
            all_emails.extend(json.load(f))
            
    if not all_emails:
        print("Error: No email data loaded. Ensure mock-data files exist.")
        return

    # 3. Evaluate each email
    tp, fp, fn, tn = 0, 0, 0, 0
    incorrect_predictions = []
    
    # Category breakdown (confusion matrix)
    # Rows: Ground Truth, Cols: Predicted
    # Ground truth classes: "phishing", "borderline_phishing", "safe"
    # Predicted classes: "phishing", "scam", "spam", "safe"
    gt_categories = ["phishing", "borderline_phishing", "safe"]
    pred_categories = ["phishing", "scam", "spam", "safe"]
    
    breakdown = {gt: {pred: 0 for pred in pred_categories} for gt in gt_categories}
    
    print(f"Evaluating {len(all_emails)} emails...")
    
    for email in all_emails:
        gt = email.get("ground_truth")
        if not gt:
            # Fallback if not injected/loaded properly
            continue
            
        try:
            pred_res = score_email(email)
            pred = pred_res["category"]
            
            # Update breakdown
            if gt in breakdown and pred in breakdown[gt]:
                breakdown[gt][pred] += 1
                
            # Determine binary status
            # Positive class: "phishing" or "scam"
            # Negative class: "safe" or "spam"
            gt_is_positive = gt in {"phishing", "borderline_phishing"}
            pred_is_positive = pred in {"phishing", "scam"}
            
            if gt_is_positive and pred_is_positive:
                tp += 1
            elif not gt_is_positive and pred_is_positive:
                fp += 1
                incorrect_predictions.append({
                    "email": email,
                    "prediction": pred_res,
                    "type": "False Positive"
                })
            elif gt_is_positive and not pred_is_positive:
                fn += 1
                incorrect_predictions.append({
                    "email": email,
                    "prediction": pred_res,
                    "type": "False Negative"
                })
            else:
                tn += 1
                
        except Exception as e:
            print(f"Error scoring email ID {email.get('id', 'unknown')}: {e}")

    # 4. Compute metrics
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    # 5. Print results table to console
    print("\n" + "="*50)
    print(" EVALUATION RESULTS: BINARY CLASSIFICATION")
    print(" (Positive = phishing/scam, Negative = safe/spam)")
    print("="*50)
    print(f"Total Emails:   {total}")
    print(f"True Positives: {tp}")
    print(f"True Negatives: {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print("-"*50)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
    print("="*50)
    
    print("\n" + "="*50)
    print(" CATEGORY BREAKDOWN (CONFUSION MATRIX)")
    print(" Rows = Ground Truth, Cols = Predicted Category")
    print("="*50)
    # Header row
    print(f"{'Ground Truth \\ Pred':<22} | {'phishing':<8} | {'scam':<6} | {'spam':<6} | {'safe':<6}")
    print("-"*50)
    for gt in gt_categories:
        row_str = f"{gt:<22} | "
        row_str += " | ".join(f"{breakdown[gt][pred]:<8}" if pred == "phishing" else 
                             f"{breakdown[gt][pred]:<6}" for pred in pred_categories)
        print(row_str)
    print("="*50)

    # 6. Generate written report to evaluation/metrics_report.md
    os.makedirs("evaluation", exist_ok=True)
    report_path = os.path.join("evaluation", "metrics_report.md")
    
    # Analyze where the scorer does well and where it struggles
    # (Typically look at False Negatives and False Positives)
    # We will format this section nicely.
    
    # Write report content
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Email Scorer Performance Evaluation Report\n\n")
        f.write("This report evaluates the scoring agent's accuracy and performance on a combined dataset of mock student emails and real-world phishing samples.\n\n")
        
        f.write("## Binary Classification Metrics\n")
        f.write("- **Positive Class**: Phishing or Scam (High risk)\n")
        f.write("- **Negative Class**: Safe or Spam (Low risk / Benign)\n\n")
        
        f.write("| Metric | Value | Details |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write(f"| **Total Emails Evaluated** | {total} | Combined mock-data datasets |\n")
        f.write(f"| **True Positives (TP)** | {tp} | Phishing/scam correctly flagged |\n")
        f.write(f"| **True Negatives (TN)** | {tn} | Safe/spam correctly identified as low risk |\n")
        f.write(f"| **False Positives (FP)** | {fp} | Benign emails incorrectly flagged as phishing/scam |\n")
        f.write(f"| **False Negatives (FN)** | {fn} | Phishing/scam missed by the filter |\n")
        f.write(f"| **Accuracy** | {accuracy*100:.2f}% | ({tp + tn}/{total}) |\n")
        f.write(f"| **Precision** | {precision*100:.2f}% | ({tp}/{tp + fp}) |\n")
        f.write(f"| **Recall** | {recall*100:.2f}% | ({tp}/{tp + fn}) |\n")
        f.write(f"| **F1 Score** | {f1*100:.2f}% | Harmonic mean of precision & recall |\n\n")
        
        f.write("## Detailed Category Breakdown\n")
        f.write("This table shows how individual ground truth categories were classified by the scorer.\n\n")
        f.write("| Ground Truth \\ Predicted | Phishing | Scam | Spam | Safe |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for gt in gt_categories:
            f.write(f"| **{gt}** | {breakdown[gt]['phishing']} | {breakdown[gt]['scam']} | {breakdown[gt]['spam']} | {breakdown[gt]['safe']} |\n")
        f.write("\n")
        
        # Interpretation
        f.write("## Performance Interpretation\n\n")
        
        well_desc = []
        struggle_desc = []
        
        if tp > 0:
            well_desc.append(f"correctly identifying unambiguous phishing attempts (TP = {tp}), successfully catching emails with clear threat signals (lookalike domains, SPF/DKIM/DMARC failures, and high-urgency language combined with credential requests)")
        if tn > 0:
            well_desc.append(f"correctly classifying legitimate university communications as safe (TN = {tn}), ensuring standard institutional mail is ignored by the filter")
        if fp == 0:
            well_desc.append("avoiding false alarms entirely (FP = 0), which guarantees that safe emails do not trigger warnings for users")
        if fn == 0:
            well_desc.append("capturing all dangerous emails (FN = 0) without letting threats leak into the inbox")
            
        if fn > 0:
            struggle_desc.append(f"detecting borderline or sophisticated phishing emails (FN = {fn}). These emails often lack obvious triggers: they might pass SPF or DKIM checks, omit overt urgency keywords, or avoid malicious links entirely, relying instead on pure text manipulation or attachments that fail to accumulate enough threat points to trigger a high-risk classification")
        if fp > 0:
            struggle_desc.append(f"handling benign emails that happen to contain keywords commonly associated with scams (FP = {fp}), leading to occasional false alarms where safe context is misconstrued as high risk")
            
        f.write(f"**Strengths**: The scorer performs well at:\n")
        for wd in well_desc:
            f.write(f"- {wd}.\n")
        f.write("\n")
        
        if struggle_desc:
            f.write(f"**Weaknesses**: The scorer struggles with:\n")
            for sd in struggle_desc:
                f.write(f"- {sd}.\n")
        else:
            f.write(f"**Weaknesses**: No significant weaknesses were observed under the current test dataset (all threats detected, and no false alarms generated).\n")
        f.write("\n")
        
        # Incorrect prediction examples
        f.write("## Incorrectly Classified Examples\n\n")
        if not incorrect_predictions:
            f.write("No incorrect predictions were found in this evaluation!\n")
        else:
            for idx, err in enumerate(incorrect_predictions[:2]):
                email = err["email"]
                pred_res = err["prediction"]
                err_type = err["type"]
                
                f.write(f"### Example {idx+1}: {err_type}\n")
                f.write(f"- **Email ID**: `{email.get('id')}`\n")
                f.write(f"- **Sender**: `{email.get('sender')}`\n")
                f.write(f"- **Subject**: \"{email.get('subject')}\"\n")
                f.write(f"- **Ground Truth**: `{email.get('ground_truth')}`\n")
                f.write(f"- **Predicted Category**: `{pred_res.get('category')}` (Score: {pred_res.get('score')}/100)\n")
                f.write(f"- **Explanation**: *{pred_res.get('explanation')}*\n\n")
                
                # Analyze why it got it wrong based on the code/email body
                f.write("**Analysis of Failure Cause**:\n")
                body = email.get('body_text', '')
                links = email.get('links', [])
                headers = email.get('headers', {})
                
                analysis_points = []
                # Check SPF/DKIM/DMARC
                if "fail" in (headers.get("spf", ""), headers.get("dkim", ""), headers.get("dmarc", "")):
                    analysis_points.append("The email has failing authentication headers which triggered the scorer's authenticity penalties.")
                else:
                    analysis_points.append("The email successfully passed authentication checks (SPF/DKIM/DMARC), preventing the scorer from applying authenticity flags.")
                    
                # Check lookalikes
                has_lookalike = False
                for link in links:
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(link)
                        netloc = parsed.netloc or parsed.path.split("/")[0]
                        from agents.scoring_agent import check_lookalike
                        if check_lookalike(netloc):
                            has_lookalike = True
                    except:
                        pass
                if has_lookalike:
                    analysis_points.append("It contained lookalike domain links, which triggered domain flags.")
                else:
                    analysis_points.append("It did not contain lookalike domain links, so it missed lookalike-based flags.")
                    
                # Check keywords
                from agents.scoring_agent import LEGITIMATE_DOMAINS
                has_mismatch = False
                for brand, legit in LEGITIMATE_DOMAINS.items():
                    if brand in email.get('sender', '').lower():
                        sender_parts = email.get('sender', '').split("@")
                        sender_domain = sender_parts[1].split(">")[0].strip().lower() if len(sender_parts) > 1 else ""
                        if sender_domain != legit:
                            has_mismatch = True
                if has_mismatch:
                    analysis_points.append("It triggered a Display Name/Domain mismatch because it referenced a brand in the sender local part but used a different sender domain.")
                    
                # Summarize why it got it wrong
                if err_type == "False Negative":
                    f.write(f"This email was an attack (`{email.get('ground_truth')}`) but was classified as benign (`{pred_res.get('category')}`). ")
                    if pred_res.get("category") == "safe":
                        f.write("This occurred because the email did not contain enough explicit indicators to push its score past the baseline risk threshold (20), leading it to be classified as safe.\n")
                    else:
                        f.write("This occurred because the email's score (between 21 and 50) was not high enough to cross the high-risk threshold (50) for a phishing classification, and it did not contain a too-good-to-be-true offer to be classified as a scam. This led it to be categorized as spam (which is treated as benign/negative for this evaluation).\n")
                    f.write("Specifically:\n")
                    for p in analysis_points:
                        f.write(f"- {p}\n")
                    f.write(f"- The email body content: *\"{body[:150]}...\"* relies on subtle context that the rule-based scanner does not recognize as high risk.\n\n")
                elif err_type == "False Positive":
                    f.write(f"This email was safe (`{email.get('ground_truth')}`) but was classified as a threat (`{pred_res.get('category')}`). ")
                    f.write("This occurred because benign keywords matched threat patterns (such as urgency terms or references to account/security checks), causing the rule-based scorer to generate a false alarm.\n")
                    f.write("Specifically:\n")
                    for p in analysis_points:
                        f.write(f"- {p}\n")
                    f.write(f"- The email body content: *\"{body[:150]}...\"* triggered keyword checks without actually presenting a threat.\n\n")

    print(f"\nSaved evaluation metrics report to {report_path}")

if __name__ == "__main__":
    main()
