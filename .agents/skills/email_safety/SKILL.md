---
name: EmailSafetyOperator
description: Instructions for operating, testing, and verifying the Email Safety analysis pipeline and MCP client.
---

# Email Safety Operator Skill

This skill guides developer agents on how to execute, verify, and maintain the Email Safety pipeline and stdio MCP server.

## Pipeline Operations

### 1. Run the ADK Pipeline
The pipeline is orchestrated using the Google Agent Development Kit (ADK) workflow graph. It fetches recent emails and scores them for security risks.
To execute it, run:
```bash
python run_adk_pipeline.py
```
*Note: If `credentials.json` is missing from the project root, the script automatically falls back to `mock-data/sample-emails.json` to complete the evaluation.*

### 2. Verify the MCP Client/Server Connection
To verify that the Gmail MCP stdio server compiles and responds correctly to tool queries:
```bash
python run_mcp_client.py
```
*Note: This script launches the MCP server in a subprocess, initializes the connection, queries the tool schemas, and exits safely.*

### 3. Run Binary classification metrics
To evaluate the scoring model accuracy (Accuracy, Precision, Recall, F1 Score) against the mock datasets and real phishing samples:
```bash
python evaluation/run_evaluation.py
```
This updates the performance evaluation report at `evaluation/metrics_report.md`.

---

## Security Guardrails

*   **PII Compliance**: Never log email bodies, subjects, or sender names to the persistent audit log. Only record `email_id`, `score`, `category`, and `confidence` using the decision logger.
*   **Prompt Injection Protection**: The system relies on a deterministic, rule-based classifier. Do not pass untrusted email bodies directly into LLM prompts without strict delimiters and output validation.
*   **Access Control**: Ensure that the OAuth scope remains strictly set to `gmail.readonly` to prevent accidental write actions (sending, deleting, or archiving emails).
