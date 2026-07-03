"""
agents package
--------------
Contains the core analytical agents and utilities:
- scoring_agent: analyzes and scores email headers, links, and content
- connector_agent: interfaces with the Gmail MCP client/server
- audit_log: handles PII-free file logging
- email_utils: shared HTML stripping, URL matching, and MIME helper functions
- llm_analysis_agent: Gemini LLM-powered threat explanation generation
"""

from .scoring_agent import score_email
from .connector_agent import fetch_recent_emails
from .audit_log import log_decision
from .llm_analysis_agent import analyze_email_with_llm, analyze_batch

__all__ = [
    "score_email",
    "fetch_recent_emails",
    "log_decision",
    "analyze_email_with_llm",
    "analyze_batch",
]
