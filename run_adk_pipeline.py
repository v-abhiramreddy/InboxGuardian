"""
run_adk_pipeline.py
-------------------
Runs the email safety analysis pipeline using the official Google Agent
Development Kit (ADK) framework.

It defines a two-step sequential workflow using ADK BaseAgent subclasses:
  FetchEmailsAgent  →  ScoreEmailsAgent

State is shared across agents via the ADK InvocationContext session state.
The workflow is orchestrated by a SequentialAgent and run via the ADK Runner.

FIX Bug 1: The original file imported `google.adk.Workflow` (which does not
exist), defined nodes with custom (ctx, node_input) signatures that don't
match ADK's API, and used Runner/session APIs with wrong argument signatures.
This file is a complete rewrite using the correct ADK agent primitives.

FIX Bug 7: score_emails_node previously returned "score_success" even when
results.json could not be written. The new implementation propagates the
error into state and logs it clearly instead of silently succeeding.
"""

import asyncio
import json
from collections import Counter
from pathlib import Path
from typing import AsyncGenerator

# ---------------------------------------------------------------------------
# ADK imports — google-adk uses BaseAgent / SequentialAgent as the primary
# agent composition primitives. Runner and InMemorySessionService handle
# execution and session lifecycle respectively.
# ---------------------------------------------------------------------------
from google.adk.agents import BaseAgent, SequentialAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
import google.genai.types as genai_types

# ---------------------------------------------------------------------------
# Path plumbing — allow importing from agents/ regardless of CWD
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
RESULTS_PATH = PROJECT_ROOT / "results.json"


# ---------------------------------------------------------------------------
# ADK Agent 1: Fetch emails
# ---------------------------------------------------------------------------

class FetchEmailsAgent(BaseAgent):
    """
    ADK Agent node: Fetch recent emails from Gmail.
    Stores fetched emails in the shared ADK session state under "emails".
    Falls back to mock-data/sample-emails.json if Gmail credentials fail.
    """

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        from agents.connector_agent import fetch_recent_emails

        print("\n[ADK] FetchEmailsAgent: Fetching recent emails from Gmail...")
        try:
            emails = fetch_recent_emails(count=15)
            ctx.session.state["emails"] = emails
            ctx.session.state["mode"] = "live"
            print(f"      [OK] Successfully fetched {len(emails)} email(s).")
        except Exception as exc:
            err_msg = str(exc).replace("→", "->")
            print(f"      [WARNING] Live Gmail fetch failed: {err_msg}")
            print("      [INFO] Falling back to mock-data/sample-emails.json ...")

            mock_path = PROJECT_ROOT / "mock-data" / "sample-emails.json"
            try:
                with open(mock_path, "r", encoding="utf-8") as f:
                    emails = json.load(f)[:15]
                ctx.session.state["emails"] = emails
                ctx.session.state["mode"] = "mock"
                print(f"      [OK] Loaded {len(emails)} mock email(s).")
            except Exception as mock_exc:
                print(f"      [ERROR] Could not load mock emails: {mock_exc}")
                ctx.session.state["emails"] = []
                ctx.session.state["mode"] = "error"

        # Yield an empty event to satisfy the async generator contract
        yield Event(
            author=self.name,
            content=genai_types.Content(parts=[], role="model"),
        )


# ---------------------------------------------------------------------------
# ADK Agent 2: Score emails
# ---------------------------------------------------------------------------

class ScoreEmailsAgent(BaseAgent):
    """
    ADK Agent node: Score all fetched emails.
    Reads "emails" from session state, writes "results" and "category_counts".
    Also writes results.json to disk.

    FIX Bug 7: If the file write fails, the error is recorded in session state
    under "save_error" and clearly logged — the agent no longer silently
    returns success.
    """

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        from agents.scoring_agent import score_email
        from agents.audit_log import log_decision

        emails = ctx.session.state.get("emails", [])
        if not emails:
            print("      [WARNING] No emails to score in state.")
            ctx.session.state["results"] = []
            ctx.session.state["category_counts"] = {}
            ctx.session.state["save_error"] = None
            yield Event(
                author=self.name,
                content=genai_types.Content(parts=[], role="model"),
            )
            return

        print("\n[ADK] ScoreEmailsAgent: Running threat analysis & scoring...")
        new_results = []
        category_counts = Counter()

        for email in emails:
            try:
                score_obj = score_email(email)
                log_decision(
                    email_id=score_obj["email_id"],
                    score=score_obj["score"],
                    category=score_obj["category"],
                    confidence=score_obj["confidence"],
                )
                score_obj["subject"] = email.get("subject", "")
                score_obj["sender"] = email.get("sender", "")
                new_results.append(score_obj)
                category_counts[score_obj["category"]] += 1
            except Exception as exc:
                print(f"      [WARNING] Failed to score email {email.get('id')}: {exc}")

        # Save results.json
        save_error = None
        try:
            with open(RESULTS_PATH, "w", encoding="utf-8") as f:
                json.dump(new_results, f, indent=2, ensure_ascii=False)
            print("      [OK] Scoring results saved to results.json.")
        except Exception as exc:
            # FIX Bug 7: Record and surface the failure instead of silently succeeding
            save_error = str(exc)
            print(f"      [ERROR] Could not save results.json: {exc}")

        ctx.session.state["results"] = new_results
        ctx.session.state["category_counts"] = dict(category_counts)
        ctx.session.state["save_error"] = save_error

        yield Event(
            author=self.name,
            content=genai_types.Content(parts=[], role="model"),
        )


# ---------------------------------------------------------------------------
# ADK Agent 3: Generate Safety Report
# ---------------------------------------------------------------------------

class SafetyReporterAgent(BaseAgent):
    """
    ADK Agent node: Generate a clean, readable safety report.
    Reads "results" from session state and writes safety_report.md.
    """

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        results = ctx.session.state.get("results", [])
        counts = ctx.session.state.get("category_counts", {})
        
        report_path = PROJECT_ROOT / "safety_report.md"
        print("\n[ADK] SafetyReporterAgent: Generating final safety report...")
        
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("# 🛡️ Inbox Guardian Safety Report\n\n")
                f.write(f"Generated automatically by Google ADK Pipeline.\n\n")
                
                # Summary table
                f.write("## 📊 Summary Metrics\n")
                f.write(f"- **Total Emails Scanned**: {len(results)}\n")
                f.write(f"- **Safe**: {counts.get('safe', 0)}\n")
                f.write(f"- **Spam**: {counts.get('spam', 0)}\n")
                f.write(f"- **Scam**: {counts.get('scam', 0)}\n")
                f.write(f"- **Phishing**: {counts.get('phishing', 0)}\n\n")
                
                # Status overview
                n_threats = counts.get('phishing', 0) + counts.get('scam', 0)
                if n_threats > 0:
                    f.write(f"> [!WARNING]\n")
                    f.write(f"> **Action Required**: {n_threats} active threat(s) detected in your inbox! Check details below.\n\n")
                else:
                    f.write(f"> [!NOTE]\n")
                    f.write(f"> **Inbox Clean**: No active phishing or scam threats detected in this scan.\n\n")
                
                # Detailed list
                f.write("## 🔍 Scanned Emails Details\n")
                f.write("| ID | Sender | Subject | Score | Category |\n")
                f.write("| :--- | :--- | :--- | :---: | :---: |\n")
                for email in results:
                    sender = email.get("sender", "Unknown").replace("<", "&lt;").replace(">", "&gt;")
                    f.write(f"| `{email.get('email_id')}` | `{sender}` | \"{email.get('subject')}\" | **{email.get('score')}** | `{email.get('category').upper()}` |\n")
                    
            print(f"      [OK] Safety report saved to safety_report.md.")
            ctx.session.state["report_saved"] = True
        except Exception as exc:
            print(f"      [ERROR] Could not save safety_report.md: {exc}")
            ctx.session.state["report_saved"] = False

        yield Event(
            author=self.name,
            content=genai_types.Content(parts=[], role="model"),
        )


# ---------------------------------------------------------------------------
# ADK Sequential Workflow definition
# FIX Bug 1: Use SequentialAgent (the correct ADK composition primitive)
# instead of the non-existent Workflow class with graph edges.
# ---------------------------------------------------------------------------

email_safety_workflow = SequentialAgent(
    name="email_safety_workflow",
    description="Fetches and scores emails for phishing risk using Google ADK",
    sub_agents=[
        FetchEmailsAgent(name="fetch_emails_agent"),
        ScoreEmailsAgent(name="score_emails_agent"),
        SafetyReporterAgent(name="safety_reporter_agent"),
    ],
)


# ---------------------------------------------------------------------------
# Execution entry point
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("Email Safety Pipeline - ADK Workflow Run")
    print("=" * 60)

    # 1. Initialise session service & runner
    sessions = InMemorySessionService()
    runner = Runner(
        agent=email_safety_workflow,
        session_service=sessions,
        app_name="email_safety",
    )

    # 2. Create a session for this run
    session = await sessions.create_session(
        app_name="email_safety", user_id="user"
    )

    # 3. Execute the workflow (no initial user message needed for this pipeline)
    print("\nExecuting sequential workflow...")
    async for _event in runner.run_async(
        user_id="user",
        session_id=session.id,
        new_message=genai_types.Content(
            parts=[genai_types.Part(text="start")], role="user"
        ),
    ):
        pass  # events are handled inside each agent node

    # 4. Retrieve final state from session
    updated_session = await sessions.get_session(
        app_name="email_safety", user_id="user", session_id=session.id
    )
    results = updated_session.state.get("results", [])
    counts = updated_session.state.get("category_counts", {})
    save_error = updated_session.state.get("save_error")

    # 5. Summary report
    print("\n" + "=" * 60)
    print("Pipeline Execution Summary (via ADK)")
    print("=" * 60)
    print(f"Total Emails Scanned : {len(results)}")
    print(f"Data mode            : {updated_session.state.get('mode', 'unknown')}")
    if save_error:
        print(f"[ERROR] results.json was NOT saved: {save_error}")
    print("Breakdown by Safety Category:")
    for cat in ["safe", "spam", "scam", "phishing"]:
        count = counts.get(cat, 0)
        print(f"  - {cat.upper():<10}: {count}")
    print("=" * 60)
    print("\nAll done! Start the dashboard with:")
    print("streamlit run dashboard/app.py\n")


if __name__ == "__main__":
    asyncio.run(main())
