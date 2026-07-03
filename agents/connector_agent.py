"""
connector_agent.py
------------------
Fetches real emails from Gmail and returns them as clean email objects
matching the project's standard schema.

Design note:
    This module calls the Gmail MCP server's helper functions DIRECTLY
    (in-process import) for simplicity during development.  In a production
    deployment the calls would cross the MCP client/server boundary — i.e.,
    a proper MCP client would send JSON-RPC tool-call requests over stdio (or
    HTTP+SSE) to the gmail_mcp_server process, and receive JSON-RPC responses.
    The schema of the returned email objects is identical either way.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path plumbing — allow importing from mcp-server/ regardless of CWD
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_MCP_SERVER_DIR = _PROJECT_ROOT / "mcp-server"

if str(_MCP_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_SERVER_DIR))

# These imports resolve to mcp-server/gmail_auth.py and the helper functions
# defined in mcp-server/gmail_mcp_server.py.
# FIX Bug 6: Use the public API wrappers instead of private `_`-prefixed internals.
from gmail_auth import get_gmail_service                    # noqa: E402
from gmail_mcp_server import list_messages, get_message     # noqa: E402


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_recent_emails(count: int = 10) -> list[dict]:
    """
    Fetch the most recent *count* emails from Gmail and return them as a list
    of email objects.

    Each object matches the project schema:
    {
        "id":       str,
        "sender":   str,
        "subject":  str,
        "body_text": str,          # plain text, HTML-stripped, max 1500 chars
        "links":    list[str],     # all URLs found in body
        "headers":  {
            "spf":  str,           # pass | fail | softfail | none
            "dkim": str,
            "dmarc": str,
        }
    }

    NOTE (production path):
        In production, replace the direct function calls below with an MCP
        client that sends tool-call requests over stdio/HTTP to the running
        gmail_mcp_server process:

            client.call_tool("list_messages", {"max_results": count})
            client.call_tool("get_message",   {"message_id": msg_id})

        The returned JSON payloads are identical to what the helpers produce.
    """
    service = get_gmail_service()

    # Step 1: get message IDs + snippets
    message_stubs = list_messages(service, max_results=count)

    # Step 2: fetch full email object for each ID
    emails: list[dict] = []
    for stub in message_stubs:
        try:
            email_obj = get_message(service, stub["id"])
            emails.append(email_obj)
        except Exception as exc:
            # Log and continue — a single bad message shouldn't abort the batch
            print(
                f"[connector_agent] Warning: could not fetch message "
                f"{stub['id']}: {exc}",
                file=sys.stderr,
            )

    return emails


# ---------------------------------------------------------------------------
# __main__ self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Connector Agent - Self-Test")
    print("=" * 60)

    print("\nFetching 10 most recent emails...")
    emails = fetch_recent_emails(count=10)
    print(f"[OK] Got {len(emails)} email(s).\n")

    for i, email in enumerate(emails, start=1):
        # Build a display copy with body_text truncated to 200 chars
        display = {
            **email,
            "body_text": email["body_text"][:200]
                         + ("..." if len(email["body_text"]) > 200 else ""),
        }
        print(f"--- Email {i} ---")
        print(json.dumps(display, indent=2, ensure_ascii=False))
        print()

    print("=" * 60)
    print("Self-test complete.")
    print("=" * 60)
