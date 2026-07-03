"""
gmail_mcp_server.py
--------------------
MCP server (stdio transport) exposing three Gmail tools:
  • list_messages(max_results)
  • get_message(message_id)
  • get_headers(message_id)

Run as an MCP server:
    python mcp-server/gmail_mcp_server.py

Run the self-test (not as MCP):
    python mcp-server/gmail_mcp_server.py --self-test
or simply run the __main__ block directly in an IDE.
"""

from __future__ import annotations

import base64
import re
import sys
from email import message_from_bytes
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from gmail_auth import get_gmail_service

# FIX Bug 12: Shared helpers used to be copy-pasted here and in dashboard/app.py.
# They now live in agents/email_utils.py and are imported from both places.
# Use centralised _path_setup instead of inline sys.path hacks.
import sys as _sys
from pathlib import Path as _Path
_PROJECT_ROOT = str(_Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)

import _path_setup  # noqa: E402  — adds project root to sys.path

from agents.email_utils import (  # noqa: E402
    decode_mime_header  as _decode_mime_header,
    strip_html          as _strip_html,
    extract_body_text   as _extract_body_text,
    extract_links       as _extract_links,
    extract_auth_result as _extract_auth_result,
)

# ---------------------------------------------------------------------------
# Rate limiting — simple inter-call delay to avoid Gmail API quota errors
# ---------------------------------------------------------------------------
import time

_RATE_LIMIT_SECONDS = 0.5
_last_api_call_time = 0.0


def _rate_limited_execute(request):
    """
    Execute a Gmail API request with a minimum delay between consecutive calls.
    Prevents hitting per-user rate limits on the Gmail API.
    """
    global _last_api_call_time
    now = time.monotonic()
    elapsed = now - _last_api_call_time
    if elapsed < _RATE_LIMIT_SECONDS:
        time.sleep(_RATE_LIMIT_SECONDS - elapsed)
    result = request.execute()
    _last_api_call_time = time.monotonic()
    return result

# ---------------------------------------------------------------------------
# MCP Server setup
# ---------------------------------------------------------------------------

app = Server("gmail-mcp-server")


# ---------------------------------------------------------------------------
# Tool: list_messages
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_messages",
            description="Return a list of recent Gmail messages with id and snippet.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of messages to return (default 10).",
                        "default": 10,
                    }
                },
                "required": [],
            },
        ),
        types.Tool(
            name="get_message",
            description=(
                "Return a full email object for the given message ID. "
                "Includes sender, subject, body text, extracted links, "
                "and SPF/DKIM/DMARC authentication results."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "message_id": {
                        "type": "string",
                        "description": "Gmail message ID.",
                    }
                },
                "required": ["message_id"],
            },
        ),
        types.Tool(
            name="get_headers",
            description="Return the raw header dictionary for a Gmail message.",
            inputSchema={
                "type": "object",
                "properties": {
                    "message_id": {
                        "type": "string",
                        "description": "Gmail message ID.",
                    }
                },
                "required": ["message_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(
    name: str, arguments: dict[str, Any]
) -> list[types.TextContent]:
    service = get_gmail_service()

    if name == "list_messages":
        max_results = int(arguments.get("max_results", 10))
        result = _list_messages(service, max_results)
    elif name == "get_message":
        message_id = arguments["message_id"]
        result = _get_message(service, message_id)
    elif name == "get_headers":
        message_id = arguments["message_id"]
        result = _get_headers(service, message_id)
    else:
        raise ValueError(f"Unknown tool: {name}")

    import json
    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


# ---------------------------------------------------------------------------
# Gmail helper functions (sync — fine for stdio MCP)
# ---------------------------------------------------------------------------

def _list_messages(service, max_results: int = 10) -> list[dict]:
    """Return [{id, snippet}, …] for the most recent messages."""
    response = _rate_limited_execute(
        service.users()
        .messages()
        .list(userId="me", maxResults=max_results)
    )
    messages = response.get("messages", [])
    result = []
    for msg in messages:
        detail = _rate_limited_execute(
            service.users()
            .messages()
            .get(userId="me", id=msg["id"], format="metadata",
                 metadataHeaders=["Subject"])
        )
        result.append(
            {
                "id": msg["id"],
                "snippet": detail.get("snippet", ""),
            }
        )
    return result


def _get_message(service, message_id: str) -> dict:
    """
    Return a full email object:
    {
        "id": str,
        "sender": str,
        "subject": str,
        "body_text": str,
        "links": [str],
        "headers": {"spf": str, "dkim": str, "dmarc": str}
    }
    """
    raw_msg = _rate_limited_execute(
        service.users()
        .messages()
        .get(userId="me", id=message_id, format="raw")
    )

    raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"] + "==")
    email_msg = message_from_bytes(raw_bytes)

    # --- Basic headers (decoded from RFC 2047 encoded-word format) ---
    sender = _decode_mime_header(email_msg.get("From", ""))
    subject = _decode_mime_header(email_msg.get("Subject", ""))

    # --- Body text ---
    body_text = _extract_body_text(email_msg)

    # --- Links ---
    links = _extract_links(body_text)

    # --- Auth headers (SPF / DKIM / DMARC) ---
    auth_results_header = email_msg.get("Authentication-Results", "")
    spf = _extract_auth_result(auth_results_header, "spf")
    dkim = _extract_auth_result(auth_results_header, "dkim")
    dmarc = _extract_auth_result(auth_results_header, "dmarc")

    # Truncate body to 1500 chars — enough for phishing analysis, avoids bloat
    body_text = body_text[:1500]

    return {
        "id": message_id,
        "sender": sender,
        "subject": subject,
        "body_text": body_text,
        "links": links,
        "headers": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
        },
    }


def _get_headers(service, message_id: str) -> dict:
    """Return a flat {name: value} dict of all raw headers."""
    msg = _rate_limited_execute(
        service.users()
        .messages()
        .get(userId="me", id=message_id, format="full")
    )
    payload = msg.get("payload", {})
    headers = payload.get("headers", [])
    return {h["name"]: h["value"] for h in headers}



# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
# (Moved to agents/email_utils.py — imported at top of file as private aliases)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Public API wrappers
# FIX Bug 6: connector_agent.py was importing private `_list_messages` and
# `_get_message` directly. Expose public wrappers so external callers don't
# depend on private implementation details.
# ---------------------------------------------------------------------------

def list_messages(service, max_results: int = 10) -> list[dict]:
    """Public wrapper: return [{id, snippet}, …] for the most recent messages."""
    return _list_messages(service, max_results)


def get_message(service, message_id: str) -> dict:
    """Public wrapper: return a full email object for the given message ID."""
    return _get_message(service, message_id)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _run_mcp_server():
    """Start the stdio MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


def _self_test():
    """
    Quick self-test: authenticate, call list_messages(5), then get_message on
    each of those 5 IDs, and print results to the console.
    """
    import json

    print("=" * 60)
    print("Gmail MCP Server - Self-Test")
    print("=" * 60)

    print("\n[1] Authenticating ...")
    service = get_gmail_service()
    print("    [OK] Authenticated successfully.\n")

    print("[2] Calling list_messages(5) ...")
    messages = _list_messages(service, 5)
    print(f"    [OK] Got {len(messages)} message(s).\n")
    for m in messages:
        print(f"    ID: {m['id']}")
        print(f"    Snippet: {m['snippet'][:80]}...\n")

    print("[3] Calling get_message() on each ID ...\n")
    for i, m in enumerate(messages, start=1):
        print(f"  --- Message {i} ---")
        email_obj = _get_message(service, m["id"])
        # Truncate body_text for terminal readability; the full 1500-char value
        # is what get_message() actually returns to callers.
        display_obj = {
            **email_obj,
            "body_text": email_obj["body_text"][:200]
                         + ("..." if len(email_obj["body_text"]) > 200 else ""),
        }
        print(json.dumps(display_obj, indent=2, ensure_ascii=False))
        print()

    print("=" * 60)
    print("Self-test complete.")
    print("=" * 60)


if __name__ == "__main__":
    if "--self-test" in sys.argv:   # run self-test only when requested
        _self_test()
    else:
        import asyncio
        asyncio.run(_run_mcp_server())
