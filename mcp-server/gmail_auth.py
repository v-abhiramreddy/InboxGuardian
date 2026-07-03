"""
gmail_auth.py
-------------
Handles OAuth2 authentication for the Gmail API.
Only requests the gmail.readonly scope — no write/modify/send access.
"""

import os
import sys
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# SECURITY: The OAuth scope below is intentionally restricted to gmail.readonly.
# This grants ONLY read access to the user's Gmail messages and metadata.
# It does NOT permit sending, drafting, modifying, deleting, or inserting
# messages. Any broader scope (e.g. gmail.modify, gmail.send, gmail.compose,
# mail.google.com) would violate this project's read-only security posture.
# Do not widen this scope without a formal security review.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Resolve paths relative to the *project root* (one level up from mcp-server/)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
CREDENTIALS_PATH = _PROJECT_ROOT / "credentials.json"
TOKEN_PATH = _PROJECT_ROOT / "token.json"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_gmail_service():
    """
    Return an authenticated Gmail API service object.

    Authentication flow:
    1. If token.json exists and is still valid, reuse it silently.
    2. If the token is expired but has a refresh_token, refresh it automatically.
    3. Otherwise start an interactive OAuth2 browser flow.
    4. Save the resulting token to token.json for future runs.

    Raises:
        FileNotFoundError: If credentials.json is missing.
        RuntimeError:       If authentication fails for any other reason.
    """
    if not CREDENTIALS_PATH.exists():
        raise FileNotFoundError(
            f"credentials.json not found at: {CREDENTIALS_PATH}\n"
            "Download it from the Google Cloud Console → APIs & Services → Credentials."
        )

    creds = _load_cached_token()

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as exc:
                # Refresh failed (revoked token, etc.) — start fresh
                print(f"[gmail_auth] Token refresh failed ({exc}), re-authenticating …")
                creds = _run_oauth_flow()
        else:
            creds = _run_oauth_flow()

        _save_token(creds)

    try:
        service = build("gmail", "v1", credentials=creds)
        return service
    except Exception as exc:
        raise RuntimeError(f"Failed to build Gmail service: {exc}") from exc


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_cached_token() -> Credentials | None:
    """Load and return cached credentials from token.json, or None."""
    if TOKEN_PATH.exists():
        try:
            return Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
        except Exception as exc:
            print(f"[gmail_auth] Could not load token.json ({exc}), will re-authenticate.")
    return None


def _run_oauth_flow() -> Credentials:
    """Run the OAuth2 InstalledAppFlow and return new credentials."""
    flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_PATH), SCOPES)
    creds = flow.run_local_server(port=0, prompt="consent")
    return creds


def _save_token(creds: Credentials) -> None:
    """Persist credentials to token.json for reuse on future runs."""
    try:
        TOKEN_PATH.write_text(creds.to_json())
        print(f"[gmail_auth] Token saved to {TOKEN_PATH}")
    except Exception as exc:
        print(f"[gmail_auth] Warning: could not save token ({exc})")
