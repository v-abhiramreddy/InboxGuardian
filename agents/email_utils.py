"""
agents/email_utils.py
---------------------
Shared email parsing utilities used by both the MCP server and the dashboard.

FIX Bug 12: These six functions were copy-pasted verbatim between
  mcp-server/gmail_mcp_server.py  and  dashboard/app.py.
Any bug fixed in one copy had to be manually mirrored to the other.
They now live here and are imported from both places.
"""

from __future__ import annotations

import re
from email.header import decode_header, make_header
from html.parser import HTMLParser


# ---------------------------------------------------------------------------
# HTML → plain text
# ---------------------------------------------------------------------------

class _HTMLTextExtractor(HTMLParser):
    """Minimal HTML parser that collects visible text, skipping scripts/styles."""

    SKIP_TAGS = {"script", "style", "head", "meta", "link", "noscript"}

    def __init__(self):
        super().__init__()
        self._parts: list[str] = []
        self._skip_depth: int = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            stripped = data.strip()
            if stripped:
                self._parts.append(stripped)

    def get_text(self) -> str:
        raw = " ".join(self._parts)
        return re.sub(r"[ \t]{2,}", " ", raw).strip()


def strip_html(html: str) -> str:
    """Strip HTML tags and return clean visible text."""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        return parser.get_text()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html).strip()


# ---------------------------------------------------------------------------
# MIME header decoding
# ---------------------------------------------------------------------------

def decode_mime_header(raw: str) -> str:
    """
    Decode an RFC 2047 encoded-word header value into a plain Unicode string.

    Handles values like:
        =?utf-8?B?VXBncmFkZSB5b3Ugc...?=   (base64-encoded)
        =?utf-8?Q?Hello=20World?=            (quoted-printable encoded)
        Plain text with no encoding          (returned as-is)
    """
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw


# ---------------------------------------------------------------------------
# Body text extraction
# ---------------------------------------------------------------------------

def extract_body_text(email_msg) -> str:
    """
    Walk the MIME tree and return readable plain text.
    Priority: text/plain > HTML-stripped text/html > empty string.
    """
    plain_text: str | None = None
    html_text: str | None = None

    parts = list(email_msg.walk()) if email_msg.is_multipart() else [email_msg]
    for part in parts:
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        decoded = payload.decode(charset, errors="replace")

        if ctype == "text/plain" and plain_text is None:
            plain_text = decoded
        elif ctype == "text/html" and html_text is None:
            html_text = decoded

    if plain_text is not None:
        return plain_text
    if html_text is not None:
        return strip_html(html_text)
    return ""


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"https?://[^\s\)\]\>\"\'<]+",
    re.IGNORECASE,
)

# Characters that are commonly part of surrounding prose, not the URL itself
_TRAILING_PUNCT = re.compile(r"[.,;:!?\)\]}'\"]+$")


def extract_links(text: str) -> list[str]:
    """Extract all http/https URLs from text, stripping trailing punctuation."""
    raw_matches = _URL_RE.findall(text)
    cleaned = [_TRAILING_PUNCT.sub("", url) for url in raw_matches]
    return list(dict.fromkeys(cleaned))  # deduplicated, order-preserved


# ---------------------------------------------------------------------------
# Authentication-Results header parsing
# ---------------------------------------------------------------------------

_AUTH_RESULT_RE = re.compile(
    r"(?:^|;)\s*(?P<proto>spf|dkim|dmarc)\s*=\s*(?P<result>\w+)",
    re.IGNORECASE | re.MULTILINE,
)


def extract_auth_result(auth_header: str, proto: str) -> str:
    """
    Parse an Authentication-Results header and return pass/fail/none/softfail/…
    for the requested protocol.  Returns 'none' if not found.
    """
    for m in _AUTH_RESULT_RE.finditer(auth_header):
        if m.group("proto").lower() == proto.lower():
            return m.group("result").lower()
    return "none"
