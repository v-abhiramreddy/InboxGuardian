# -*- coding: utf-8 -*-
"""
dashboard/app.py
----------------
Inbox Guardian - Streamlit web app.

Flow
────
1. No session  ->  Sign-in page (Google OAuth button + "View demo" link).
2. ?code=...     ->  Exchange code for access token, store in session_state,
                   clear URL param, rerun.
3. Signed in   ->  Fetch live Gmail, score every message, render dashboard.
4. Demo mode   ->  Load results-demo.json, show "Demo mode" banner.

OAuth is implemented with plain `requests` - no authlib / google-auth-oauthlib.
"""

from __future__ import annotations

import base64
import html as _html   # FIX Bug 4: used to escape XSS-risky email content
import json
import os
import re
import sys
import time
from email import message_from_bytes
from pathlib import Path
from urllib.parse import urlencode, urlparse

import pandas as pd
import requests
import streamlit as st

# ==============================================================================
#  Path plumbing - use centralised _path_setup instead of inline sys.path hacks
# ==============================================================================
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import _path_setup  # noqa: E402  - adds mcp-server/ to sys.path

from agents.scoring_agent import score_email  # noqa: E402  (our own module)
# FIX Bug 12: Import shared email helpers from the single source of truth
# instead of duplicating ~80 lines of code here.
from agents.email_utils import (           # noqa: E402
    decode_mime_header  as _decode_mime_header,
    strip_html          as _strip_html,
    extract_body_text   as _extract_body_text,
    extract_links       as _extract_links,
    extract_auth_result as _auth_result,
)

# ==============================================================================
#  Page config  (must be first Streamlit call)
# ==============================================================================
st.set_page_config(
    page_title="Inbox Guardian",
    page_icon=chr(0x1f6e1),
    layout="wide",
)

# ==============================================================================
#  Global CSS
# ==============================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* Force dark theme layout for the entire app */
[data-testid="stAppViewContainer"] {
    background-color: #0b1329 !important;
    background-image: radial-gradient(at 0% 0%, rgba(124, 58, 237, 0.08) 0, transparent 50%),
                      radial-gradient(at 50% 0%, rgba(59, 130, 246, 0.05) 0, transparent 50%) !important;
}
[data-testid="stHeader"] {
    background-color: transparent !important;
}
[data-testid="stSidebar"] {
    background-color: #070d1e !important;
    border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
}

html, body, [class*="css"] { 
    font-family: 'Inter', sans-serif; 
}

/* -- Sign-in page -- */
.signin-wrapper {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 80px 20px 40px;
    text-align: center;
}
.signin-logo {
    font-size: 64px;
    margin-bottom: 16px;
    animation: pulse 2.4s ease-in-out infinite;
}
@keyframes pulse {
    0%, 100% { transform: scale(1);    opacity: 1;    }
    50%       { transform: scale(1.06); opacity: 0.85; }
}
.signin-title {
    font-size: 42px;
    font-weight: 700;
    background: linear-gradient(135deg, #a78bfa 0%, #60a5fa 50%, #34d399 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 10px;
}
.signin-desc {
    font-size: 17px;
    color: #94a3b8;
    margin-bottom: 36px;
    max-width: 440px;
}
.google-btn {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    background: #fff;
    color: #1a1a2e;
    border: none;
    border-radius: 10px;
    padding: 13px 28px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    transition: box-shadow 0.2s ease, transform 0.15s ease;
    box-shadow: 0 2px 12px rgba(0,0,0,0.25);
}
.google-btn:hover {
    box-shadow: 0 6px 24px rgba(167,139,250,0.35);
    transform: translateY(-2px);
}
.demo-link {
    margin-top: 24px;
    font-size: 13px;
    color: #94a3b8;
}
.demo-link a { color: #a78bfa; text-decoration: underline; }

/* -- Demo banner -- */
.demo-banner {
    background: linear-gradient(90deg, rgba(245,158,11,0.15) 0%, rgba(245,158,11,0.05) 100%);
    border: 1px solid rgba(245,158,11,0.35);
    border-radius: 10px;
    padding: 10px 18px;
    margin-bottom: 18px;
    font-size: 13px;
    color: #fbbf24;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* -- Glassmorphic card -- */
.email-card {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 14px;
    padding: 20px 24px;
    margin-bottom: 14px;
    backdrop-filter: blur(10px);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.email-card:hover {
    border-color: rgba(255, 255, 255, 0.22);
    box-shadow: 0 4px 32px rgba(0,0,0,0.35);
}
.card-subject {
    font-size: 15px;
    font-weight: 600;
    color: #e2e8f0;
    margin-bottom: 3px;
    line-height: 1.4;
}
.card-sender {
    font-size: 12.5px;
    color: #94a3b8;
    margin-bottom: 14px;
    font-weight: 400;
}
.meta-row {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 10px;
}
.badge {
    display: inline-block;
    padding: 3px 11px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.badge-phishing { background: rgba(239,68,68,0.18);  color: #f87171; border: 1px solid rgba(239,68,68,0.35); }
.badge-scam     { background: rgba(245,101,101,0.18); color: #fc8181; border: 1px solid rgba(245,101,101,0.35); }
.badge-spam     { background: rgba(251,146,60,0.18);  color: #fb923c; border: 1px solid rgba(251,146,60,0.35); }
.badge-safe     { background: rgba(34,197,94,0.16);   color: #4ade80; border: 1px solid rgba(34,197,94,0.30); }
.score-pill {
    font-size: 12px;
    font-weight: 700;
    padding: 3px 11px;
    border-radius: 20px;
    background: rgba(139,92,246,0.18);
    color: #a78bfa;
    border: 1px solid rgba(139,92,246,0.35);
}
.conf-pill {
    font-size: 12px;
    font-weight: 500;
    color: #94a3b8;
}
.explanation {
    font-size: 13px;
    color: #94a3b8;
    line-height: 1.55;
    border-left: 3px solid rgba(99, 102, 241, 0.35);
    padding-left: 10px;
    margin-top: 6px;
}
.llm-explanation {
    margin-top: 10px;
    padding: 10px;
    border-left: 3px solid #8b5cf6;
    background: rgba(139, 92, 246, 0.05);
    border-radius: 0 6px 6px 0;
    font-size: 13px;
    line-height: 1.5;
    color: #cbd5e1;
}

/* -- Metric cards -- */
.metric-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.09);
    border-radius: 12px;
    padding: 16px 20px;
    text-align: center;
}
.metric-value {
    font-size: 32px;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.1;
}
.metric-label {
    font-size: 11px;
    color: #94a3b8;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
}
.section-header {
    font-size: 13px;
    font-weight: 600;
    color: #818cf8;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin: 24px 0 12px 0;
}
.privacy-note {
    font-size: 12px;
    color: #64748b;
    border-top: 1px solid rgba(255,255,255,0.06);
    padding-top: 16px;
    margin-top: 24px;
    text-align: center;
}
hr { border-color: rgba(255,255,255,0.07) !important; margin: 20px 0; }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
#  OAuth constants  (read from Streamlit secrets or env)
# ==============================================================================
def _secret(key: str, fallback: str = "") -> str:
    """Read from st.secrets first, then os.environ, then fallback to credentials.json."""
    try:
        return st.secrets[key]
    except (KeyError, AttributeError, Exception):
        val = os.environ.get(key)
        if val:
            return val

    # Fallback: Try reading from credentials.json at the project root
    try:
        creds_path = _PROJECT_ROOT / "credentials.json"
        if creds_path.exists():
            with open(creds_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg = data.get("installed") or data.get("web")
            if cfg:
                if key == "GOOGLE_CLIENT_ID":
                    return cfg.get("client_id", fallback)
                elif key == "GOOGLE_CLIENT_SECRET":
                    return cfg.get("client_secret", fallback)
    except Exception:
        pass

    return fallback


CLIENT_ID     = _secret("GOOGLE_CLIENT_ID")
CLIENT_SECRET = _secret("GOOGLE_CLIENT_SECRET")
# Default redirect URI to Streamlit's default local address if not configured
REDIRECT_URI  = _secret("REDIRECT_URI", "http://localhost:8501")

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
AUTH_URL    = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL   = "https://oauth2.googleapis.com/token"


# ==============================================================================
#  Gmail REST helpers  (no google-auth-oauthlib needed)
# ==============================================================================

_RATE_LIMIT = 0.35   # seconds between Gmail API calls
_last_call  = 0.0


def _gmail_get(path: str, access_token: str, **params) -> dict:
    """Thin GET wrapper around the Gmail REST API."""
    global _last_call
    elapsed = time.monotonic() - _last_call
    if elapsed < _RATE_LIMIT:
        time.sleep(_RATE_LIMIT - elapsed)

    url  = f"https://gmail.googleapis.com/gmail/v1/users/me/{path}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=15,
    )
    _last_call = time.monotonic()

    if resp.status_code == 401:
        raise PermissionError("Gmail access token expired or revoked.")
    resp.raise_for_status()
    return resp.json()


# ====================================================================== Body / link / auth extraction helpers ----                                
# FIX Bug 12: All helpers are imported from agents/email_utils.py above.
# _decode_mime_header, _strip_html, _extract_body_text, _extract_links,
# and _auth_result are already available as imported names.


def _parse_message(raw_b64: str, message_id: str) -> dict:
    """Decode a raw base64url Gmail message into our email schema."""
    raw_bytes = base64.urlsafe_b64decode(raw_b64 + "==")
    msg       = message_from_bytes(raw_bytes)

    sender  = _decode_mime_header(msg.get("From", ""))
    subject = _decode_mime_header(msg.get("Subject", ""))
    body    = _extract_body_text(msg)[:1500]
    links   = _extract_links(body)

    auth_hdr = msg.get("Authentication-Results", "")
    return {
        "id":        message_id,
        "sender":    sender,
        "subject":   subject,
        "body_text": body,
        "links":     links,
        "headers": {
            "spf":   _auth_result(auth_hdr, "spf"),
            "dkim":  _auth_result(auth_hdr, "dkim"),
            "dmarc": _auth_result(auth_hdr, "dmarc"),
        },
    }


# ==============================================================================
#  High-level: fetch + score
# ==============================================================================

def fetch_and_score(access_token: str, count: int = 20) -> pd.DataFrame:
    """
    Fetch `count` recent Gmail messages using the access token, score each
    one with scoring_agent.score_email(), and return a sorted DataFrame.
    """
    list_resp = _gmail_get("messages", access_token, maxResults=count)
    stubs     = list_resp.get("messages", [])

    if not stubs:
        return pd.DataFrame()

    rows = []
    for stub in stubs:
        try:
            raw_resp  = _gmail_get(f"messages/{stub['id']}", access_token, format="raw")
            email_obj = _parse_message(raw_resp.get("raw", ""), stub["id"])
            scored    = score_email(email_obj)
            # Attach display fields that scoring_agent doesn't return
            scored["subject"] = email_obj["subject"]
            scored["sender"]  = email_obj["sender"]
            
            # Dynamically call Gemini threat analyzer on-the-fly for flagged emails
            # if an API key is set in the environment
            from agents.llm_analysis_agent import analyze_email_with_llm
            if scored["score"] >= 25:
                scored["llm_explanation"] = analyze_email_with_llm(email_obj, scored)
            else:
                scored["llm_explanation"] = None
                
            rows.append(scored)
        except PermissionError:
            raise
        except Exception as exc:
            st.warning(f"Could not process message {stub['id']}: {exc}")

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)


# ==============================================================================
#  Demo data loader
# ==============================================================================

@st.cache_data
def load_demo_data() -> pd.DataFrame:
    demo_path = _PROJECT_ROOT / "results-demo.json"
    with open(demo_path, "r", encoding="utf-8") as f:
        results = json.load(f)
    rows = [
        {
            "email_id":    r["email_id"],
            "subject":     r.get("subject", "-"),
            "sender":      r.get("sender",  "-"),
            "score":       r["score"],
            "category":    r["category"],
            "confidence":  r["confidence"],
            "explanation": r["explanation"],
            "llm_explanation": r.get("llm_explanation"),
        }
        for r in results
    ]
    return pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)


# ==============================================================================
#  Dashboard renderer  (shared by live and demo paths)
# ==============================================================================

CATEGORY_ICONS = {"phishing": "🎣", "scam": "💀", "spam": "📧", "safe": "✅"}


def _badge(cat: str) -> str:
    icon = CATEGORY_ICONS.get(cat, "")
    return f'<span class="badge badge-{cat}">{icon} {cat}</span>'


def _score_color(score: int) -> str:
    if score >= 81: return "#f87171"
    if score >= 51: return "#fb923c"
    if score >= 21: return "#fbbf24"
    return "#4ade80"


def render_dashboard(df: pd.DataFrame, is_demo: bool = False) -> None:
    """Render the full metrics + card dashboard for a scored email DataFrame."""

    if is_demo:
        st.markdown(
            '<div class="demo-banner">Warning <strong>Demo mode</strong> - '
            'sign in to score your own inbox</div>',
            unsafe_allow_html=True,
        )

    # -- Sidebar filters ----                                                
    with st.sidebar:
        st.markdown("## Shield Inbox Guardian")
        st.markdown("---")
        st.markdown("### Filters")

        all_cats      = sorted(df["category"].unique().tolist())
        selected_cats = st.multiselect(
            "Category", options=all_cats, default=all_cats,
            help="Show only emails in the selected risk categories."
        )
        min_score = st.slider(
            "Minimum Risk Score", min_value=0, max_value=100, value=0, step=1,
            help="Only show emails with a risk score ≥ this value."
        )

        st.markdown("---")

        if not is_demo:
            if st.button("🔄 Re-scan inbox"):
                st.session_state.pop("scored_df", None)
                st.rerun()
            if st.button("Exit Sign out"):
                st.session_state.clear()
                st.rerun()
        else:
            if st.button("🔙 Back to sign-in"):
                st.session_state.pop("demo_mode", None)
                st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)
        st.caption("Capstone · Inbox Guardian")

    # -- Apply filters ----                                                  
    filtered = df[
        df["category"].isin(selected_cats) & (df["score"] >= min_score)
    ].reset_index(drop=True)

    # -- Page header ----                                                    
    st.markdown("# Shield Inbox Guardian")
    st.markdown("Real-time phishing, scam, spam, and safety classification for your Gmail inbox.")
    st.markdown("---")

    # -- Summary metrics ----                                                
    total     = len(df)
    n_phish   = len(df[df["category"] == "phishing"])
    n_scam    = len(df[df["category"] == "scam"])
    n_spam    = len(df[df["category"] == "spam"])
    n_safe    = len(df[df["category"] == "safe"])
    avg_score = round(df["score"].mean(), 1)

    cols    = st.columns(6)
    metrics = [
        ("Total Scanned", total,     "#a78bfa"),
        ("Warning Phishing",   n_phish,   "#f87171"),
        ("🚨 Scam",       n_scam,    "#fc8181"),
        ("📬 Spam",       n_spam,    "#fb923c"),
        ("✅ Safe",       n_safe,    "#4ade80"),
        ("Avg Score",    avg_score,  "#60a5fa"),
    ]
    for col, (label, value, color) in zip(cols, metrics):
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value" style="color:{color};">{value}</div>'
                f'<div class="metric-label">{label}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")

    # -- Analytics Section ----                                              
    with st.expander("📊 View Inbox Analytics & Risk Trends", expanded=False):
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown("<p style='font-size:14px; font-weight:600; color:#94a3b8;'>Risk Category Distribution</p>", unsafe_allow_html=True)
            if not filtered.empty:
                import plotly.graph_objects as go
                cat_counts = filtered["category"].value_counts().reindex(["safe", "spam", "scam", "phishing"], fill_value=0)
                
                # Brand matching colors (green, orange, light-red, deep-red)
                colors = ["#4ade80", "#fb923c", "#fc8181", "#f87171"]
                
                fig = go.Figure(data=[go.Bar(
                    x=["Safe", "Spam", "Scam", "Phishing"],
                    y=cat_counts.values,
                    marker_color=colors,
                    text=cat_counts.values,
                    textposition='auto',
                    hovertemplate='%{x}: %{y} emails<extra></extra>'
                )])
                
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=260,
                    font=dict(color='#94a3b8', family='Inter, sans-serif'),
                    yaxis=dict(
                        gridcolor='rgba(255,255,255,0.05)',
                        zeroline=False,
                        tickfont=dict(color='#64748b')
                    ),
                    xaxis=dict(
                        tickfont=dict(color='#94a3b8')
                    )
                )
                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            else:
                st.info("No data available to plot.")
            
        with chart_col2:
            st.markdown("<p style='font-size:14px; font-weight:600; color:#94a3b8;'>Risk Score Spectrum</p>", unsafe_allow_html=True)
            if not filtered.empty:
                import plotly.graph_objects as go
                score_bins = pd.cut(filtered["score"], bins=[-1, 20, 50, 80, 100], labels=["0-20 (Safe)", "21-50 (Low/Spam)", "51-80 (Likely Phish)", "81-100 (High Phish)"])
                score_counts = score_bins.value_counts().sort_index()
                
                # Graduated risk spectrum colors
                colors = ["#4ade80", "#fb923c", "#f87171", "#ef4444"]
                
                fig = go.Figure(data=[go.Bar(
                    x=list(score_counts.index),
                    y=score_counts.values,
                    marker_color=colors,
                    text=score_counts.values,
                    textposition='auto',
                    hovertemplate='%{x}: %{y} emails<extra></extra>'
                )])
                
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=260,
                    font=dict(color='#94a3b8', family='Inter, sans-serif'),
                    yaxis=dict(
                        gridcolor='rgba(255,255,255,0.05)',
                        zeroline=False,
                        tickfont=dict(color='#64748b')
                    ),
                    xaxis=dict(
                        tickfont=dict(color='#94a3b8')
                    )
                )
                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            else:
                st.info("No data available to plot.")

    st.markdown("---")

    # -- Results count ----                                                  
    extra = "  ·  filtered" if len(filtered) < total else ""
    st.markdown(
        f"<div class='section-header'>Showing {len(filtered)} of {total} emails{extra}</div>",
        unsafe_allow_html=True,
    )

    # -- Email cards ----                                                    
    if filtered.empty:
        st.info("No emails match the current filters.")
    else:
        for _, row in filtered.iterrows():
            conf_pct = int(row["confidence"] * 100)
            s_color  = _score_color(row["score"])
            eid      = row.get("email_id", "-")

            # Format the LLM explanation if available
            llm_exp = ""
            if "llm_explanation" in row and pd.notna(row["llm_explanation"]) and row["llm_explanation"]:
                llm_exp = (
                    f'<div class="llm-explanation">'
                    f'{chr(0x1f916)} <b>AI Analysis (Gemini):</b> {_html.escape(str(row["llm_explanation"]))}'
                    f'</div>'
                )

            st.markdown(f"""
            <div class="email-card">
                <div class="card-subject">{_html.escape(str(row['subject']))}</div>
                <div class="card-sender">{chr(0x2709)} {_html.escape(str(row['sender']))}</div>
                <div class="meta-row">
                    {_badge(row['category'])}
                    <span class="score-pill">Score: <span style="color:{s_color}">{row['score']}</span> / 100</span>
                    <span class="conf-pill">Confidence: {conf_pct}%</span>
                    <span class="conf-pill" style="color:#475569; font-size:11px;">#{_html.escape(str(eid))}</span>
                </div>
                <div class="explanation">{chr(0x1f50d)} {_html.escape(str(row['explanation']))}</div>{llm_exp}
            </div>
            """, unsafe_allow_html=True)

    # -- Raw data expander ----                                              
    st.markdown("---")
    with st.expander("Document View raw data table"):
        show_cols = [c for c in
                     ["email_id", "subject", "sender", "score",
                      "category", "confidence", "explanation", "llm_explanation"]
                     if c in filtered.columns]
        st.dataframe(filtered[show_cols], use_container_width=True, hide_index=True)

    # -- Privacy note ----                                                   
    if not is_demo:
        st.markdown(
            '<div class="privacy-note">'
            '🔒 Your emails are scored in real time and never stored. '
            'Session data is cleared when you close this tab.'
            '</div>',
            unsafe_allow_html=True,
        )


# ==============================================================================
#  Sign-in page
# ==============================================================================

def build_oauth_url() -> str:
    params = {
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         GMAIL_SCOPE,
        "access_type":   "online",
        "prompt":        "select_account",
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def render_signin_page() -> None:
    st.markdown(f"""
    <div class="signin-wrapper">
        <div class="signin-logo">{chr(0x1f6e1)}</div>
        <div class="signin-title">Inbox Guardian</div>
        <div class="signin-desc">Score your Gmail inbox for phishing and fraud risk</div>
    </div>
    """, unsafe_allow_html=True)

    _, centre, _ = st.columns([1, 2, 1])
    with centre:
        oauth_url = build_oauth_url()
        st.markdown(f"""
        <div style="text-align:center; margin-top:-20px;">
            <a href="{oauth_url}" class="google-btn" id="google-signin-btn">
                <svg width="20" height="20" viewBox="0 0 48 48">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                    <path fill="none" d="M0 0h48v48H0z"/>
                </svg>
                Sign in with Google
            </a>
            <div class="demo-link">
                No account? <a href="?demo=1" id="view-demo-link">View demo</a>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
#  OAuth callback - exchange code for token
# ==============================================================================

def exchange_code(code: str) -> str:
    """POST to Google's token endpoint; return the access_token string."""
    payload = {
        "code":          code,
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri":  REDIRECT_URI,
        "grant_type":    "authorization_code",
    }
    resp = requests.post(TOKEN_URL, data=payload, timeout=15)
    # FIX Bug 5: The response HTTP status was never checked, so a 4xx/5xx from
    # Google (e.g. wrong client_secret) fell through silently.
    resp.raise_for_status()
    data = resp.json()

    if "access_token" not in data:
        error = data.get("error_description") or data.get("error") or str(data)
        raise ValueError(f"Token exchange failed: {error}")

    return data["access_token"]


# ==============================================================================
#  Main app router
# ==============================================================================

def main() -> None:
    params = st.query_params

    # -- 1. OAuth callback: ?code=... ----                                    
    if "code" in params and "access_token" not in st.session_state:
        code = params["code"]
        with st.spinner("Completing sign-in..."):
            try:
                token = exchange_code(code)
                st.session_state["access_token"] = token
                st.query_params.clear()
                st.rerun()
            except Exception as exc:
                st.query_params.clear()
                st.error(f"Sign-in failed: {exc}")
                if st.button("Try again", key="retry_signin"):
                    st.rerun()
                return

    # -- 2. Demo mode: ?demo=1 ----                                         
    if "demo" in params and params["demo"] == "1":
        st.session_state["demo_mode"] = True
        st.query_params.clear()
        st.rerun()

    # -- 3. Demo dashboard ----                                             
    if st.session_state.get("demo_mode"):
        try:
            df = load_demo_data()
            render_dashboard(df, is_demo=True)
        except FileNotFoundError:
            st.error("Demo data file (results-demo.json) not found.")
        return

    # -- 4. Authenticated dashboard ----                                    
    if "access_token" in st.session_state:
        token = st.session_state["access_token"]

        if "scored_df" not in st.session_state:
            with st.spinner(f"{chr(0x1f50d)} Fetching and scoring your inbox..."):
                try:
                    df = fetch_and_score(token, count=20)
                    st.session_state["scored_df"] = df
                except PermissionError:
                    st.error(
                        "Your Gmail access has expired or been revoked. "
                        "Please sign in again."
                    )
                    st.session_state.clear()
                    if st.button("Sign in again", key="resign_perm"):
                        st.rerun()
                    return
                except Exception as exc:
                    st.error(f"Failed to fetch emails: {exc}")
                    st.session_state.clear()
                    if st.button("Sign in again", key="resign_err"):
                        st.rerun()
                    return

        df = st.session_state["scored_df"]

        if df.empty:
            st.info(f"{chr(0x1f4eb)} No recent emails found in your inbox.")
            with st.sidebar:
                st.markdown(f"## {chr(0x1f6e1)} Inbox Guardian")
                st.markdown("---")
                if st.button("Sign out"):
                    st.session_state.clear()
                    st.rerun()
        else:
            render_dashboard(df, is_demo=False)
        return

    # -- 5. Sign-in page (default) ----                                     
    render_signin_page()


if __name__ == "__main__":
    main()