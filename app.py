"""
AppSec SNOW Ticket Intelligence Dashboard
Futuristic dark-theme Streamlit application for AppSec workload management.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import sqlite3
import os
import io
import json
import hashlib
from datetime import datetime, timedelta

# ─── Optional agent dependencies ──────────────────────────────────────────────
try:
    import anthropic as _anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── CSV helper ───────────────────────────────────────────────────────────────

def safe_read_csv(source) -> pd.DataFrame:
    """Read CSV with automatic encoding detection (handles Windows-1252 / latin-1 files)."""
    for enc in ("utf-8-sig", "latin-1", "cp1252", "utf-8"):
        try:
            if hasattr(source, "read"):
                source.seek(0)
            return pd.read_csv(source, encoding=enc, low_memory=False)
        except (UnicodeDecodeError, Exception):
            continue
    if hasattr(source, "read"):
        source.seek(0)
        raw = source.read()
    else:
        with open(source, "rb") as f:
            raw = f.read()
    return pd.read_csv(io.BytesIO(raw.decode("latin-1", errors="replace").encode("utf-8")), low_memory=False)

# ─── Constants ────────────────────────────────────────────────────────────────

DB_PATH = "appsec_dashboard.db"
CSV_DEFAULT = "sn_grc_application_security.csv"

SLA_THRESHOLDS = {"Critical": 7, "High": 14, "Medium": 21, "Low": 30}

REQUEST_TYPE_RULES = [
    (["dast false positive", "false positive dast"],                              "DAST False Positive reviews"),
    (["manual dast", "manual dynamic"],                                           "Manual DAST Assessments"),
    (["sast false positive", "false positive sast"],                              "SAST False Positive reviews"),
    (["manual sast", "manual static"],                                            "Manual SAST Assessments"),
    (["masa"],                                                                    "MASA Request"),
    (["oss false positive", "open source false positive", "sca false positive"],  "OSS False Positive Reviews"),
    (["security requirement", "design review", "architecture review"],            "Security Requirements/Design Review"),
    (["sign off", "signoff", "sign-off", "security approval", "security sign"],   "Security Sign-off request"),
]

REQUEST_TYPE_VALUES = [
    "DAST False Positive reviews",
    "Manual DAST Assessments",
    "Manual SAST Assessments",
    "MASA Request",
    "OSS False Positive Reviews",
    "SAST False Positive reviews",
    "Security Requirements/Design Review",
    "Security Requirements/Design Review & Validation",
    "Security Sign-off request",
]

BCM_PRIORITY_MAP    = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 1}
APPSEC_PRIORITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                       "tier 1": 4, "tier 2": 3, "tier 3": 2, "tier 4": 1, "": 1}

STATE_COLORS    = {"Pending for Review": "#ffa64d", "Sent for Clarification": "#00d4ff", "Rejected": "#ff4b6e", "Closed": "#00ff88"}
PRIORITY_COLORS = {"Critical": "#ff4b6e", "High": "#ffa64d", "Medium": "#00d4ff", "Low": "#00ff88"}

NEON_GREEN  = "#00ff88"
NEON_BLUE   = "#00d4ff"
NEON_PURPLE = "#b44fff"
NEON_ORANGE = "#ffa64d"
NEON_RED    = "#ff4b6e"
NEON_PINK   = "#ff6eb4"
BG_DARK     = "#070914"
BG_CARD     = "#0d1526"
BORDER_DIM  = "rgba(0,212,255,0.12)"

CHART_COLORS = [NEON_BLUE, NEON_GREEN, NEON_PURPLE, NEON_ORANGE, NEON_RED,
                NEON_PINK, "#ffe066", "#66ffee", "#d966ff", "#ff9966"]

PLOTLY_BASE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color="#8892b0", size=12),
    title_font=dict(family="Orbitron, monospace", color="#cdd6f4", size=13),
    legend=dict(bgcolor="rgba(7,9,20,0.85)", bordercolor=BORDER_DIM, borderwidth=1,
                font=dict(color="#cdd6f4", size=11)),
    margin=dict(l=40, r=24, t=52, b=36),
    xaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor="rgba(255,255,255,0.04)",
               tickfont=dict(color="#8892b0")),
    yaxis=dict(gridcolor="rgba(255,255,255,0.04)", zerolinecolor="rgba(255,255,255,0.04)",
               tickfont=dict(color="#8892b0")),
)

# ─── CSS ──────────────────────────────────────────────────────────────────────

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Inter:wght@300;400;500;600&display=swap');

/* ── Reset & base ── */
:root {{
    --bg: {BG_DARK};
    --card: {BG_CARD};
    --green: {NEON_GREEN};
    --blue: {NEON_BLUE};
    --purple: {NEON_PURPLE};
    --orange: {NEON_ORANGE};
    --red: {NEON_RED};
    --text: #cdd6f4;
    --muted: #6c7a9c;
    --border: {BORDER_DIM};
}}

html, body, .stApp {{ background: var(--bg) !important; }}

/* Hide Streamlit chrome */
header[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stDecoration"],
.stDeployButton,
#MainMenu, footer {{ display: none !important; }}

/* Main content padding */
.block-container {{ padding: 1.5rem 2rem 2rem !important; max-width: 1400px !important; }}

/* ── Sidebar ── */
[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, #04060f 0%, #07091a 60%, #0a0e1a 100%) !important;
    border-right: 1px solid rgba(0,212,255,0.1) !important;
}}
[data-testid="stSidebar"] > div {{ padding-top: 0 !important; }}
[data-testid="stSidebar"] * {{ color: var(--text) !important; }}

/* Nav radio */
[data-testid="stSidebar"] .stRadio > div {{ gap: 2px !important; }}
[data-testid="stSidebar"] .stRadio label {{
    font-family: 'Inter', sans-serif !important;
    font-size: 0.85rem !important;
    color: var(--muted) !important;
    padding: 8px 14px !important;
    border-radius: 8px !important;
    width: 100% !important;
    cursor: pointer;
    transition: all 0.2s !important;
    border: 1px solid transparent !important;
}}
[data-testid="stSidebar"] .stRadio label:hover {{
    color: var(--blue) !important;
    background: rgba(0,212,255,0.07) !important;
    border-color: rgba(0,212,255,0.15) !important;
}}

/* ── Typography ── */
h1 {{
    font-family: 'Orbitron', monospace !important;
    font-size: 1.5rem !important;
    font-weight: 700 !important;
    color: var(--text) !important;
    letter-spacing: 0.06em !important;
    margin-bottom: 2px !important;
}}
h2 {{
    font-family: 'Orbitron', monospace !important;
    font-size: 1.05rem !important;
    color: var(--blue) !important;
    letter-spacing: 0.04em !important;
}}
h3, h4 {{
    font-family: 'Inter', sans-serif !important;
    color: var(--text) !important;
    font-size: 0.95rem !important;
    font-weight: 600 !important;
}}
p, li, label {{ color: var(--text) !important; }}

/* ── KPI Cards ── */
.kpi-row {{ display: flex; gap: 14px; margin-bottom: 14px; }}
.kpi-card {{
    flex: 1;
    background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px 20px 16px;
    position: relative;
    overflow: hidden;
    transition: all 0.25s ease;
    cursor: default;
}}
.kpi-card::after {{
    content: '';
    position: absolute;
    inset: 0;
    border-radius: 14px;
    background: radial-gradient(ellipse at top left, var(--accent-color, rgba(0,212,255,0.06)) 0%, transparent 70%);
    pointer-events: none;
}}
.kpi-card:hover {{
    border-color: var(--accent-color, rgba(0,212,255,0.3));
    transform: translateY(-3px);
    box-shadow: 0 12px 40px rgba(0,0,0,0.4);
}}
.kpi-top-bar {{
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    border-radius: 14px 14px 0 0;
    background: var(--accent-color, {NEON_BLUE});
    opacity: 0.7;
}}
.kpi-icon {{
    font-size: 1.1rem;
    margin-bottom: 8px;
    opacity: 0.8;
}}
.kpi-value {{
    font-family: 'Orbitron', monospace;
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent-color, {NEON_BLUE});
    line-height: 1;
    letter-spacing: -0.02em;
    margin-bottom: 5px;
}}
.kpi-label {{
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    font-weight: 500;
}}
.kpi-sub {{
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 4px;
}}

/* ── Section header ── */
.section-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 24px 0 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
}}
.section-header-title {{
    font-family: 'Orbitron', monospace;
    font-size: 0.8rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--blue);
}}
.section-dot {{
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--blue);
    box-shadow: 0 0 8px var(--blue);
}}

/* ── Page banner ── */
.page-header {{
    background: linear-gradient(135deg, rgba(0,212,255,0.06) 0%, rgba(180,79,255,0.04) 100%);
    border: 1px solid rgba(0,212,255,0.12);
    border-left: 3px solid {NEON_BLUE};
    border-radius: 0 12px 12px 0;
    padding: 14px 20px;
    margin-bottom: 20px;
}}
.page-title {{
    font-family: 'Orbitron', monospace;
    font-size: 1.3rem;
    font-weight: 700;
    color: {NEON_BLUE};
    letter-spacing: 0.06em;
    margin: 0;
}}
.page-sub {{
    font-size: 0.82rem;
    color: var(--muted);
    margin-top: 3px;
}}

/* ── Status pill ── */
.pill {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}}
.pill-open     {{ background: rgba(255,75,110,0.15); color: {NEON_RED};    border: 1px solid rgba(255,75,110,0.35); }}
.pill-assigned {{ background: rgba(255,166,77,0.15); color: {NEON_ORANGE}; border: 1px solid rgba(255,166,77,0.35); }}
.pill-progress {{ background: rgba(0,212,255,0.15);  color: {NEON_BLUE};   border: 1px solid rgba(0,212,255,0.35); }}
.pill-closed   {{ background: rgba(0,255,136,0.15);  color: {NEON_GREEN};  border: 1px solid rgba(0,255,136,0.35); }}

/* ── Info panel ── */
.info-panel {{
    background: rgba(0,212,255,0.05);
    border: 1px solid rgba(0,212,255,0.15);
    border-radius: 10px;
    padding: 14px 18px;
    font-size: 0.85rem;
    color: var(--text);
}}
.warn-panel {{
    background: rgba(255,166,77,0.06);
    border: 1px solid rgba(255,166,77,0.2);
    border-radius: 10px;
    padding: 14px 18px;
    font-size: 0.85rem;
    color: var(--text);
}}
.alert-panel {{
    background: rgba(255,75,110,0.06);
    border: 1px solid rgba(255,75,110,0.2);
    border-left: 3px solid {NEON_RED};
    border-radius: 0 10px 10px 0;
    padding: 14px 18px;
    font-size: 0.85rem;
}}

/* ── Workload badge ── */
.wl-optimal  {{ color: {NEON_GREEN};  font-weight: 600; }}
.wl-moderate {{ color: {NEON_ORANGE}; font-weight: 600; }}
.wl-overload {{ color: {NEON_RED};    font-weight: 600; }}

/* ── Dataframe tweaks ── */
[data-testid="stDataFrame"] iframe {{ border-radius: 8px !important; }}
.stDataFrame {{ border-radius: 8px !important; border: 1px solid var(--border) !important; }}

/* ── Buttons ── */
.stButton > button {{
    background: linear-gradient(135deg, rgba(0,212,255,0.1), rgba(0,255,136,0.08)) !important;
    border: 1px solid {NEON_BLUE} !important;
    color: {NEON_BLUE} !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.03em !important;
    border-radius: 8px !important;
    transition: all 0.25s !important;
    text-transform: none !important;
}}
.stButton > button:hover {{
    background: linear-gradient(135deg, rgba(0,212,255,0.22), rgba(0,255,136,0.15)) !important;
    box-shadow: 0 0 18px rgba(0,212,255,0.25) !important;
    transform: translateY(-1px) !important;
}}
.stDownloadButton > button {{
    background: linear-gradient(135deg, rgba(0,255,136,0.1), rgba(0,212,255,0.08)) !important;
    border: 1px solid {NEON_GREEN} !important;
    color: {NEON_GREEN} !important;
    text-transform: none !important;
}}

/* ── Chat input dark theme ── */
[data-testid="stChatInput"],
[data-testid="stChatInput"] > div,
[data-testid="stChatInput"] > div > div,
[class*="stChatInput"],
section[data-testid="stBottom"],
section[data-testid="stBottom"] > div,
section[data-testid="stBottom"] > div > div {{
    background: #0d1526 !important;
    background-color: #0d1526 !important;
}}
[data-testid="stChatInput"] {{
    border: 1px solid rgba(180,79,255,0.45) !important;
    border-radius: 14px !important;
    box-shadow: 0 0 28px rgba(180,79,255,0.12), inset 0 1px 0 rgba(180,79,255,0.08) !important;
}}
[data-testid="stChatInput"] textarea,
[data-testid="stChatInput"] input {{
    color: #e2eaf8 !important;
    background: #0d1526 !important;
    background-color: #0d1526 !important;
    font-size: 0.88rem !important;
    caret-color: {NEON_PURPLE} !important;
    -webkit-box-shadow: 0 0 0 1000px #0d1526 inset !important;
    -webkit-text-fill-color: #e2eaf8 !important;
}}
[data-testid="stChatInput"] textarea::placeholder,
[data-testid="stChatInput"] input::placeholder {{
    color: #6c7a9c !important;
    font-style: italic !important;
    -webkit-text-fill-color: #6c7a9c !important;
}}
[data-testid="stChatInput"] button {{
    background: rgba(180,79,255,0.2) !important;
    border-radius: 8px !important;
    color: {NEON_PURPLE} !important;
}}
[data-testid="stChatInput"] button:hover {{
    background: rgba(180,79,255,0.4) !important;
}}

/* ── Chat messages ── */
[data-testid="stChatMessage"] {{
    background: rgba(13,21,38,0.7) !important;
    border: 1px solid rgba(0,212,255,0.08) !important;
    border-radius: 14px !important;
    padding: 4px 8px !important;
    margin-bottom: 6px !important;
}}
[data-testid="stChatMessage"][data-testid*="assistant"] {{
    border-color: rgba(180,79,255,0.15) !important;
    background: rgba(180,79,255,0.04) !important;
}}

/* ── Form inputs — control box ── */
.stSelectbox > div > div,
.stMultiSelect > div > div {{
    background: linear-gradient(135deg, rgba(0,212,255,0.08) 0%, rgba(13,21,38,0.98) 100%) !important;
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 8px !important;
    color: #e2eaf8 !important;
    box-shadow: 0 0 10px rgba(0,212,255,0.12), inset 0 1px 0 rgba(0,212,255,0.06) !important;
    transition: border-color 0.2s, box-shadow 0.2s !important;
}}
.stSelectbox > div > div:focus-within,
.stMultiSelect > div > div:focus-within {{
    border-color: {NEON_GREEN} !important;
    box-shadow: 0 0 0 2px rgba(0,255,136,0.18), 0 0 16px rgba(0,255,136,0.12) !important;
}}
/* Selected text & placeholder inside control */
.stSelectbox [data-baseweb="select"] span,
.stMultiSelect [data-baseweb="select"] span,
.stSelectbox [data-baseweb="select"] div,
.stMultiSelect [data-baseweb="select"] div {{
    color: #e2eaf8 !important;
    background: transparent !important;
    font-weight: 500 !important;
}}
/* Placeholder text */
.stSelectbox input::placeholder,
.stMultiSelect input::placeholder {{
    color: #5a6a8a !important;
}}
/* Dropdown arrow icon */
.stSelectbox svg, .stMultiSelect svg {{
    fill: {NEON_BLUE} !important;
}}
/* ── Dropdown popup — nuclear dark override ── */
/* Target every layer the BaseWeb portal renders */
[data-baseweb="popover"],
[data-baseweb="popover"] > div,
[data-baseweb="popover"] > div > div,
[data-baseweb="select-dropdown"],
[data-baseweb="select-dropdown"] > div,
div[role="listbox"],
div[role="listbox"] > div,
ul[data-baseweb="menu"],
ul[data-baseweb="menu"] > div {{
    background-color: #07091a !important;
    background:       #07091a !important;
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 10px !important;
    box-shadow: 0 16px 56px rgba(0,0,0,0.85), 0 0 28px rgba(0,212,255,0.15) !important;
    color: #e2eaf8 !important;
}}
/* Every item row — use all possible selectors */
[data-baseweb="menu"] li,
[data-baseweb="option"],
div[role="option"],
li[role="option"] {{
    background-color: #07091a !important;
    background:       #07091a !important;
    color: #cdd6f4 !important;
    font-size: 0.85rem !important;
    padding: 9px 16px !important;
    border-left: 3px solid transparent !important;
    transition: all 0.15s !important;
}}
/* Hover */
[data-baseweb="menu"] li:hover,
[data-baseweb="option"]:hover,
div[role="option"]:hover,
li[role="option"]:hover {{
    background-color: rgba(0,212,255,0.14) !important;
    background:       rgba(0,212,255,0.14) !important;
    color: {NEON_BLUE} !important;
    border-left-color: {NEON_BLUE} !important;
    cursor: pointer !important;
}}
/* Selected / checked */
[aria-selected="true"],
[data-baseweb="option"][aria-selected="true"],
div[role="option"][aria-selected="true"],
li[role="option"][aria-selected="true"] {{
    background-color: rgba(0,255,136,0.12) !important;
    background:       rgba(0,255,136,0.12) !important;
    color: {NEON_GREEN} !important;
    border-left-color: {NEON_GREEN} !important;
    font-weight: 700 !important;
}}
/* "Select all" header */
[data-baseweb="menu"] li:first-child,
ul[data-baseweb="menu"] > div:first-child {{
    border-bottom: 1px solid rgba(0,212,255,0.2) !important;
    color: {NEON_PURPLE} !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.08em !important;
    background-color: rgba(180,79,255,0.07) !important;
    background:       rgba(180,79,255,0.07) !important;
}}
/* Tooltip inside popup (the "Corporate services IT systems - CWS..." full text) */
div[data-baseweb="tooltip"] > div,
[role="tooltip"] {{
    background-color: #0d1a2e !important;
    background:       #0d1a2e !important;
    color: {NEON_BLUE} !important;
    border: 1px solid rgba(0,212,255,0.35) !important;
    border-radius: 6px !important;
    font-size: 0.82rem !important;
    box-shadow: 0 4px 16px rgba(0,0,0,0.6) !important;
}}
/* Multi-select tags (chips) — cycle vivid colors */
[data-baseweb="tag"] {{
    background: linear-gradient(135deg, rgba(0,212,255,0.2), rgba(180,79,255,0.15)) !important;
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 6px !important;
    color: #e2eaf8 !important;
    box-shadow: 0 0 6px rgba(0,212,255,0.2) !important;
    font-weight: 600 !important;
    font-size: 0.78rem !important;
}}
[data-baseweb="tag"] span {{ color: {NEON_BLUE} !important; font-weight: 700 !important; }}
[data-baseweb="tag"] button {{ color: {NEON_BLUE} !important; opacity: 0.85; }}
[data-baseweb="tag"] button:hover {{ color: {NEON_RED} !important; opacity: 1; }}

/* ── Text input ── */
.stTextInput > div > div > input {{
    background: #0d1526 !important;
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 8px !important;
    color: #e2eaf8 !important;
    box-shadow: 0 0 8px rgba(0,212,255,0.1) !important;
    font-weight: 500 !important;
    font-size: 0.88rem !important;
}}
.stTextInput > div > div > input::placeholder {{
    color: #8892b0 !important;
    font-style: italic !important;
}}
.stTextInput > div > div > input:focus {{
    border-color: {NEON_GREEN} !important;
    box-shadow: 0 0 0 2px rgba(0,255,136,0.18), 0 0 16px rgba(0,255,136,0.1) !important;
}}
/* ── Browser autofill override — prevents white/yellow flash on filled fields ── */
input:-webkit-autofill,
input:-webkit-autofill:hover,
input:-webkit-autofill:focus,
input:-webkit-autofill:active {{
    -webkit-box-shadow: 0 0 0 1000px #0d1526 inset !important;
    -webkit-text-fill-color: #e2eaf8 !important;
    caret-color: #e2eaf8 !important;
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 8px !important;
    transition: background-color 9999s ease-in-out 0s !important;
}}
/* Label text above all inputs */
.stTextInput label, .stSelectbox label,
.stMultiSelect label, .stCheckbox label {{
    color: {NEON_BLUE} !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
    text-shadow: 0 0 8px rgba(0,212,255,0.4) !important;
}}

/* ── File uploader ── */
[data-testid="stFileUploader"] {{
    background: rgba(0,212,255,0.04) !important;
    border: 1px dashed rgba(0,212,255,0.3) !important;
    border-radius: 10px !important;
}}
[data-testid="stFileUploader"] span,
[data-testid="stFileUploader"] p,
[data-testid="stFileDropzoneInstructions"] {{ color: #6c7a9c !important; }}
[data-testid="stFileUploader"] button {{
    background: rgba(0,212,255,0.12) !important;
    border: 1px solid {NEON_BLUE} !important;
    color: {NEON_BLUE} !important;
    border-radius: 6px !important;
}}

/* ── Alerts ── */
.stAlert > div {{ border-radius: 8px !important; }}
div[data-testid="stNotification"] {{ border-radius: 8px !important; }}

/* ── Expander ── */
details summary {{
    background: linear-gradient(135deg, rgba(0,212,255,0.08), rgba(180,79,255,0.05)) !important;
    border: 1px solid rgba(0,212,255,0.4) !important;
    border-radius: 8px !important;
    color: {NEON_BLUE} !important;
    padding: 10px 14px !important;
    font-weight: 600 !important;
    letter-spacing: 0.04em !important;
    box-shadow: 0 0 10px rgba(0,212,255,0.08) !important;
}}
details[open] summary {{
    border-color: {NEON_GREEN} !important;
    color: {NEON_GREEN} !important;
    box-shadow: 0 0 12px rgba(0,255,136,0.12) !important;
}}
details > div {{
    background: rgba(7,9,26,0.92) !important;
    border: 1px solid rgba(0,212,255,0.18) !important;
    border-top: none !important;
    border-radius: 0 0 8px 8px !important;
    padding: 14px !important;
}}

/* ── Checkbox ── */
.stCheckbox > label {{
    color: {NEON_ORANGE} !important;
    font-weight: 600 !important;
    letter-spacing: 0.04em !important;
}}

/* ── Scrollbar ── */
::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: {BG_DARK}; }}
::-webkit-scrollbar-thumb {{ background: rgba(0,212,255,0.25); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: {NEON_BLUE}; }}

/* ── Divider ── */
hr {{ border-color: var(--border) !important; margin: 20px 0 !important; }}

/* ── Sidebar logo ── */
.sidebar-logo {{
    padding: 24px 16px 20px;
    border-bottom: 1px solid rgba(0,212,255,0.08);
    margin-bottom: 12px;
}}
.sidebar-logo-title {{
    font-family: 'Orbitron', monospace;
    font-size: 1rem;
    font-weight: 900;
    background: linear-gradient(135deg, {NEON_BLUE}, {NEON_GREEN});
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: 0.1em;
    line-height: 1.2;
}}
.sidebar-logo-sub {{
    font-size: 0.62rem;
    letter-spacing: 0.2em;
    color: #4a5568;
    text-transform: uppercase;
    margin-top: 4px;
}}

/* ── Quick stats in sidebar ── */
.sidebar-stat {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 0;
    font-size: 0.82rem;
    border-bottom: 1px solid rgba(255,255,255,0.04);
}}
.sidebar-stat-label {{ color: #6c7a9c; }}
.sidebar-stat-value {{ font-weight: 600; font-family: 'Orbitron', monospace; font-size: 0.78rem; }}

/* ── GLOBAL portal dark fix (BaseWeb renders outside .stApp) ── */
body [data-baseweb="popover"],
body [data-baseweb="popover"] *:not(svg):not(path) {{
    background-color: #07091a !important;
    color: #cdd6f4 !important;
}}
body [data-baseweb="popover"] [aria-selected="true"] {{
    background-color: rgba(0,255,136,0.12) !important;
    color: {NEON_GREEN} !important;
    font-weight: 700 !important;
}}
body [data-baseweb="popover"] li:hover,
body [data-baseweb="popover"] [role="option"]:hover {{
    background-color: rgba(0,212,255,0.14) !important;
    color: {NEON_BLUE} !important;
}}
body [data-baseweb="popover"] > div > div > div:first-child > div {{
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 10px !important;
    box-shadow: 0 16px 56px rgba(0,0,0,0.85), 0 0 30px rgba(0,212,255,0.15) !important;
    overflow: hidden !important;
}}
</style>
"""

# ─── SQLite ────────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS ticket_states (
        request_id TEXT PRIMARY KEY, state TEXT NOT NULL,
        priority TEXT DEFAULT 'Medium', notes TEXT DEFAULT '',
        updated_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS assignments (
        request_id TEXT PRIMARY KEY, assigned_to TEXT NOT NULL,
        assigned_group TEXT, assigned_at TEXT NOT NULL)""")
    conn.commit(); conn.close()


def get_all_states():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT request_id, state, priority FROM ticket_states", conn)
    conn.close()
    return df.set_index("request_id").to_dict("index") if not df.empty else {}


def update_ticket_state(request_id, state, priority="Medium", notes=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO ticket_states VALUES(?,?,?,?,?)
        ON CONFLICT(request_id) DO UPDATE SET state=excluded.state,
        priority=excluded.priority, notes=excluded.notes, updated_at=excluded.updated_at""",
        (request_id, state, priority, notes, datetime.now().isoformat()))
    conn.commit(); conn.close()


def save_assignment(request_id, assigned_to, assigned_group=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO assignments VALUES(?,?,?,?)
        ON CONFLICT(request_id) DO UPDATE SET assigned_to=excluded.assigned_to,
        assigned_group=excluded.assigned_group, assigned_at=excluded.assigned_at""",
        (request_id, assigned_to, assigned_group, datetime.now().isoformat()))
    conn.commit(); conn.close()


def get_all_assignments():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql("SELECT request_id, assigned_to, assigned_group FROM assignments", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df.set_index("request_id").to_dict("index") if not df.empty else {}

# ─── Data helpers ──────────────────────────────────────────────────────────────

def _is_blank(val):
    return str(val).strip().lower() in ("", "nan", "none", "null", "n/a", "-")


def detect_request_type(description, assigned_group=""):
    text = str(description).lower() if description else ""
    for keywords, label in REQUEST_TYPE_RULES:
        if any(kw in text for kw in keywords):
            return label
    return ""


def _stable_state(request_id):
    h = int(hashlib.md5(str(request_id).encode()).hexdigest(), 16) % 100
    if h < 18: return "Closed"
    if h < 38: return "Rejected"
    if h < 58: return "Sent for Clarification"
    return "Pending for Review"


def process_data(df: pd.DataFrame, state_overrides: dict, assign_overrides: dict) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    required = ["Request ID", "Assigned To", "Assigned Group",
                "Request Type", "State", "BCM criticality",
                "Application Security Prioritization", "App Exposure",
                "Application Name", "Application Status",
                "Portfolio Name", "Application ID",
                "Signed-off By(ITSecurityChamp)"]
    for col in required:
        if col not in df.columns:
            df[col] = ""

    for col in df.select_dtypes(include="object").columns:
        df[col] = df[col].fillna("").astype(str).str.strip()

    # Request Type — use CSV column directly; fall back to keyword detection only if blank
    df["Request Type"] = df.apply(
        lambda r: r["Request Type"] if r["Request Type"].strip() != ""
        else detect_request_type(r.get("Assessment Request Description", ""), r["Assigned Group"]),
        axis=1)

    # Priority
    def score(row):
        b = BCM_PRIORITY_MAP.get(str(row["BCM criticality"]).strip().lower(), 1)
        a = APPSEC_PRIORITY_MAP.get(str(row["Application Security Prioritization"]).strip().lower(), 1)
        return round(b * 0.6 + a * 0.4, 2)

    df["Priority Score"] = df.apply(score, axis=1)
    df["Priority"] = df["Priority Score"].apply(
        lambda s: "Critical" if s >= 3.4 else ("High" if s >= 2.5 else ("Medium" if s >= 1.5 else "Low")))
    df["SLA Days"] = df["Priority"].map(SLA_THRESHOLDS)

    # Created Date — reproducible spread over last 90 days
    rng = np.random.default_rng(42)
    today = datetime.now().date()
    offsets = rng.integers(1, 90, size=len(df))
    df["Created Date"] = [today - timedelta(days=int(d)) for d in offsets]
    df["Days Open"] = (pd.Timestamp("today").normalize() - pd.to_datetime(df["Created Date"])).dt.days
    df["SLA Breached"] = df["Days Open"] > df["SLA Days"]

    # State — use CSV column directly; DB overrides take priority; blank Assigned To → Pending for Review
    valid_states = set(STATE_COLORS.keys())
    def get_state(row):
        rid = row["Request ID"]
        if rid in state_overrides:
            return state_overrides[rid]["state"]
        if _is_blank(row["Assigned To"]):
            return "Pending for Review"
        csv_state = row["State"].strip()
        if csv_state in valid_states:
            return csv_state
        return _stable_state(rid)

    df["State"] = df.apply(get_state, axis=1)

    # Apply DB assignment overrides
    for rid, asgn in assign_overrides.items():
        mask = df["Request ID"] == rid
        if mask.any():
            df.loc[mask, "Assigned To"] = asgn["assigned_to"]
            if asgn.get("assigned_group"):
                df.loc[mask, "Assigned Group"] = asgn["assigned_group"]
            df.loc[mask & (df["State"] == "Pending for Review"), "State"] = "Sent for Clarification"

    # Primary group for grouping
    df["Primary Group"] = df["Assigned Group"].apply(
        lambda x: x.split(",")[0].strip() if x and not _is_blank(x) else "Unassigned")

    # Clean Assigned To for workload  — blank → empty string
    df["Assigned To Clean"] = df["Assigned To"].apply(lambda x: "" if _is_blank(x) else x.strip())

    return df

# ─── Chart builder ────────────────────────────────────────────────────────────

def _layout(**extra):
    d = dict(**PLOTLY_BASE)
    d.update(extra)
    return d


def kpi_card(value, label, color=NEON_BLUE, icon="", sub=""):
    """Returns a self-contained HTML card using only inline styles — no CSS class dependency."""
    sub_html = (f"<div style='font-size:0.73rem;color:#6c7a9c;margin-top:5px'>{sub}</div>"
                if sub else "")
    return (
        f"<div style='background:linear-gradient(135deg,rgba(255,255,255,0.04) 0%,"
        f"rgba(255,255,255,0.01) 100%);border:1px solid {color}33;"
        f"border-top:3px solid {color};border-radius:14px;"
        f"padding:18px 20px 15px;height:100%;box-sizing:border-box'>"
        f"<div style='font-size:1.05rem;margin-bottom:8px;opacity:0.7'>{icon}</div>"
        f"<div style='font-family:Orbitron,monospace;font-size:1.85rem;font-weight:700;"
        f"color:{color};line-height:1;letter-spacing:-0.01em;margin-bottom:5px'>{value}</div>"
        f"<div style='font-size:0.68rem;text-transform:uppercase;letter-spacing:0.12em;"
        f"color:#6c7a9c;font-weight:500'>{label}</div>"
        f"{sub_html}"
        f"</div>"
    )


def render_kpis(cards):
    """Render KPI cards using st.columns — one st.markdown per card, always works in Streamlit.
    cards: list of (value, label, color, icon, sub) tuples
    """
    cols = st.columns(len(cards))
    for col, args in zip(cols, cards):
        with col:
            st.markdown(kpi_card(*args), unsafe_allow_html=True)


def section_hdr(title, icon=""):
    return f"""<div class="section-header">
        <div class="section-dot"></div>
        <div class="section-header-title">{icon} {title}</div>
    </div>"""


def page_banner(title, subtitle, color=NEON_BLUE):
    return f"""<div class="page-header" style="border-left-color:{color}">
        <div class="page-title" style="color:{color}">{title}</div>
        <div class="page-sub">{subtitle}</div>
    </div>"""


def horizontal_bar(series: pd.Series, title: str, color_scale=None):
    vals = series.values.tolist()
    labels = series.index.tolist()
    if color_scale is None:
        mx = max(vals) if vals else 1
        colors = [f"rgba(0,{int(212*(v/mx))},{int(255*(v/mx))},0.75)" for v in vals]
    else:
        colors = color_scale
    fig = go.Figure(go.Bar(
        y=labels, x=vals, orientation="h",
        marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.06)", width=0.5)),
        text=vals, textposition="outside",
        textfont=dict(color="#cdd6f4", size=11),
    ))
    fig.update_layout(title=title, xaxis_title="", **_layout(height=max(320, len(series)*34+80)))
    return fig


def vertical_bar(series: pd.Series, title: str):
    fig = go.Figure(go.Bar(
        x=series.index.tolist(), y=series.values.tolist(),
        marker=dict(color=CHART_COLORS[:len(series)],
                    line=dict(color="rgba(255,255,255,0.06)", width=0.5)),
        text=series.values.tolist(), textposition="outside",
        textfont=dict(color="#cdd6f4", size=11),
    ))
    fig.update_layout(title=title, **_layout())
    return fig


def donut(series: pd.Series, title: str, colors=None, center_text=""):
    c = colors or CHART_COLORS[:len(series)]
    total = series.sum()
    fig = go.Figure(go.Pie(
        labels=series.index.tolist(), values=series.values.tolist(),
        hole=0.6,
        marker=dict(colors=c, line=dict(color=BG_DARK, width=2)),
        textfont=dict(color="#cdd6f4", size=11),
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
    ))
    annot_text = center_text or f"<b>{total:,}</b>"
    fig.update_layout(
        title=title,
        **_layout(),
        annotations=[dict(text=annot_text, x=0.5, y=0.5,
            font=dict(family="Orbitron, monospace", size=20, color=NEON_BLUE),
            showarrow=False)],
    )
    return fig

# ─── Page: Overview ───────────────────────────────────────────────────────────

def page_overview(df: pd.DataFrame):
    st.markdown(page_banner(
        "AppSec Operations Overview",
        f"Live pipeline view — {datetime.now().strftime('%d %b %Y, %H:%M')}",
        NEON_BLUE), unsafe_allow_html=True)

    total    = len(df)
    pending_t  = (df["State"] == "Pending for Review").sum()
    clarify_t  = (df["State"] == "Sent for Clarification").sum()
    rejected_t = (df["State"] == "Rejected").sum()
    closed_t   = (df["State"] == "Closed").sum()
    unasgn_t   = (df["Assigned To Clean"] == "").sum()
    breached   = int(df["SLA Breached"].sum())
    breach_pct = breached / total * 100 if total else 0

    pending_pct = f"{pending_t/total*100:.0f}% of total"
    closed_pct  = f"{closed_t/total*100:.0f}% complete"
    ontime_pct  = f"{(total-breached)/total*100:.0f}% compliance"
    breach_lbl  = f"{breach_pct:.1f}% breach rate"

    render_kpis([
        (f"{total:,}",      "Total Tickets",         NEON_BLUE,   "📋", ""),
        (f"{pending_t:,}",  "Pending for Review",    NEON_ORANGE, "🕐", pending_pct),
        (f"{clarify_t:,}",  "Sent for Clarification",NEON_BLUE,   "💬", ""),
        (f"{closed_t:,}",   "Closed",                NEON_GREEN,  "✅", closed_pct),
    ])
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    render_kpis([
        (f"{unasgn_t:,}",       "Unassigned",  NEON_ORANGE, "⚠️", "needs assignment"),
        (f"{rejected_t:,}",     "Rejected",    NEON_RED,    "❌", ""),
        (f"{breached:,}",       "SLA Breached",NEON_RED,    "🚨", breach_lbl),
        (f"{total-breached:,}", "On-Time",     NEON_GREEN,  "🎯", ontime_pct),
    ])

    st.markdown(section_hdr("State Distribution & Request Types", ""), unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1])
    with c1:
        state_counts = df["State"].value_counts()
        colors = [STATE_COLORS.get(s, NEON_BLUE) for s in state_counts.index]
        fig = donut(state_counts, "Ticket State Distribution", colors=colors)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        type_counts = df["Request Type"].value_counts().head(10)
        st.plotly_chart(horizontal_bar(type_counts, "Tickets by Request Type"), use_container_width=True)

    st.markdown(section_hdr("Group Distribution"), unsafe_allow_html=True)

    grp_counts = df["Primary Group"].value_counts().head(8)
    st.plotly_chart(vertical_bar(grp_counts, "Tickets by Assigned Group"), use_container_width=True)

# ─── Page: Workload Distribution ─────────────────────────────────────────────

def page_workload(df: pd.DataFrame):
    st.markdown(page_banner(
        "Workload Distribution",
        "Engineer assignment breakdown by status and severity — filtered by Assigned Group",
        NEON_PURPLE), unsafe_allow_html=True)

    # ── Group filter ──────────────────────────────────────────────────────────
    all_groups = sorted(df["Primary Group"].replace("Unassigned", float("nan")).dropna().unique())
    selected_group = st.selectbox("Filter by Assigned Group", ["All Groups"] + all_groups, key="wl_group")

    # Engineers who belong to ITIT-ITSSDLC must never appear under ITIT-CSAppSec
    ITSSDLC_GROUP  = "ITIT-ITSSDLC-Global-Support-L1"
    CSAPPSEC_GROUP = "ITIT-CSAppSec-Global-Support-L1"
    itssdlc_engs = set(
        df[(df["Primary Group"] == ITSSDLC_GROUP) & (df["Assigned To Clean"] != "")]["Assigned To Clean"].unique()
    )

    if selected_group == "All Groups":
        wdf = df[df["Assigned To Clean"] != ""].copy()
    elif selected_group == CSAPPSEC_GROUP:
        wdf = df[
            (df["Primary Group"] == CSAPPSEC_GROUP) &
            (df["Assigned To Clean"] != "") &
            (~df["Assigned To Clean"].isin(itssdlc_engs))
        ].copy()
    else:
        wdf = df[(df["Primary Group"] == selected_group) & (df["Assigned To Clean"] != "")].copy()

    if wdf.empty:
        st.markdown('<div class="warn-panel">No assigned tickets found for this group.</div>',
                    unsafe_allow_html=True)
        return

    # KPIs
    total_eng    = wdf["Assigned To Clean"].nunique()
    total_tickets = len(wdf)
    open_tickets  = int((wdf["State"].isin(["Pending for Review", "Sent for Clarification"])).sum())
    high_sev      = int((wdf["Priority"].isin(["Critical", "High"])).sum())

    render_kpis([
        (f"{total_tickets:,}", "Total Assigned",   NEON_PURPLE, "📋", f"across {total_eng} engineers"),
        (f"{total_eng:,}",     "Active Engineers",  NEON_BLUE,   "👷", "with open tickets"),
        (f"{open_tickets:,}",  "Open Issues",       NEON_ORANGE, "🕐", "Pending / Clarification"),
        (f"{high_sev:,}",      "High/Critical",     NEON_RED,    "🚨", "needs attention"),
    ])

    # ── Grouped Bar: All Engineers vs Ticket Count by Status ─────────────────
    st.markdown(section_hdr("Engineer Workload by Status", "📊"), unsafe_allow_html=True)

    status_order  = ["Pending for Review", "Sent for Clarification", "Rejected", "Closed"]
    status_colors = [NEON_ORANGE, NEON_BLUE, NEON_RED, NEON_GREEN]

    # All engineers sorted by total ticket count descending
    all_engs = (wdf.groupby("Assigned To Clean").size()
                   .sort_values(ascending=False)
                   .index.tolist())

    eng_status = (wdf.groupby(["Assigned To Clean", "State"])
                     .size()
                     .reset_index(name="Count"))

    fig_bar = go.Figure()
    for status, color in zip(status_order, status_colors):
        s = eng_status[eng_status["State"] == status]
        counts = {row["Assigned To Clean"]: row["Count"] for _, row in s.iterrows()}
        y_vals = [counts.get(e, 0) for e in all_engs]
        fig_bar.add_trace(go.Bar(
            name=status,
            x=all_engs,
            y=y_vals,
            marker_color=color,
            opacity=0.85,
            text=[v if v > 0 else "" for v in y_vals],
            textposition="inside",
            textfont=dict(color="#ffffff", size=10),
        ))

    fig_bar.update_layout(
        title="All Engineers — Ticket Count split by Status",
        barmode="group",
        xaxis_tickangle=-40,
        **_layout(height=max(420, len(all_engs) * 18 + 120)),
    )
    st.plotly_chart(fig_bar, use_container_width=True)

    # ── Summary Table ─────────────────────────────────────────────────────────
    st.markdown(section_hdr("Engineer Summary Table", "📋"), unsafe_allow_html=True)

    eng_group = (wdf.groupby(["Assigned To Clean", "Primary Group"])
                    .size().reset_index(name="_n")
                    .sort_values("_n", ascending=False)
                    .drop_duplicates("Assigned To Clean")
                    .set_index("Assigned To Clean")["Primary Group"])

    summary = (wdf.groupby("Assigned To Clean")
                  .agg(
                      Total_Assigned=("Request ID", "count"),
                      Open_Issues=("State", lambda x: (x.isin(["Pending for Review", "Sent for Clarification"])).sum()),
                  )
                  .reset_index()
                  .rename(columns={
                      "Assigned To Clean": "Engineer",
                      "Total_Assigned":    "Total Assigned",
                      "Open_Issues":       "Open Issues",
                  })
                  .sort_values("Total Assigned", ascending=False)
                  .reset_index(drop=True))

    summary["Assigned Group"] = summary["Engineer"].map(eng_group)

    def workload_label(n):
        if n <= 5:  return "Optimal"
        if n <= 10: return "Moderate"
        return "Overloaded"

    summary["Workload"] = summary["Total Assigned"].apply(workload_label)

    st.dataframe(
        summary[["Engineer", "Assigned Group", "Total Assigned", "Open Issues", "Workload"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Total Assigned": st.column_config.NumberColumn(format="%d"),
            "Open Issues":    st.column_config.NumberColumn(format="%d"),
        },
    )

    buf = io.StringIO()
    summary.to_csv(buf, index=False)
    st.download_button(
        "Export Summary CSV", buf.getvalue(),
        f"workload_summary_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", "text/csv",
        key="wl_export")


# ─── Page: Unassigned Queue ────────────────────────────────────────────────────

def page_unassigned(df: pd.DataFrame):
    st.markdown(page_banner(
        "Unassigned Queue",
        "Pending for Review tickets awaiting assignment — sorted by priority and age",
        NEON_ORANGE), unsafe_allow_html=True)

    unassigned = df[
        (df["State"] == "Pending for Review") & (df["Assigned To Clean"] == "")
    ].copy().sort_values(["Priority Score", "Days Open"], ascending=[False, False])

    total_u  = len(unassigned)
    crit_u   = (unassigned["Priority"] == "Critical").sum()
    breach_u = int(unassigned["SLA Breached"].sum())

    render_kpis([
        (f"{total_u:,}",  "Unassigned Tickets", NEON_ORANGE, "📭", ""),
        (f"{crit_u:,}",   "Critical Priority",  NEON_RED,    "🚨", "immediate action needed"),
        (f"{breach_u:,}", "SLA Breached",        NEON_RED,    "⏰", "past SLA deadline"),
    ])

    if unassigned.empty:
        st.markdown('<div class="info-panel">All tickets are assigned. No open unassigned tickets.</div>',
                    unsafe_allow_html=True)
        return

    st.markdown(section_hdr("Filter Queue"), unsafe_allow_html=True)

    f1, f2, f3 = st.columns(3)
    with f1:
        prio_f = st.multiselect("Priority", ["Critical", "High", "Medium", "Low"], key="uq_prio")
    with f2:
        type_f = st.multiselect("Request Type", sorted(unassigned["Request Type"].unique()), key="uq_type")
    with f3:
        breach_only = st.checkbox("SLA Breached only", key="uq_breach")

    filtered = unassigned.copy()
    if prio_f:       filtered = filtered[filtered["Priority"].isin(prio_f)]
    if type_f:       filtered = filtered[filtered["Request Type"].isin(type_f)]
    if breach_only:  filtered = filtered[filtered["SLA Breached"]]

    st.markdown(f'<div style="font-size:0.82rem;color:#6c7a9c;margin-bottom:8px">'
                f'Showing <b style="color:#cdd6f4">{len(filtered)}</b> tickets</div>',
                unsafe_allow_html=True)

    show_cols = [c for c in ["Request ID", "Application ID", "Portfolio Name",
                             "Application Name", "Request Type", "State",
                             "App Exposure", "Application Security Prioritization",
                             "Assigned Group", "SLA Breached"] if c in filtered.columns]
    st.dataframe(filtered[show_cols], use_container_width=True, hide_index=True)

    st.markdown(section_hdr("Quick Assign"), unsafe_allow_html=True)

    all_engineers = sorted(df[df["Assigned To Clean"] != ""]["Assigned To Clean"].unique())
    if not all_engineers:
        st.warning("No engineers found in dataset to assign to.")
        return

    qa1, qa2, qa3 = st.columns([3, 3, 1])
    with qa1:
        sel_ticket = st.selectbox("Select Ticket", filtered["Request ID"].tolist() if not filtered.empty else [], key="qa_ticket")
    with qa2:
        sel_eng = st.selectbox("Assign To", all_engineers, key="qa_eng")
    with qa3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Assign", key="qa_btn") and sel_ticket:
            update_ticket_state(sel_ticket, "Assigned")
            save_assignment(sel_ticket, sel_eng)
            del st.session_state["df_raw"], st.session_state["df_processed"]
            st.success(f"Assigned **{sel_ticket}** → **{sel_eng}**")
            st.rerun()

# ─── Page: Ticket Tracker ──────────────────────────────────────────────────────

def page_tracker(df: pd.DataFrame):
    st.markdown(page_banner(
        "Ticket Tracker",
        "Full searchable registry — filter, export, and update ticket states",
        NEON_GREEN), unsafe_allow_html=True)

    st.markdown(section_hdr("Search & Filter"), unsafe_allow_html=True)

    fc1, fc2, fc3 = st.columns(3)
    with fc1: search    = st.text_input("Search", placeholder="App name / Request ID...", key="tr_s")
    with fc2: state_f   = st.multiselect("State", ["Closed","Pending for Review","Rejected","Sent for Clarification"], key="tr_st")
    _rt_in_data = sorted(df["Request Type"].replace("", float("nan")).dropna().unique())
    _rt_opts = sorted(set(REQUEST_TYPE_VALUES) | set(_rt_in_data)) + ["(Blanks)"]
    with fc3: type_f    = st.multiselect("Request Type", _rt_opts, key="tr_ty")

    fc4, fc5, fc6 = st.columns(3)
    with fc4: portfolio_f = st.multiselect("Portfolio Name", sorted(df["Portfolio Name"].dropna().replace("", float("nan")).dropna().unique()), key="tr_pf")
    with fc5: appid_f     = st.multiselect("Application ID", sorted(df["Application ID"].dropna().replace("", float("nan")).dropna().unique()), key="tr_ai")
    with fc6: group_f     = st.multiselect("Assigned Group",  sorted(df["Primary Group"].dropna().unique()), key="tr_gr")

    filtered = df.copy()
    if search:
        m = (filtered["Application Name"].str.contains(search, case=False, na=False) |
             filtered["Request ID"].str.contains(search, case=False, na=False) |
             filtered["Application ID"].str.contains(search, case=False, na=False))
        filtered = filtered[m]
    if state_f:     filtered = filtered[filtered["State"].isin(state_f)]
    if type_f:
        named = [v for v in type_f if v != "(Blanks)"]
        if "(Blanks)" in type_f and named:
            filtered = filtered[filtered["Request Type"].isin(named) | (filtered["Request Type"] == "")]
        elif "(Blanks)" in type_f:
            filtered = filtered[filtered["Request Type"] == ""]
        else:
            filtered = filtered[filtered["Request Type"].isin(named)]
    if portfolio_f: filtered = filtered[filtered["Portfolio Name"].isin(portfolio_f)]
    if appid_f:     filtered = filtered[filtered["Application ID"].isin(appid_f)]
    if group_f:     filtered = filtered[filtered["Primary Group"].isin(group_f)]

    st.markdown(f'<div style="font-size:0.82rem;color:#6c7a9c;margin-bottom:8px">'
                f'Showing <b style="color:#cdd6f4">{len(filtered):,}</b> of '
                f'<b style="color:#cdd6f4">{len(df):,}</b> tickets</div>', unsafe_allow_html=True)

    show_cols = [c for c in ["Request ID","Application ID","Portfolio Name","Application Name",
                             "Request Type","State","Assigned To","Assigned Group",
                             "App Exposure","Application Security Prioritization",
                             "Signed-off By(ITSecurityChamp)","SLA Breached"] if c in filtered.columns]
    st.dataframe(filtered[show_cols], use_container_width=True, hide_index=True)

    ec1, ec2 = st.columns([1, 4])
    with ec1:
        buf = io.StringIO()
        filtered[show_cols].to_csv(buf, index=False)
        st.download_button("Export CSV", buf.getvalue(),
                           f"appsec_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", "text/csv")

    st.markdown(section_hdr("Update Ticket State"), unsafe_allow_html=True)

    with st.expander("Click to expand state updater"):
        u1, u2, u3 = st.columns([3, 3, 1])
        with u1: upd_id    = st.selectbox("Ticket", filtered["Request ID"].tolist(), key="upd_id")
        with u2: upd_state = st.selectbox("State",  ["Closed","Pending for Review","Rejected","Sent for Clarification"], key="upd_st")
        with u3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Update", key="upd_btn") and upd_id:
                update_ticket_state(upd_id, upd_state)
                del st.session_state["df_raw"], st.session_state["df_processed"]
                st.success(f"Updated {upd_id} → {upd_state}")
                st.rerun()

# ─── Page: SLA & Analytics ────────────────────────────────────────────────────

def page_analytics(df: pd.DataFrame):
    st.markdown(page_banner(
        "SLA & Performance Analytics",
        "Resolution performance, SLA compliance, and trend analysis",
        NEON_RED), unsafe_allow_html=True)

    closed = df[df["State"] == "Closed"]
    active = df[df["State"] != "Closed"]
    total  = len(df)

    breach_rate  = df["SLA Breached"].sum() / total * 100 if total else 0
    avg_open     = df["Days Open"].mean()
    avg_res      = closed["Days Open"].mean() if not closed.empty else 0
    on_time      = total - int(df["SLA Breached"].sum())

    breached_count = total - on_time
    compliant_pct  = f"{on_time/total*100:.0f}% compliant"
    render_kpis([
        (f"{breach_rate:.1f}%", "SLA Breach Rate", NEON_RED,    "🚨", f"{breached_count} tickets"),
        (f"{avg_open:.1f}d",    "Avg Days Open",   NEON_ORANGE, "📅", ""),
        (f"{avg_res:.1f}d",     "Avg Resolution",  NEON_BLUE,   "⏱️", "closed tickets"),
        (f"{on_time:,}",        "On-Time Tickets", NEON_GREEN,  "✅", compliant_pct),
    ])

    st.markdown(section_hdr("SLA Compliance by Priority"), unsafe_allow_html=True)
    c1, c2 = st.columns(2)

    with c1:
        prio_order = ["Critical", "High", "Medium", "Low"]
        sla_df = df.groupby("Priority").agg(
            Total=("Request ID","count"), Breached=("SLA Breached","sum")).reindex(prio_order).fillna(0)
        sla_df["On Time"] = sla_df["Total"] - sla_df["Breached"]
        fig1 = go.Figure()
        fig1.add_trace(go.Bar(name="On Time",  x=sla_df.index.tolist(), y=sla_df["On Time"].tolist(),  marker_color=NEON_GREEN, opacity=0.85))
        fig1.add_trace(go.Bar(name="Breached", x=sla_df.index.tolist(), y=sla_df["Breached"].tolist(), marker_color=NEON_RED,   opacity=0.85))
        fig1.update_layout(title="SLA Compliance by Priority", barmode="stack", **_layout())
        st.plotly_chart(fig1, use_container_width=True)

    with c2:
        breach_type = df[df["SLA Breached"]].groupby("Request Type").size().sort_values(ascending=False).head(10)
        if not breach_type.empty:
            st.plotly_chart(horizontal_bar(breach_type, "Top SLA Breaches by Request Type"), use_container_width=True)
        else:
            st.markdown('<div class="info-panel">No SLA breaches found.</div>', unsafe_allow_html=True)

    st.markdown(section_hdr("Days Open Distribution & Priority Scatter"), unsafe_allow_html=True)
    c3, c4 = st.columns(2)

    with c3:
        fig3 = go.Figure(go.Histogram(
            x=active["Days Open"].dropna().tolist(), nbinsx=25,
            marker=dict(color=NEON_BLUE, opacity=0.75, line=dict(color=BG_DARK, width=0.5))))
        fig3.update_layout(title="Days Open — Active Tickets", xaxis_title="Days Open",
                           yaxis_title="Count", **_layout())
        st.plotly_chart(fig3, use_container_width=True)

    with c4:
        sample = df.sample(min(600, len(df)), random_state=42)
        fig4 = go.Figure()
        for prio, col in PRIORITY_COLORS.items():
            s = sample[sample["Priority"] == prio]
            if s.empty: continue
            fig4.add_trace(go.Scatter(
                x=s["Priority Score"].tolist(), y=s["Days Open"].tolist(),
                mode="markers", name=prio,
                marker=dict(color=col, size=7, opacity=0.65, line=dict(color=BG_DARK, width=0.5)),
                text=s["Application Name"].tolist(),
                hovertemplate="%{text}<br>Score: %{x:.2f}<br>Days: %{y}<extra></extra>",
            ))
        fig4.add_hline(y=14, line=dict(color=NEON_RED, dash="dot"),
                       annotation_text="High SLA (14d)", annotation_font_color=NEON_RED)
        fig4.update_layout(title="Priority Score vs Days Open", **_layout())
        st.plotly_chart(fig4, use_container_width=True)

    st.markdown(section_hdr("Monthly Volume & Breach Trend"), unsafe_allow_html=True)

    df_m = df.copy()
    df_m["Month"] = pd.to_datetime(df_m["Created Date"]).dt.to_period("M").astype(str)
    monthly = df_m.groupby("Month").agg(Total=("Request ID","count"), Breached=("SLA Breached","sum"))
    monthly["Breach %"] = (monthly["Breached"] / monthly["Total"] * 100).round(1)

    fig5 = go.Figure()
    fig5.add_trace(go.Bar(x=monthly.index.tolist(), y=monthly["Total"].tolist(),
                          name="Total", marker_color="rgba(0,212,255,0.25)", opacity=0.9))
    fig5.add_trace(go.Bar(x=monthly.index.tolist(), y=monthly["Breached"].tolist(),
                          name="Breached", marker_color=NEON_RED, opacity=0.8))
    fig5.add_trace(go.Scatter(x=monthly.index.tolist(), y=monthly["Breach %"].tolist(),
                              name="Breach %", yaxis="y2",
                              line=dict(color=NEON_ORANGE, width=2.5, shape="spline"),
                              mode="lines+markers",
                              marker=dict(color=NEON_ORANGE, size=6),
                              hovertemplate="%{y:.1f}%<extra>Breach %</extra>"))
    fig5.update_layout(
        title="Monthly Ticket Volume & SLA Breach Rate", barmode="overlay",
        yaxis2=dict(overlaying="y", side="right", title="Breach %",
                    tickfont=dict(color=NEON_ORANGE), gridcolor="rgba(0,0,0,0)"),
        **_layout(),
    )
    st.plotly_chart(fig5, use_container_width=True)



# ─── Agent helpers ────────────────────────────────────────────────────────────

def _get_api_key() -> str:
    """Resolve Anthropic API key: session state → env var → Streamlit secrets."""
    if st.session_state.get("anthropic_api_key"):
        return st.session_state["anthropic_api_key"]
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        try:
            key = st.secrets.get("ANTHROPIC_API_KEY", "")
        except Exception:
            pass
    return key


def _build_data_context(df: pd.DataFrame) -> str:
    """Build a compact plain-text summary of the dataframe for AI system prompts."""
    total   = len(df)
    pending = int((df["State"] == "Pending for Review").sum())
    clarify = int((df["State"] == "Sent for Clarification").sum())
    closed  = int((df["State"] == "Closed").sum())
    rejected= int((df["State"] == "Rejected").sum())
    unassigned = int((df["Assigned To Clean"] == "").sum())
    breached   = int(df["SLA Breached"].sum())
    breach_pct = breached / total * 100 if total else 0
    avg_days   = df["Days Open"].mean()

    # Top engineers by load
    eng_load = (df[df["Assigned To Clean"] != ""]
                .groupby("Assigned To Clean").size()
                .sort_values(ascending=False).head(10))

    # Request types
    rt_counts = df["Request Type"].replace("", "Unknown").value_counts().head(8)

    # Group distribution
    grp_counts = df["Primary Group"].value_counts().head(6)

    # SLA by priority
    sla_df = df.groupby("Priority").agg(
        Total=("Request ID", "count"),
        Breached=("SLA Breached", "sum")
    ).reindex(["Critical", "High", "Medium", "Low"]).fillna(0)

    lines = [
        f"=== AppSec ServiceNow Ticket Dashboard — Live Data Snapshot ({datetime.now().strftime('%d %b %Y %H:%M')}) ===",
        "",
        "## Summary",
        f"- Total tickets: {total:,}",
        f"- Pending for Review: {pending:,}",
        f"- Sent for Clarification: {clarify:,}",
        f"- Closed: {closed:,}",
        f"- Rejected: {rejected:,}",
        f"- Unassigned: {unassigned:,}",
        f"- SLA Breached: {breached:,} ({breach_pct:.1f}%)",
        f"- Average days open: {avg_days:.1f}",
        "",
        "## Engineer Workload (Top 10 by ticket count)",
    ]
    for eng, cnt in eng_load.items():
        lines.append(f"  - {eng}: {cnt} tickets")

    lines += ["", "## Request Type Breakdown"]
    for rt, cnt in rt_counts.items():
        lines.append(f"  - {rt}: {cnt}")

    lines += ["", "## Group Distribution"]
    for grp, cnt in grp_counts.items():
        lines.append(f"  - {grp}: {cnt}")

    lines += ["", "## SLA by Priority"]
    for prio in ["Critical", "High", "Medium", "Low"]:
        if prio in sla_df.index:
            t = int(sla_df.loc[prio, "Total"])
            b = int(sla_df.loc[prio, "Breached"])
            pct = b / t * 100 if t else 0
            lines.append(f"  - {prio}: {t} total, {b} breached ({pct:.0f}%)")

    # Unassigned critical tickets
    crit_unasgn = df[
        (df["Assigned To Clean"] == "") & (df["Priority"] == "Critical")
    ]["Request ID"].tolist()[:10]
    if crit_unasgn:
        lines += ["", f"## Unassigned Critical Tickets ({len(crit_unasgn)} shown)"]
        for rid in crit_unasgn:
            lines.append(f"  - {rid}")

    return "\n".join(lines)


# ─── AI Copilot: rule-based query engine (no API key required) ────────────────

def _rule_based_answer(question: str, df: pd.DataFrame) -> str:
    """Return a data-driven answer without any external API."""
    q = question.lower()
    total = len(df)

    # ── Engineer list / directory queries (checked BEFORE generic workload) ───
    if any(w in q for w in ["engineer list", "list of engineer", "all engineer",
                             "show engineer", "engineer detail", "team list",
                             "team member", "who are the", "list engineer",
                             "engineer name", "full list", "complete list",
                             "all team", "show team", "team detail"]):
        eng = (df[df["Assigned To Clean"] != ""]
               .groupby("Assigned To Clean").size()
               .sort_values(ascending=False))
        if eng.empty:
            return "No engineers found in the current dataset."
        lines = [
            f"## Engineer Directory  ({len(eng)} engineers)",
            "",
            "| # | Engineer | Tickets | Status |",
            "|---|----------|---------|--------|",
        ]
        for rank, (name, cnt) in enumerate(eng.items(), 1):
            if cnt > 10:
                status = "🔴 Overloaded"
            elif cnt > 5:
                status = "🟡 Moderate"
            else:
                status = "🟢 Optimal"
            lines.append(f"| {rank} | {name} | {cnt} | {status} |")
        lines += [
            "",
            f"**Total engineers:** {len(eng)}  |  "
            f"**Overloaded (>10):** {int((eng > 10).sum())}  |  "
            f"**Optimal (≤5):** {int((eng <= 5).sum())}",
        ]
        return "\n".join(lines)

    # ── Workload / engineer queries ────────────────────────────────────────────
    if any(w in q for w in ["workload", "load", "busy", "overload", "engineer",
                             "who has", "who have", "who having", "who is",
                             "lightest", "heaviest", "most ticket", "fewest ticket",
                             "more ticket", "number of ticket", "ticket count",
                             "more number", "most number", "highest ticket",
                             "redistribute", "rebalance"]):
        eng = (df[df["Assigned To Clean"] != ""]
               .groupby("Assigned To Clean").size()
               .sort_values(ascending=False))
        if eng.empty:
            return "No engineers have assigned tickets in the current dataset."
        lightest = eng.index[-1]
        lightest_cnt = int(eng.iloc[-1])
        heaviest = eng.index[0]
        heaviest_cnt = int(eng.iloc[0])
        overloaded = eng[eng > 10]
        optimal    = eng[eng <= 5]
        lines = [
            f"## Engineer Workload Summary",
            f"- **Most loaded:** {heaviest} — **{heaviest_cnt} tickets**",
            f"- **Lightest load:** {lightest} — **{lightest_cnt} tickets** ← best for new assignments",
            f"- **Overloaded (>10):** {len(overloaded)} engineers",
            f"- **Optimal (≤5):** {len(optimal)} engineers",
            "",
            "**Top 5 engineers by ticket count:**",
        ]
        for eng_name, cnt in eng.head(5).items():
            badge = " 🔴 Overloaded" if cnt > 10 else (" 🟡 Moderate" if cnt > 5 else " 🟢 Optimal")
            lines.append(f"  - {eng_name}: {cnt}{badge}")
        if "lightest" in q or "recommend" in q or "new" in q:
            lines += ["", f"**Recommendation:** Assign new tickets to **{lightest}** "
                          f"(only {lightest_cnt} active tickets)."]
        return "\n".join(lines)

    # ── SLA / breach queries ───────────────────────────────────────────────────
    if any(w in q for w in ["sla", "breach", "overdue", "late", "compliance",
                             "deadline", "on time", "on-time"]):
        breached   = int(df["SLA Breached"].sum())
        breach_pct = breached / total * 100 if total else 0
        by_prio    = df.groupby("Priority").agg(
            Total=("Request ID","count"), Breached=("SLA Breached","sum")
        ).reindex(["Critical","High","Medium","Low"]).fillna(0)
        by_type    = (df[df["SLA Breached"]]
                      .groupby("Request Type").size()
                      .sort_values(ascending=False).head(5))
        lines = [
            f"## SLA Performance Analysis",
            f"- **Overall breach rate:** {breach_pct:.1f}% ({breached} of {total} tickets)",
            f"- **On-time tickets:** {total - breached} ({(total-breached)/total*100:.0f}%)",
            "",
            "**By Priority:**",
        ]
        for prio in ["Critical","High","Medium","Low"]:
            if prio in by_prio.index:
                t = int(by_prio.loc[prio,"Total"])
                b = int(by_prio.loc[prio,"Breached"])
                pct = b/t*100 if t else 0
                icon = "🔴" if pct > 40 else ("🟡" if pct > 20 else "🟢")
                lines.append(f"  - {icon} **{prio}:** {b}/{t} breached ({pct:.0f}%)")
        if not by_type.empty:
            lines += ["", "**Most breached request types:**"]
            for rt, cnt in by_type.items():
                lines.append(f"  - {rt}: {cnt} breaches")
        if breach_pct > 30:
            lines += ["", "**Insight:** Breach rate is high. Focus on unassigned Critical/High "
                          "tickets and ensure engineers are not overloaded."]
        return "\n".join(lines)

    # ── Unassigned / queue queries ─────────────────────────────────────────────
    if any(w in q for w in ["unassigned", "queue", "no one", "nobody", "triage",
                             "pending", "waiting", "assign"]):
        unasgn = df[(df["State"] == "Pending for Review") & (df["Assigned To Clean"] == "")]
        crit   = int((unasgn["Priority"] == "Critical").sum())
        high   = int((unasgn["Priority"] == "High").sum())
        breach = int(unasgn["SLA Breached"].sum())
        eng    = (df[df["Assigned To Clean"] != ""]
                  .groupby("Assigned To Clean").size()
                  .sort_values())
        lines = [
            f"## Unassigned Queue",
            f"- **Total unassigned:** {len(unasgn)} tickets",
            f"- **Critical unassigned:** {crit} 🔴 — immediate action needed",
            f"- **High unassigned:** {high} 🟡",
            f"- **Already SLA breached:** {breach} ⏰",
        ]
        if not eng.empty:
            lightest = eng.index[0]
            lightest_cnt = int(eng.iloc[0])
            lines += ["", f"**Triage recommendation:** Start by assigning the {crit} Critical "
                          f"tickets. **{lightest}** has the lightest load ({lightest_cnt} tickets) "
                          f"and should be first choice."]
        return "\n".join(lines)

    # ── Assignment recommendation ──────────────────────────────────────────────
    if any(w in q for w in ["recommend", "suggest", "best person", "who should",
                             "ideal", "suitable", "right person"]):
        eng = (df[df["Assigned To Clean"] != ""]
               .groupby("Assigned To Clean").size()
               .sort_values())
        unasgn_cnt = int(((df["State"] == "Pending for Review") &
                          (df["Assigned To Clean"] == "")).sum())
        if eng.empty:
            return "No engineer data available for recommendations."
        top3 = eng.head(3)
        lines = [
            f"## Assignment Recommendations",
            f"There are **{unasgn_cnt} unassigned tickets** pending triage.",
            "",
            "**Best available engineers (by lightest load):**",
        ]
        for i, (name, cnt) in enumerate(top3.items(), 1):
            badge = "🟢 Optimal" if cnt <= 5 else "🟡 Moderate"
            lines.append(f"  {i}. **{name}** — {cnt} active tickets ({badge})")
        lines += ["", "Assign Critical/High SLA-breached tickets first to avoid further delays."]
        return "\n".join(lines)

    # ── Critical / urgent queries ──────────────────────────────────────────────
    if any(w in q for w in ["critical", "urgent", "high priority", "most important",
                             "immediate", "emergency"]):
        crit_df  = df[df["Priority"] == "Critical"]
        unasgn_c = int(((df["Priority"] == "Critical") &
                         (df["Assigned To Clean"] == "")).sum())
        breach_c = int(((df["Priority"] == "Critical") & df["SLA Breached"]).sum())
        lines = [
            f"## Critical Ticket Summary",
            f"- **Total Critical tickets:** {len(crit_df)}",
            f"- **Unassigned Critical:** {unasgn_c} 🔴",
            f"- **Critical & SLA breached:** {breach_c} ⏰",
            f"- **Critical on-time:** {len(crit_df) - breach_c}",
        ]
        if unasgn_c > 0:
            lines += ["", f"**Action required:** {unasgn_c} Critical tickets have no owner. "
                          "Assign immediately — SLA for Critical is **7 days**."]
        return "\n".join(lines)

    # ── Request type queries ───────────────────────────────────────────────────
    if any(w in q for w in ["type", "request type", "dast", "sast", "oss", "masa",
                             "sign off", "design review", "false positive", "breakdown"]):
        rt = df["Request Type"].replace("", "Unknown").value_counts()
        breach_rt = (df[df["SLA Breached"]].groupby("Request Type")
                     .size().sort_values(ascending=False))
        lines = [f"## Request Type Breakdown", ""]
        for rtype, cnt in rt.head(8).items():
            b = int(breach_rt.get(rtype, 0))
            pct = b/cnt*100 if cnt else 0
            icon = "🔴" if pct > 40 else ("🟡" if pct > 20 else "🟢")
            lines.append(f"  - {icon} **{rtype}:** {cnt} tickets, {b} breached ({pct:.0f}%)")
        worst = breach_rt.index[0] if not breach_rt.empty else "N/A"
        lines += ["", f"**Worst SLA compliance:** {worst}"]
        return "\n".join(lines)

    # ── Group / team queries ───────────────────────────────────────────────────
    if any(w in q for w in ["group", "team", "csappsec", "itssdlc", "cssdlc",
                             "which team", "which group"]):
        grp = df["Primary Group"].value_counts()
        lines = [f"## Group Distribution", ""]
        for g, cnt in grp.items():
            b = int(df[df["Primary Group"] == g]["SLA Breached"].sum())
            pct = b/cnt*100 if cnt else 0
            lines.append(f"  - **{g}:** {cnt} tickets, {b} breached ({pct:.0f}%)")
        return "\n".join(lines)

    # ── Default: general overview ──────────────────────────────────────────────
    breached   = int(df["SLA Breached"].sum())
    breach_pct = breached / total * 100 if total else 0
    unassigned = int((df["Assigned To Clean"] == "").sum())
    closed     = int((df["State"] == "Closed").sum())
    pending    = int((df["State"] == "Pending for Review").sum())
    eng_count  = df[df["Assigned To Clean"] != ""]["Assigned To Clean"].nunique()
    return (
        f"## AppSec Dashboard Overview\n\n"
        f"- **Total tickets:** {total:,}\n"
        f"- **Pending for Review:** {pending} | **Closed:** {closed}\n"
        f"- **Unassigned:** {unassigned} | **Active Engineers:** {eng_count}\n"
        f"- **SLA Breach Rate:** {breach_pct:.1f}% ({breached} tickets)\n\n"
        f"You can ask me about: **workload**, **SLA breaches**, **unassigned tickets**, "
        f"**assignment recommendations**, **critical tickets**, **request types**, or **group distribution**."
    )


# ─── Page: AI Copilot Chat ─────────────────────────────────────────────────────

def page_copilot(df: pd.DataFrame):
    api_key = _get_api_key()
    mode    = "claude" if (ANTHROPIC_AVAILABLE and api_key) else "local"
    mode_label = "Claude AI" if mode == "claude" else "Intelligence Engine"

    st.markdown(page_banner(
        "AI Copilot",
        f"Ask anything about your AppSec ticket pipeline · {mode_label} · Live data",
        NEON_PURPLE), unsafe_allow_html=True)

    # ── Live context stats bar ─────────────────────────────────────────────────
    total      = len(df)
    breached   = int(df["SLA Breached"].sum())
    unassigned = int((df["Assigned To Clean"] == "").sum())
    eng_count  = df[df["Assigned To Clean"] != ""]["Assigned To Clean"].nunique()
    breach_pct = breached / total * 100 if total else 0

    st.markdown(f"""
    <div style='display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap'>
        <div style='flex:1;min-width:110px;background:rgba(180,79,255,0.07);
            border:1px solid rgba(180,79,255,0.25);border-radius:10px;padding:10px 14px'>
            <div style='font-family:Orbitron,monospace;font-size:1.2rem;font-weight:700;
                color:{NEON_PURPLE}'>{total:,}</div>
            <div style='font-size:0.65rem;color:#6c7a9c;text-transform:uppercase;
                letter-spacing:0.1em'>Total Tickets</div>
        </div>
        <div style='flex:1;min-width:110px;background:rgba(255,75,110,0.07);
            border:1px solid rgba(255,75,110,0.25);border-radius:10px;padding:10px 14px'>
            <div style='font-family:Orbitron,monospace;font-size:1.2rem;font-weight:700;
                color:{NEON_RED}'>{breach_pct:.1f}%</div>
            <div style='font-size:0.65rem;color:#6c7a9c;text-transform:uppercase;
                letter-spacing:0.1em'>SLA Breach Rate</div>
        </div>
        <div style='flex:1;min-width:110px;background:rgba(255,166,77,0.07);
            border:1px solid rgba(255,166,77,0.25);border-radius:10px;padding:10px 14px'>
            <div style='font-family:Orbitron,monospace;font-size:1.2rem;font-weight:700;
                color:{NEON_ORANGE}'>{unassigned}</div>
            <div style='font-size:0.65rem;color:#6c7a9c;text-transform:uppercase;
                letter-spacing:0.1em'>Unassigned</div>
        </div>
        <div style='flex:1;min-width:110px;background:rgba(0,212,255,0.07);
            border:1px solid rgba(0,212,255,0.2);border-radius:10px;padding:10px 14px'>
            <div style='font-family:Orbitron,monospace;font-size:1.2rem;font-weight:700;
                color:{NEON_BLUE}'>{eng_count}</div>
            <div style='font-size:0.65rem;color:#6c7a9c;text-transform:uppercase;
                letter-spacing:0.1em'>Active Engineers</div>
        </div>
        <div style='flex:1;min-width:140px;background:rgba(0,255,136,0.04);
            border:1px solid rgba(0,255,136,0.15);border-radius:10px;
            padding:10px 14px;display:flex;flex-direction:column;justify-content:center'>
            <div style='font-size:0.65rem;color:#b44fff;text-transform:uppercase;
                letter-spacing:0.1em;margin-bottom:2px'>Mode</div>
            <div style='font-size:0.78rem;color:#cdd6f4;font-weight:600'>{mode_label}</div>
            <div style='font-size:0.62rem;color:#4a5568;margin-top:1px'>
                {'Claude Sonnet 4.6' if mode == 'claude' else 'No API key needed'}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Optional: Claude API key setup ────────────────────────────────────────
    if mode == "local":
        with st.expander("Upgrade to Claude AI (optional — needs API key)", expanded=False):
            st.markdown(
                '<div class="info-panel" style="margin-bottom:10px">The copilot works fully '
                'without a key. Add an Anthropic API key to unlock richer conversational '
                'answers with full context awareness.</div>', unsafe_allow_html=True)
            with st.form("api_key_form", clear_on_submit=False):
                key_input = st.text_input("Anthropic API Key", type="password",
                                          placeholder="sk-ant-...")
                if st.form_submit_button("Save Key"):
                    if key_input.startswith("sk-"):
                        st.session_state["anthropic_api_key"] = key_input
                        st.success("Key saved. Reload page to activate Claude mode.")
                        st.rerun()
                    else:
                        st.error("Key must start with 'sk-ant-'")

    # ── Init chat history ──────────────────────────────────────────────────────
    if "copilot_messages" not in st.session_state:
        st.session_state["copilot_messages"] = []

    if mode == "claude" and "copilot_context" not in st.session_state:
        st.session_state["copilot_context"] = _build_data_context(df)

    # ── Capture ALL question sources FIRST (before any rendering decisions) ───
    # st.chat_input is sticky at the bottom regardless of where it's called
    user_input = st.chat_input("Ask about your AppSec tickets — workload, SLA, assignments...")
    # Suggestion buttons set _copilot_pending; consume it here on the rerun they trigger
    pending_q = st.session_state.pop("_copilot_pending", None)
    question = pending_q or user_input  # whichever arrived this frame

    # ── Welcome state — shown ONLY when chat is truly empty AND no question ────
    if not st.session_state["copilot_messages"] and not question:
        st.markdown(f"""
        <div style='text-align:center;padding:20px 0 10px'>
            <div style='font-size:2.4rem;margin-bottom:8px'>🛡</div>
            <div style='font-family:Orbitron,monospace;font-size:1rem;font-weight:700;
                background:linear-gradient(135deg,{NEON_PURPLE},{NEON_BLUE});
                -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                background-clip:text;letter-spacing:0.06em'>AppSec Intelligence Copilot</div>
            <div style='color:#6c7a9c;font-size:0.85rem;margin-top:6px'>
                Ask anything about your live ServiceNow ticket data
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(section_hdr("Suggested Questions — click to ask", ""), unsafe_allow_html=True)

        suggestions = [
            ("👷", "Workload",      "Who has the lightest workload right now?"),
            ("🚨", "SLA Breach",    "What is our current SLA breach situation?"),
            ("📭", "Unassigned",    "Summarize all unassigned tickets and suggest a triage plan."),
            ("📊", "Request Types", "Which request type has the worst SLA compliance?"),
            ("🔴", "Overloaded",    "Which engineer is most overloaded?"),
            ("📋", "Overview",      "Give me an overview of the current dashboard."),
        ]

        col1, col2, col3 = st.columns(3)
        cols = [col1, col2, col3]
        for i, (icon, label, sug_q) in enumerate(suggestions):
            with cols[i % 3]:
                st.markdown(f"""
                <div style='background:rgba(180,79,255,0.05);
                    border:1px solid rgba(180,79,255,0.2);
                    border-top:2px solid {NEON_PURPLE};
                    border-radius:0 0 10px 10px;
                    padding:4px 12px 6px;margin-bottom:2px'>
                    <span style='font-size:0.65rem;text-transform:uppercase;
                        letter-spacing:0.1em;color:{NEON_PURPLE};font-weight:600'>
                        {icon} {label}</span>
                </div>
                """, unsafe_allow_html=True)
                # Set pending and let the button-triggered rerun handle response generation
                if st.button(sug_q, key=f"sug_{i}", use_container_width=True):
                    st.session_state["_copilot_pending"] = sug_q

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    else:
        # ── Render existing chat messages ──────────────────────────────────────
        for msg in st.session_state["copilot_messages"]:
            with st.chat_message(msg["role"],
                                 avatar="🛡" if msg["role"] == "assistant" else "👤"):
                st.markdown(msg["content"])

        # ── Generate response for the incoming question ────────────────────────
        if question:
            # Show user message
            with st.chat_message("user", avatar="👤"):
                st.markdown(question)
            st.session_state["copilot_messages"].append(
                {"role": "user", "content": question})

            # Generate and show assistant response
            with st.chat_message("assistant", avatar="🛡"):
                placeholder = st.empty()

                if mode == "claude":
                    system_prompt = (
                        "You are the AppSec Operations Intelligence Copilot for a cybersecurity team. "
                        "Be concise, direct, and always ground your answers in the live dashboard data "
                        "below. Format in clean markdown with bullet points and bold key figures. "
                        "Never fabricate data not in the context.\n\n"
                        + st.session_state["copilot_context"]
                    )
                    full_response = ""
                    try:
                        client = _anthropic.Anthropic(api_key=api_key)
                        api_messages = [{"role": m["role"], "content": m["content"]}
                                        for m in st.session_state["copilot_messages"]]
                        with client.messages.stream(
                            model="claude-sonnet-4-6", max_tokens=1024,
                            system=system_prompt, messages=api_messages,
                        ) as stream:
                            for chunk in stream.text_stream:
                                full_response += chunk
                                placeholder.markdown(full_response + "▌")
                        placeholder.markdown(full_response)
                        st.session_state["copilot_messages"].append(
                            {"role": "assistant", "content": full_response})
                    except Exception as e:
                        err = str(e)
                        if "authentication" in err.lower() or "api_key" in err.lower():
                            placeholder.error("Invalid API key — falling back to local mode.")
                            st.session_state.pop("anthropic_api_key", None)
                            st.session_state.pop("copilot_context", None)
                        else:
                            placeholder.error(f"Claude API error: {err}")
                else:
                    answer = _rule_based_answer(question, df)
                    placeholder.markdown(answer)
                    st.session_state["copilot_messages"].append(
                        {"role": "assistant", "content": answer})

        # ── Clear chat ─────────────────────────────────────────────────────────
        if st.session_state["copilot_messages"]:
            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
            col_clr, _ = st.columns([1, 5])
            with col_clr:
                if st.button("Clear Chat", key="copilot_clear", use_container_width=True):
                    st.session_state["copilot_messages"] = []
                    st.session_state.pop("copilot_context", None)
                    st.rerun()


# ─── Briefing: pure-Python template (no API key needed) ───────────────────────

def _generate_template_briefing(df: pd.DataFrame, today: datetime) -> str:
    """Build a complete professional briefing using only computed metrics."""
    total      = len(df)
    pending    = int((df["State"] == "Pending for Review").sum())
    clarify    = int((df["State"] == "Sent for Clarification").sum())
    closed     = int((df["State"] == "Closed").sum())
    rejected   = int((df["State"] == "Rejected").sum())
    unassigned = int((df["Assigned To Clean"] == "").sum())
    breached   = int(df["SLA Breached"].sum())
    breach_pct = breached / total * 100 if total else 0
    on_time    = total - breached
    avg_open   = df["Days Open"].mean()
    closed_df  = df[df["State"] == "Closed"]
    avg_res    = closed_df["Days Open"].mean() if not closed_df.empty else 0.0

    eng_load   = (df[df["Assigned To Clean"] != ""]
                  .groupby("Assigned To Clean").size()
                  .sort_values(ascending=False))
    overloaded  = int((eng_load > 10).sum())
    optimal     = int((eng_load <= 5).sum())
    top_eng     = eng_load.index[0]  if not eng_load.empty else "N/A"
    top_eng_cnt = int(eng_load.iloc[0]) if not eng_load.empty else 0
    light_eng   = eng_load.index[-1] if not eng_load.empty else "N/A"
    light_cnt   = int(eng_load.iloc[-1]) if not eng_load.empty else 0

    crit_unasgn = int(((df["Assigned To Clean"] == "") & (df["Priority"] == "Critical")).sum())
    high_unasgn = int(((df["Assigned To Clean"] == "") & (df["Priority"] == "High")).sum())

    sla_df     = df.groupby("Priority").agg(
        Total=("Request ID","count"), Breached=("SLA Breached","sum")
    ).reindex(["Critical","High","Medium","Low"]).fillna(0)

    top_types  = df["Request Type"].replace("","Unknown").value_counts().head(5)
    breach_by_type = (df[df["SLA Breached"]].groupby("Request Type")
                      .size().sort_values(ascending=False))
    worst_type = breach_by_type.index[0] if not breach_by_type.empty else "N/A"

    health = "CRITICAL" if breach_pct > 40 else ("AT RISK" if breach_pct > 20 else "HEALTHY")
    health_icon = "🔴" if health == "CRITICAL" else ("🟡" if health == "AT RISK" else "🟢")

    # Build recommended actions
    actions = []
    if crit_unasgn > 0:
        actions.append(f"Immediately assign the **{crit_unasgn} unassigned Critical ticket(s)** "
                       f"— assign to {light_eng} (lightest load: {light_cnt} tickets).")
    if high_unasgn > 0:
        actions.append(f"Process **{high_unasgn} unassigned High tickets** before end of week "
                       f"to avoid SLA escalation (SLA = 14 days).")
    if overloaded > 0:
        actions.append(f"Rebalance workload — **{overloaded} engineer(s) have >10 tickets**. "
                       f"Redistribute to engineers with ≤5 tickets ({optimal} available).")
    if breach_pct > 20:
        actions.append(f"**{worst_type}** has the highest SLA breach count — "
                       f"review if resource allocation matches volume for this type.")
    if not actions:
        actions.append("No urgent actions identified. Maintain current assignment cadence.")

    lines = [
        f"# AppSec Weekly Intelligence Briefing",
        f"**{today.strftime('%A, %d %B %Y')}** | Auto-generated from live ServiceNow data",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary",
        f"",
        f"The AppSec operations pipeline currently holds **{total:,} tickets** with an overall "
        f"SLA compliance health of **{health_icon} {health}** ({breach_pct:.1f}% breach rate). "
        f"There are **{unassigned} unassigned tickets** ({crit_unasgn} Critical, {high_unasgn} High) "
        f"requiring immediate triage. "
        + (f"Workload is unevenly distributed with {overloaded} engineer(s) overloaded."
           if overloaded > 0 else "Engineer workload is within acceptable range."),
        f"",
        f"---",
        f"",
        f"## 2. Volume & Pipeline",
        f"",
        f"| Status | Count | % of Total |",
        f"|--------|-------|------------|",
        f"| Pending for Review | {pending} | {pending/total*100:.0f}% |",
        f"| Sent for Clarification | {clarify} | {clarify/total*100:.0f}% |",
        f"| Closed | {closed} | {closed/total*100:.0f}% |",
        f"| Rejected | {rejected} | {rejected/total*100:.0f}% |",
        f"| **Total** | **{total}** | 100% |",
        f"",
        f"**Top request types by volume:**",
    ]
    for rt, cnt in top_types.items():
        pct = cnt/total*100
        lines.append(f"- {rt}: **{cnt}** ({pct:.0f}%)")

    lines += [
        f"",
        f"---",
        f"",
        f"## 3. SLA Performance",
        f"",
        f"- **Overall breach rate:** {breach_pct:.1f}% — **{breached}** breached, "
        f"**{on_time}** on-time",
        f"- **Average days open (all tickets):** {avg_open:.1f} days",
        f"- **Average resolution time (closed):** {avg_res:.1f} days",
        f"",
        f"**SLA compliance by priority:**",
        f"",
        f"| Priority | SLA Threshold | Total | Breached | Compliance |",
        f"|----------|---------------|-------|----------|------------|",
    ]
    thresholds = {"Critical": "7d", "High": "14d", "Medium": "21d", "Low": "30d"}
    for prio in ["Critical", "High", "Medium", "Low"]:
        if prio in sla_df.index:
            t  = int(sla_df.loc[prio, "Total"])
            b  = int(sla_df.loc[prio, "Breached"])
            ok = t - b
            cp = ok/t*100 if t else 100
            icon = "🔴" if cp < 60 else ("🟡" if cp < 80 else "🟢")
            lines.append(f"| {icon} {prio} | {thresholds[prio]} | {t} | {b} | {cp:.0f}% |")

    lines += [
        f"",
        f"**Most breached request type:** {worst_type} ({int(breach_by_type.iloc[0]) if not breach_by_type.empty else 0} breaches)",
        f"",
        f"---",
        f"",
        f"## 4. Workload & Capacity",
        f"",
        f"- **Unassigned tickets:** {unassigned} total ({crit_unasgn} Critical, {high_unasgn} High)",
        f"- **Overloaded engineers (>10 tickets):** {overloaded}",
        f"- **Optimal load engineers (≤5 tickets):** {optimal}",
        f"- **Most loaded:** {top_eng} ({top_eng_cnt} tickets)",
        f"- **Available capacity:** {light_eng} ({light_cnt} tickets — best for new assignments)",
        f"",
        f"---",
        f"",
        f"## 5. Top Risks This Week",
        f"",
    ]
    risks = []
    if crit_unasgn > 0:
        risks.append(f"**{crit_unasgn} unassigned Critical tickets** — each has a 7-day SLA, "
                     f"immediate assignment required.")
    if breach_pct > 30:
        risks.append(f"**SLA breach rate at {breach_pct:.1f}%** — above acceptable threshold. "
                     f"Escalation risk if not addressed this week.")
    if overloaded > 0:
        risks.append(f"**{overloaded} engineers are overloaded** — burnout and ticket quality "
                     f"risk. Rebalancing needed.")
    risks.append(f"**{worst_type}** continues to accumulate SLA breaches — "
                 f"review resourcing for this type.")
    for i, r in enumerate(risks, 1):
        lines.append(f"{i}. {r}")

    lines += [
        f"",
        f"---",
        f"",
        f"## 6. Recommended Actions",
        f"",
    ]
    for i, a in enumerate(actions, 1):
        lines.append(f"{i}. {a}")

    lines += [
        f"",
        f"---",
        f"",
        f"*Briefing generated automatically from live ServiceNow data — "
        f"{today.strftime('%d %b %Y %H:%M')}*",
    ]
    return "\n".join(lines)


# ─── Page: Weekly Intelligence Briefing ───────────────────────────────────────

def page_briefing(df: pd.DataFrame):
    today = datetime.now()
    st.markdown(page_banner(
        "Weekly Intelligence Briefing",
        "Operational briefing auto-generated from live ticket data — no API key required",
        NEON_GREEN), unsafe_allow_html=True)

    # ── KPI preview ────────────────────────────────────────────────────────────
    total      = len(df)
    breached   = int(df["SLA Breached"].sum())
    breach_pct = breached / total * 100 if total else 0
    unassigned = int((df["Assigned To Clean"] == "").sum())
    crit_unasgn= int(((df["Assigned To Clean"] == "") & (df["Priority"] == "Critical")).sum())
    eng_load   = (df[df["Assigned To Clean"] != ""]
                  .groupby("Assigned To Clean").size())
    overloaded = int((eng_load > 10).sum())

    render_kpis([
        (f"{total:,}",         "Total Tickets",    NEON_BLUE,   "📋", ""),
        (f"{breach_pct:.1f}%", "SLA Breach Rate",  NEON_RED,    "🚨", f"{breached} tickets"),
        (f"{unassigned:,}",    "Unassigned",        NEON_ORANGE, "📭", f"{crit_unasgn} critical"),
        (f"{overloaded:,}",    "Overloaded Eng.",   NEON_RED,    "⚠️",  ">10 tickets each"),
    ])

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Generate button ────────────────────────────────────────────────────────
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        generate = st.button("Generate Briefing", key="gen_brief", use_container_width=True)
    with col_info:
        api_key = _get_api_key()
        mode_label = "Claude AI (enhanced)" if (ANTHROPIC_AVAILABLE and api_key) else "Template engine (instant, no key needed)"
        st.markdown(
            f"<div style='padding:10px 0;font-size:0.82rem;color:#6c7a9c'>"
            f"Mode: <b style='color:#cdd6f4'>{mode_label}</b> &nbsp;|&nbsp; "
            f"Date: <b style='color:#cdd6f4'>{today.strftime('%d %b %Y')}</b></div>",
            unsafe_allow_html=True)

    # Show cached briefing if already generated
    if "briefing_output" in st.session_state and not generate:
        _render_briefing_output(st.session_state["briefing_output"], today)

    if generate:
        st.session_state.pop("briefing_output", None)
        api_key = _get_api_key()

        if ANTHROPIC_AVAILABLE and api_key:
            # ── Claude mode ────────────────────────────────────────────────────
            with st.spinner("Generating briefing with Claude..."):
                try:
                    metrics = _build_data_context(df)
                    prompt  = (
                        "Write a professional weekly AppSec ops briefing with these sections: "
                        "1) Executive Summary 2) Volume & Pipeline 3) SLA Performance "
                        "4) Workload & Capacity 5) Top Risks 6) Recommended Actions. "
                        "Be concise, use bold for key figures, base everything on data below.\n\n"
                        + metrics)
                    client  = _anthropic.Anthropic(api_key=api_key)
                    message = client.messages.create(
                        model="claude-sonnet-4-6", max_tokens=2048,
                        messages=[{"role": "user", "content": prompt}])
                    result  = message.content[0].text
                    st.session_state["briefing_output"] = result
                    _render_briefing_output(result, today)
                except Exception as e:
                    st.warning(f"Claude error ({e}). Falling back to template mode.")
                    result = _generate_template_briefing(df, today)
                    st.session_state["briefing_output"] = result
                    _render_briefing_output(result, today)
        else:
            # ── Template mode (instant, no key) ────────────────────────────────
            result = _generate_template_briefing(df, today)
            st.session_state["briefing_output"] = result
            _render_briefing_output(result, today)


def _render_briefing_output(text: str, today: datetime):
    """Render the briefing text as formatted markdown with a professional glowing container."""
    st.markdown(section_hdr("Generated Briefing", ""), unsafe_allow_html=True)

    # Top accent bar + metadata ribbon
    st.markdown(f"""
    <div style='
        background: linear-gradient(135deg, rgba(0,255,136,0.08) 0%, rgba(0,212,255,0.04) 100%);
        border: 1px solid rgba(0,255,136,0.3);
        border-left: 4px solid {NEON_GREEN};
        border-radius: 0 14px 14px 0;
        padding: 14px 22px 10px;
        margin-bottom: 2px;
        box-shadow: 0 0 40px rgba(0,255,136,0.07), inset 0 1px 0 rgba(0,255,136,0.08);
    '>
        <div style='display:flex;justify-content:space-between;align-items:center'>
            <div>
                <div style='font-family:Orbitron,monospace;font-size:0.78rem;color:{NEON_GREEN};
                            letter-spacing:0.08em;font-weight:700'>WEEKLY INTELLIGENCE BRIEFING</div>
                <div style='font-size:0.72rem;color:#6c7a9c;margin-top:3px'>
                    {today.strftime('%A, %d %B %Y')} &nbsp;·&nbsp; Auto-generated from live ServiceNow data
                </div>
            </div>
            <div style='font-family:Orbitron,monospace;font-size:1.2rem;color:{NEON_GREEN};
                        opacity:0.6'>&#9632;</div>
        </div>
    </div>
    <div style='
        background: rgba(7,9,20,0.6);
        border: 1px solid rgba(0,255,136,0.12);
        border-top: none;
        border-radius: 0 0 14px 14px;
        padding: 24px 28px 20px;
        margin-bottom: 16px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    '>
    </div>
    """, unsafe_allow_html=True)

    # Render the actual markdown — this is what makes headings, tables, bold work
    st.markdown(text)

    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    dl1, dl2 = st.columns([1, 4])
    with dl1:
        st.download_button(
            "Download as .md",
            data=f"# AppSec Weekly Intelligence Briefing\n**{today.strftime('%d %B %Y')}**\n\n{text}",
            file_name=f"appsec_briefing_{today.strftime('%Y%m%d')}.md",
            mime="text/markdown",
            key="dl_briefing")


# ─── Page: ServiceNow Write-Back Agent ────────────────────────────────────────

def page_snow_sync(df: pd.DataFrame):
    st.markdown(page_banner(
        "ServiceNow Write-Back Agent",
        "Sync dashboard assignments and state changes back to your ServiceNow instance",
        NEON_ORANGE), unsafe_allow_html=True)

    if not REQUESTS_AVAILABLE:
        st.markdown(
            '<div class="alert-panel"><b>requests package not installed.</b><br>'
            'Run: <code>pip install requests</code> then restart the app.</div>',
            unsafe_allow_html=True)
        return

    # ── Configuration panel ────────────────────────────────────────────────────
    st.markdown(section_hdr("ServiceNow Connection", ""), unsafe_allow_html=True)

    cfg_col1, cfg_col2 = st.columns(2)
    with cfg_col1:
        snow_instance = st.text_input(
            "SNOW Instance URL",
            value=st.session_state.get("snow_instance", ""),
            placeholder="https://yourcompany.service-now.com",
            key="snow_inst_input")
        snow_user = st.text_input(
            "Username",
            value=st.session_state.get("snow_user", ""),
            placeholder="api_user or your SNOW username",
            key="snow_user_input")
    with cfg_col2:
        snow_pass = st.text_input(
            "Password / API Token",
            type="password",
            value=st.session_state.get("snow_pass", ""),
            key="snow_pass_input")
        snow_table = st.text_input(
            "Table Name",
            value=st.session_state.get("snow_table", "sn_grc_application_security"),
            placeholder="sn_grc_application_security",
            key="snow_table_input")

    def _persist_snow_fields():
        """Save current field values into session state (called by both buttons)."""
        st.session_state["snow_instance"] = snow_instance.rstrip("/")
        st.session_state["snow_user"]     = snow_user
        st.session_state["snow_pass"]     = snow_pass
        st.session_state["snow_table"]    = snow_table or "sn_grc_application_security"

    btn1, btn2, _ = st.columns([1, 1, 3])
    with btn1:
        if st.button("Save Config", key="snow_save"):
            _persist_snow_fields()
            st.success("Connection config saved for this session.")
    with btn2:
        if st.button("Test Connection", key="snow_test"):
            _persist_snow_fields()          # always sync live field values first
            _snow_test_connection()

    if not all([snow_instance, snow_user, snow_pass]):
        st.markdown(
            '<div class="info-panel">'
            '<b>How to connect:</b><br>'
            '1. Enter your ServiceNow instance URL (e.g. <code>https://mycompany.service-now.com</code>)<br>'
            '2. Provide a user with <b>rest_service</b> or <b>admin</b> role in ServiceNow<br>'
            '3. The table name is the GRC table your tickets live in — check with your SNOW admin<br>'
            '4. Click <b>Test Connection</b> directly — no need to save first'
            '</div>',
            unsafe_allow_html=True)

    # ── Pending changes panel ──────────────────────────────────────────────────
    st.markdown(section_hdr("Pending Changes", ""), unsafe_allow_html=True)

    conn  = sqlite3.connect(DB_PATH)
    state_changes = pd.read_sql(
        "SELECT request_id, state, priority, notes, updated_at FROM ticket_states ORDER BY updated_at DESC",
        conn)
    assign_changes = pd.read_sql(
        "SELECT request_id, assigned_to, assigned_group, assigned_at FROM assignments ORDER BY assigned_at DESC",
        conn)
    conn.close()

    total_pending = len(state_changes) + len(assign_changes)

    render_kpis([
        (f"{len(state_changes):,}",  "State Changes",       NEON_BLUE,   "🔄", "queued for sync"),
        (f"{len(assign_changes):,}", "Assignment Changes",  NEON_GREEN,  "👤", "queued for sync"),
        (f"{total_pending:,}",       "Total Pending",       NEON_ORANGE, "📤", "ready to push"),
        (f"{st.session_state.get('snow_last_sync', 'Never')}", "Last Sync", NEON_PURPLE, "✅", ""),
    ])

    if not state_changes.empty:
        st.markdown("**State Changes Queued**")
        st.dataframe(state_changes.rename(columns={
            "request_id": "Request ID", "state": "New State",
            "priority": "Priority", "updated_at": "Changed At"
        })[["Request ID", "New State", "Priority", "Changed At"]],
            use_container_width=True, hide_index=True)

    if not assign_changes.empty:
        st.markdown("**Assignment Changes Queued**")
        st.dataframe(assign_changes.rename(columns={
            "request_id": "Request ID", "assigned_to": "Assigned To",
            "assigned_group": "Group", "assigned_at": "Changed At"
        })[["Request ID", "Assigned To", "Group", "Changed At"]],
            use_container_width=True, hide_index=True)

    if total_pending == 0:
        st.markdown(
            '<div class="info-panel">No pending changes. Make assignments or state updates '
            'in the <b>Unassigned Queue</b> or <b>Ticket Tracker</b> pages first.</div>',
            unsafe_allow_html=True)
        return

    # ── Sync button ────────────────────────────────────────────────────────────
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    sync_col1, sync_col2 = st.columns([1, 4])
    with sync_col1:
        do_sync = st.button("Sync to ServiceNow", key="snow_sync_btn", use_container_width=True)
    with sync_col2:
        st.markdown(
            f"<div style='padding:10px 0;font-size:0.82rem;color:#6c7a9c'>"
            f"Will push <b style='color:#ffa64d'>{total_pending}</b> changes to "
            f"<b style='color:#cdd6f4'>{st.session_state.get('snow_instance','(not configured)')}</b>"
            f" / table <b style='color:#cdd6f4'>{st.session_state.get('snow_table','(not configured)')}</b>"
            f"</div>",
            unsafe_allow_html=True)

    if do_sync:
        if not all([st.session_state.get("snow_instance"),
                    st.session_state.get("snow_user"),
                    st.session_state.get("snow_pass")]):
            st.error("Configure and save connection details before syncing.")
            return
        _snow_do_sync(state_changes, assign_changes, df)


def _snow_test_connection():
    """Attempt a lightweight GET to the SNOW instance and report result."""
    inst  = st.session_state.get("snow_instance", "").rstrip("/")
    user  = st.session_state.get("snow_user", "")
    passwd= st.session_state.get("snow_pass", "")
    table = st.session_state.get("snow_table", "sn_grc_application_security")
    if not inst:
        st.error("Enter the instance URL first.")
        return
    try:
        url = f"{inst}/api/now/table/{table}?sysparm_limit=1&sysparm_fields=sys_id"
        resp = _requests.get(url, auth=(user, passwd), timeout=10,
                             headers={"Accept": "application/json"})
        if resp.status_code == 200:
            st.success(f"Connection successful. Table `{table}` is accessible.")
        elif resp.status_code == 401:
            st.error("Authentication failed — check username/password.")
        elif resp.status_code == 403:
            st.error("Access denied — user may lack rest_service role.")
        elif resp.status_code == 404:
            st.error(f"Table `{table}` not found. Check the table name with your SNOW admin.")
        else:
            st.warning(f"Unexpected response: HTTP {resp.status_code} — {resp.text[:200]}")
    except _requests.exceptions.ConnectionError:
        st.error(f"Cannot reach `{inst}`. Check the URL and network connectivity.")
    except _requests.exceptions.Timeout:
        st.error("Connection timed out. The SNOW instance may be unreachable.")
    except Exception as e:
        st.error(f"Unexpected error: {e}")


def _snow_do_sync(state_changes: pd.DataFrame, assign_changes: pd.DataFrame,
                  df: pd.DataFrame):
    """Push all queued changes to ServiceNow via Table REST API."""
    inst   = st.session_state.get("snow_instance", "").rstrip("/")
    user   = st.session_state.get("snow_user", "")
    passwd = st.session_state.get("snow_pass", "")
    table  = st.session_state.get("snow_table", "sn_grc_application_security")
    auth   = (user, passwd)
    headers= {"Content-Type": "application/json", "Accept": "application/json"}

    # Build a Request ID → sys_id map from the loaded dataframe if sys_id column exists
    sys_id_map: dict = {}
    if "sys_id" in df.columns:
        sys_id_map = dict(zip(df["Request ID"], df["sys_id"]))

    results = {"success": 0, "skipped": 0, "failed": 0, "log": []}

    def _push(request_id: str, payload: dict):
        sys_id = sys_id_map.get(request_id)
        if not sys_id:
            results["skipped"] += 1
            results["log"].append(
                f"SKIP  {request_id} — no sys_id in dataset (SNOW cannot match without it)")
            return
        url = f"{inst}/api/now/table/{table}/{sys_id}"
        try:
            r = _requests.patch(url, auth=auth, headers=headers,
                                data=json.dumps(payload), timeout=15)
            if r.status_code in (200, 201):
                results["success"] += 1
                results["log"].append(f"OK    {request_id} → {payload}")
            else:
                results["failed"] += 1
                results["log"].append(
                    f"FAIL  {request_id} — HTTP {r.status_code}: {r.text[:120]}")
        except Exception as exc:
            results["failed"] += 1
            results["log"].append(f"ERR   {request_id} — {exc}")

    progress = st.progress(0, text="Syncing to ServiceNow...")
    total_ops = len(state_changes) + len(assign_changes)
    done = 0

    for _, row in state_changes.iterrows():
        _push(row["request_id"], {"state": row["state"], "priority": row["priority"]})
        done += 1
        progress.progress(done / total_ops, text=f"Syncing... {done}/{total_ops}")

    for _, row in assign_changes.iterrows():
        _push(row["request_id"], {"assigned_to": row["assigned_to"],
                                  "assignment_group": row["assigned_group"]})
        done += 1
        progress.progress(done / total_ops, text=f"Syncing... {done}/{total_ops}")

    progress.empty()
    st.session_state["snow_last_sync"] = datetime.now().strftime("%d %b %Y %H:%M")

    # ── Results summary ────────────────────────────────────────────────────────
    render_kpis([
        (f"{results['success']}",  "Synced OK",  NEON_GREEN,  "✅", "pushed to SNOW"),
        (f"{results['skipped']}",  "Skipped",    NEON_ORANGE, "⚠️",  "no sys_id found"),
        (f"{results['failed']}",   "Failed",     NEON_RED,    "❌", "check log below"),
    ])

    if results["skipped"] > 0:
        st.markdown(
            '<div class="warn-panel"><b>Skipped tickets</b> have no <code>sys_id</code> column '
            'in your CSV. ServiceNow requires <code>sys_id</code> to update the correct record. '
            'Re-export your CSV with the <b>sys_id</b> field included from ServiceNow.</div>',
            unsafe_allow_html=True)

    with st.expander("Sync Log", expanded=results["failed"] > 0):
        log_text = "\n".join(results["log"]) or "No operations performed."
        st.code(log_text, language=None)


# ─── Sidebar ──────────────────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown(f"""
        <div class="sidebar-logo">
            <div class="sidebar-logo-title">APPSEC<br>INTELLIGENCE</div>
            <div class="sidebar-logo-sub">Snow Ticket Dashboard</div>
        </div>
        """, unsafe_allow_html=True)

        # ── Operations section ─────────────────────────────────────────────────
        st.markdown(
            '<div style="font-size:0.58rem;letter-spacing:0.2em;text-transform:uppercase;'
            'color:#4a5568;padding:0 6px;margin-bottom:3px;font-weight:700">Operations</div>',
            unsafe_allow_html=True)

        # Reset agent radio when ops was last clicked
        if st.session_state.get("_nav_grp") == "ops" and "_nav_agent" in st.session_state:
            del st.session_state["_nav_agent"]

        def _ops_changed():
            st.session_state["_nav_grp"] = "ops"

        ops_page = st.radio("Navigation", [
            "Overview",
            "Workload Distribution",
            "Unassigned Queue",
            "Ticket Tracker",
            "SLA & Analytics",
        ], label_visibility="collapsed", key="nav", on_change=_ops_changed)

        # ── AI Agents section ───────────────────────────────────────────────────
        st.markdown(
            '<div style="margin:12px 0 3px;border-top:1px solid rgba(180,79,255,0.3);'
            'padding-top:10px;font-size:0.58rem;letter-spacing:0.2em;'
            'text-transform:uppercase;color:#b44fff;padding-left:6px;font-weight:700">'
            'AI Agents</div>',
            unsafe_allow_html=True)

        def _agent_changed():
            st.session_state["_nav_grp"] = "agent"

        agent_page = st.radio("Agent Navigation", [
            "AI Copilot",
            "Weekly Briefing",
            "ServiceNow Sync",
        ], label_visibility="collapsed", key="_nav_agent",
            index=None, on_change=_agent_changed)

        # Active page: agent takes over when explicitly selected
        page = agent_page if (st.session_state.get("_nav_grp") == "agent"
                              and agent_page is not None) else ops_page

        st.markdown('<div style="margin:16px 0;border-top:1px solid rgba(0,212,255,0.08)"></div>',
                    unsafe_allow_html=True)
        st.markdown('<div style="font-size:0.62rem;letter-spacing:0.18em;text-transform:uppercase;color:#4a5568;padding:0 4px;margin-bottom:8px">Data Source</div>',
                    unsafe_allow_html=True)

        uploaded = st.file_uploader("Upload CSV", type=["csv"], label_visibility="collapsed")

        if uploaded:
            st.success("CSV loaded from upload", icon="✅")
        elif os.path.exists(CSV_DEFAULT):
            st.info(f"Auto-loaded: {CSV_DEFAULT}", icon="📂")
        else:
            st.warning("No CSV — upload one above", icon="⚠️")

        if "df_processed" in st.session_state and st.session_state.df_processed is not None:
            df_s = st.session_state.df_processed
            total = len(df_s)
            st.divider()
            st.markdown(
                "<div style='font-size:0.62rem;letter-spacing:0.16em;text-transform:uppercase;"
                "color:#4a5568;margin-bottom:6px'>Quick Stats</div>",
                unsafe_allow_html=True)

            stats = [
                ("Total",              f"{total:,}",                                                        NEON_BLUE),
                ("Pending for Review", f"{int((df_s['State']=='Pending for Review').sum()):,}",             NEON_ORANGE),
                ("Sent for Clarif.",   f"{int((df_s['State']=='Sent for Clarification').sum()):,}",         NEON_BLUE),
                ("Rejected",           f"{int((df_s['State']=='Rejected').sum()):,}",                       NEON_RED),
                ("Closed",             f"{int((df_s['State']=='Closed').sum()):,}",                         NEON_GREEN),
                ("Unassigned",         f"{int((df_s['Assigned To Clean']=='').sum()):,}",                   NEON_ORANGE),
                ("SLA Breached",       f"{int(df_s['SLA Breached'].sum()):,}",                              NEON_RED),
            ]
            for lbl, val, col in stats:
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;align-items:center;"
                    f"padding:5px 2px;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.82rem'>"
                    f"<span style='color:#6c7a9c'>{lbl}</span>"
                    f"<span style='font-family:Orbitron,monospace;font-size:0.76rem;"
                    f"font-weight:600;color:{col}'>{val}</span>"
                    f"</div>",
                    unsafe_allow_html=True)

        st.markdown('<div style="margin:16px 0;border-top:1px solid rgba(0,212,255,0.08)"></div>',
                    unsafe_allow_html=True)

        if st.button("Refresh Data", key="refresh"):
            for k in ["df_raw", "df_processed"]:
                st.session_state.pop(k, None)
            st.rerun()

        st.markdown(f'<div style="font-size:0.62rem;color:#2d3748;text-align:center;margin-top:12px">'
                    f'{datetime.now().strftime("%d %b %Y  %H:%M:%S")}</div>',
                    unsafe_allow_html=True)

    return page, uploaded

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="AppSec Intelligence",
        page_icon="🛡",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(CSS, unsafe_allow_html=True)
    init_db()

    page, uploaded_file = render_sidebar()

    if "df_raw" not in st.session_state or st.session_state.df_raw is None:
        if uploaded_file is not None:
            try:
                st.session_state.df_raw = safe_read_csv(uploaded_file)
            except Exception as e:
                st.error(f"Failed to read uploaded file: {e}")
                st.session_state.df_raw = None
        elif os.path.exists(CSV_DEFAULT):
            try:
                st.session_state.df_raw = safe_read_csv(CSV_DEFAULT)
            except Exception as e:
                st.error(f"Failed to read {CSV_DEFAULT}: {e}")
                st.session_state.df_raw = None
        else:
            st.session_state.df_raw = None

    if st.session_state.get("df_raw") is None:
        # ── Welcome / landing screen — each st.markdown call is simple & self-contained ──
        st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)

        # Hero
        _, hero_col, _ = st.columns([1, 3, 1])
        with hero_col:
            st.markdown(
                f"<div style='text-align:center;padding:8px 0 4px'>"
                f"<div style='font-family:Orbitron,monospace;font-size:0.65rem;"
                f"letter-spacing:0.28em;color:#4a5568;text-transform:uppercase;margin-bottom:12px'>"
                f"Application Security Operations</div></div>",
                unsafe_allow_html=True)
            st.markdown(
                f"<div style='text-align:center;font-family:Orbitron,monospace;"
                f"font-size:2.4rem;font-weight:900;line-height:1.2;margin-bottom:4px;"
                f"background:linear-gradient(135deg,{NEON_BLUE},{NEON_GREEN});"
                f"-webkit-background-clip:text;-webkit-text-fill-color:transparent;"
                f"background-clip:text'>AppSec Intelligence</div>",
                unsafe_allow_html=True)
            st.markdown(
                f"<div style='text-align:center;color:#cdd6f4;font-size:1.4rem;"
                f"font-weight:600;margin-bottom:16px'>Dashboard</div>",
                unsafe_allow_html=True)
            st.markdown(
                f"<div style='text-align:center;color:#6c7a9c;font-size:0.92rem;line-height:1.7'>"
                f"Real-time visibility into your ServiceNow AppSec ticket pipeline —<br>"
                f"workload analytics, SLA tracking, and AI-assisted assignment.</div>",
                unsafe_allow_html=True)

        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

        # Get started card — single simple div
        _, card_col, _ = st.columns([1, 5, 1])
        with card_col:
            st.markdown(
                f"<div style='background:linear-gradient(135deg,rgba(0,212,255,0.07),rgba(0,255,136,0.04));"
                f"border:1px solid rgba(0,212,255,0.22);border-radius:14px;padding:24px 28px;text-align:center'>"
                f"<div style='font-size:0.65rem;letter-spacing:0.22em;text-transform:uppercase;"
                f"color:{NEON_BLUE};margin-bottom:10px;font-weight:600'>Get Started</div>"
                f"<div style='color:#cdd6f4;font-size:0.9rem;line-height:1.8'>"
                f"Use the <b style='color:{NEON_BLUE}'>Data Source</b> panel in the sidebar to upload your CSV,<br>"
                f"or place the file in the app directory as "
                f"<code style='color:{NEON_GREEN};background:rgba(0,255,136,0.1);"
                f"padding:2px 8px;border-radius:5px'>sn_grc_application_security.csv</code>"
                f"</div>"
                f"<div style='color:#4a5568;font-size:0.78rem;margin-top:10px'>"
                f"The dashboard auto-loads on startup once the file is placed in the directory.</div>"
                f"</div>",
                unsafe_allow_html=True)

        st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

        # Feature grid — 3 columns, one card per st.markdown
        st.markdown(
            f"<div style='text-align:center;font-size:0.65rem;letter-spacing:0.22em;"
            f"text-transform:uppercase;color:#4a5568;margin-bottom:14px'>Dashboard Features</div>",
            unsafe_allow_html=True)

        features = [
            (NEON_BLUE,   "📊", "Operations Overview",      "KPI metrics, state distribution, request type breakdown and group analysis"),
            (NEON_PURPLE, "👷", "Workload Distribution",    "Engineer workload bar chart, severity heatmap, and summary table by group"),
            (NEON_ORANGE, "📭", "Unassigned Queue",         "Prioritised triage view with one-click ticket assignment"),
            (NEON_GREEN,  "🔍", "Ticket Tracker",           "Full searchable registry with filters, CSV export and inline state updates"),
            (NEON_RED,    "📈", "SLA & Analytics",          "Breach rates, resolution trends and compliance by priority and type"),
        ]
        feat_cols = st.columns(5)
        for i, (color, icon, title, desc) in enumerate(features):
            with feat_cols[i]:
                st.markdown(
                    f"<div style='background:rgba(255,255,255,0.025);"
                    f"border:1px solid {color}28;border-top:2px solid {color};"
                    f"border-radius:12px;padding:18px 16px'>"
                    f"<div style='font-size:1.4rem;margin-bottom:8px'>{icon}</div>"
                    f"<div style='font-family:Orbitron,monospace;font-size:0.72rem;"
                    f"color:{color};letter-spacing:0.05em;margin-bottom:6px'>{title}</div>"
                    f"<div style='font-size:0.78rem;color:#6c7a9c;line-height:1.5'>{desc}</div>"
                    f"</div>",
                    unsafe_allow_html=True)

        st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
        return

    if "df_processed" not in st.session_state or st.session_state.df_processed is None:
        with st.spinner("Processing data..."):
            try:
                st.session_state.df_processed = process_data(
                    st.session_state.df_raw,
                    get_all_states(),
                    get_all_assignments(),
                )
            except Exception as e:
                st.error(f"Data processing error: {e}")
                st.session_state.df_processed = None
                return

    df = st.session_state.df_processed
    if df is None or df.empty:
        st.error("Loaded dataset is empty. Please check your CSV file.")
        return

    if   page == "Overview":               page_overview(df)
    elif page == "Workload Distribution":  page_workload(df)
    elif page == "Unassigned Queue":       page_unassigned(df)
    elif page == "Ticket Tracker":         page_tracker(df)
    elif page == "SLA & Analytics":        page_analytics(df)
    elif page == "AI Copilot":             page_copilot(df)
    elif page == "Weekly Briefing":        page_briefing(df)
    elif page == "ServiceNow Sync":        page_snow_sync(df)


if __name__ == "__main__":
    main()
