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
import hashlib
from datetime import datetime, timedelta

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
    letter-spacing: 0.04em !important;
    border-radius: 8px !important;
    transition: all 0.25s !important;
    text-transform: uppercase !important;
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
    background: linear-gradient(135deg, rgba(0,212,255,0.06) 0%, rgba(13,21,38,0.98) 100%) !important;
    border: 1px solid {NEON_BLUE} !important;
    border-radius: 8px !important;
    color: #e2eaf8 !important;
    box-shadow: 0 0 8px rgba(0,212,255,0.1) !important;
    font-weight: 500 !important;
}}
.stTextInput > div > div > input::placeholder {{
    color: #5a6a8a !important;
}}
.stTextInput > div > div > input:focus {{
    border-color: {NEON_GREEN} !important;
    box-shadow: 0 0 0 2px rgba(0,255,136,0.18), 0 0 16px rgba(0,255,136,0.1) !important;
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
    # Each engineer is assigned to exactly ONE home group (the group with the
    # most tickets for that engineer). This prevents engineers from bleeding
    # across groups (e.g. an ITIT-ITSSDLC engineer won't appear under
    # ITIT-CSAppSec and vice versa).
    _assigned = df[df["Assigned To Clean"] != ""].copy()
    _home = (_assigned.groupby(["Assigned To Clean", "Primary Group"])
                      .size()
                      .reset_index(name="_n")
                      .sort_values("_n", ascending=False)
                      .drop_duplicates("Assigned To Clean")
                      .set_index("Assigned To Clean")["Primary Group"])
    _assigned["Home Group"] = _assigned["Assigned To Clean"].map(_home)

    all_groups = sorted(g for g in _home.unique() if g != "Unassigned")
    selected_group = st.selectbox("Filter by Assigned Group", ["All Groups"] + all_groups, key="wl_group")

    if selected_group == "All Groups":
        wdf = _assigned.copy()
    else:
        # Only include tickets for engineers whose home group is the selected group
        home_engs = _home[_home == selected_group].index
        wdf = _assigned[_assigned["Assigned To Clean"].isin(home_engs)].copy()

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

    # Use home group already computed above
    eng_group = _home

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



# ─── Sidebar ──────────────────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown(f"""
        <div class="sidebar-logo">
            <div class="sidebar-logo-title">APPSEC<br>INTELLIGENCE</div>
            <div class="sidebar-logo-sub">Snow Ticket Dashboard</div>
        </div>
        """, unsafe_allow_html=True)

        page = st.radio("Navigation", [
            "Overview",
            "Workload Distribution",
            "Unassigned Queue",
            "Ticket Tracker",
            "SLA & Analytics",
        ], label_visibility="collapsed", key="nav")

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


if __name__ == "__main__":
    main()
