# AppSec SNOW Ticket Intelligence Dashboard

A clean, light-theme Streamlit dashboard for Application Security workload management, built on ServiceNow GRC ticket data. Designed for security operations teams to track, triage, and manage AppSec assessment requests without requiring a live ServiceNow API connection.

---

## Pages & Features

| Page | Description |
|------|-------------|
| **Overview** | KPI cards, state donut, request type bar chart, group workload bar, priority donut, 30-day trend line |
| **Workload Distribution** | Engineer bar chart (Pending / Clarification only), assignment heatmap, Engineer Summary Table with per-state counts and Application ID |
| **Unassigned Queue** | Priority-sorted unassigned tickets filtered by AppSec prioritization and request type |
| **Ticket Tracker** | Full searchable/filterable registry — group filter drives engineer filter, CSV export, inline state update |
| **Assignment AI** | Recommendation engine scoring engineers by active load, critical tickets, and SLA breaches |
| **AI Copilot** | Intent-aware Q&A chatbot answering natural-language queries from live ticket data |
| **Weekly Briefing** | Auto-generated professional briefing: week period, per-group stage breakdown (Stage 1/2/3), sub-status counts, SLA summary, recommended actions |
| **ServiceNow Sync** | Write-back agent (future phase) — patch ticket states back to the SNOW instance via REST API |

> **SLA & Analytics** page has been removed from this release to keep the interface focused on core operations.

---

## Tech Stack

| Layer | Library | Version |
|-------|---------|---------|
| UI | Streamlit | >= 1.32 |
| Charts | Plotly | >= 5.18 |
| Data | Pandas | >= 2.0 |
| Numerics | NumPy | >= 1.24 |
| Storage | SQLite | auto-created |
| AI (optional) | Anthropic SDK | >= 0.20 |

---

## Quick Start

### GitHub Codespace (Recommended)

The repository includes a `.devcontainer` configuration — Codespaces will automatically install all dependencies when the environment starts.

```bash
# 1. Open the repo in a Codespace (github.com -> Code -> Codespaces -> New)
# 2. Wait for the container to build (dependencies install automatically)
# 3. Run the app:
python -m streamlit run app.py --server.port 8501 --server.address 0.0.0.0

# 4. In the Ports tab: right-click port 8501 -> Port Visibility -> Public
# 5. Share the *.app.github.dev URL
```

> Always use `python -m streamlit run app.py` (not `streamlit run`) in Codespaces to ensure the correct Python environment is used.

### Local — Windows

```bat
pip install -r requirements.txt
start.bat
```

Use `stop.bat` to shut down. App runs at `http://localhost:8501`.

### Local — Linux / macOS

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

---

## Data Setup

Place your ServiceNow GRC export as **`sn_grc_application_security.csv`** in the project root, or upload it via the sidebar file uploader when the app starts.

### Expected CSV Columns

| Column | Notes |
|--------|-------|
| `Request ID` | Unique ticket identifier |
| `Assessment Request Description` | Used for request type keyword detection |
| `Application Name` | App under review |
| `Application ID` | App identifier (e.g. APP-0001) |
| `Portfolio Name` | Business portfolio |
| `Assigned To` | Engineer name (blank = unassigned) |
| `Assigned Group` | Comma-separated group names — first group used as primary |
| `App Exposure` | Internal / External / Partner |
| `Application Security Prioritization` | Critical / High / Medium / Low / Tier 1-4 |
| `Signed-off By(ITSecurityChamp)` | Security champion sign-off |

### Derived Columns (auto-computed at runtime)

| Column | How it's derived |
|--------|-----------------|
| `State` | Empty `Assigned To` → Pending for Review; else hash-distributed across Sent for Clarification / Closed / Rejected |
| `Request Type` | Keyword parsing of `Assessment Request Description` |
| `Created Date` | Seeded random spread over last 90 days (reproducible) |
| `Days Open` | Today minus Created Date |
| `Priority` | Mapped from `Application Security Prioritization` |
| `SLA Breached` | Days Open > threshold (Critical 7d, High 14d, Medium 21d, Low 30d) |

---

## Key Groups

| Stage | Group Name |
|-------|-----------|
| Stage 1 | `ITIT-CSAppSec-Global-Support-L1` |
| Stage 2 | `ITIT-ITSSDLC-Global-Support-L1` |
| Stage 3 | `ITIT-CSSDLC-Global-Support-L1` |

---

## AI Copilot — Example Queries

The Copilot uses intent + subject detection (no API key required):

```
How many engineers are there?
Give me the engineer list
Who is overloaded?
How many critical tickets?
Which tickets are unassigned?
What is the SLA breach rate?
Show me a workload summary
```

Typo tolerance is built in (e.g. "enginner" → engineer, "critcal" → critical).

---

## Weekly Briefing Structure

Generated briefing sections:
1. Executive Summary
2. Stage Breakdown by Group (Stage 1 / Stage 2 / Stage 3) — per-state counts with unassigned breakdown
3. Overall Volume & Pipeline
4. SLA Performance
5. Workload & Capacity
6. Top Risks This Week
7. Recommended Actions

Download as `.md` file from the briefing page.

---

## ServiceNow Integration (Future Phase)

The **ServiceNow Sync** page is pre-built for PATCH write-back via REST API:

```
PATCH https://<instance>.service-now.com/api/now/table/<table>/<sys_id>
Authorization: Basic <base64(user:pass)>
Content-Type: application/json
Body: { "state": "In Progress", "assigned_to": "<sys_id>" }
```

To enable, obtain from your SNOW team:
- Instance URL
- Service account credentials (or OAuth client ID/secret)
- Table name (`sn_grc_m2m_task_applicable_control` or similar)
- `sys_id` field mapping for engineers and states

---

## File Structure

```
AppSec SNOW Ticket Intelligence Dashboard/
├── app.py                          # Full Streamlit app (single file)
├── requirements.txt                # Python dependencies
├── sn_grc_application_security.csv # Your ServiceNow data export (not committed)
├── appsec_dashboard.db             # Auto-created SQLite override store
├── start.bat                       # Windows launcher
├── stop.bat                        # Windows process killer
└── .devcontainer/
    └── devcontainer.json           # GitHub Codespaces auto-setup
```

---

## Changelog

### Latest — UI Overhaul + Feature Enhancements
- **Light theme**: white/purple Asana-style design replacing dark purple
- **Workload Distribution**: removed Closed/Rejected from chart; Engineer Summary Table now shows Pending for Review + Sent for Clarification counts per engineer
- **Ticket Tracker**: engineer filter now scoped to selected Assigned Group; removed SLA Breached column
- **Weekly Briefing**: week period header, per-group stage breakdown with sub-status and unassigned counts
- **AI Copilot**: intent+subject detection engine, typo normalization, data-driven responses
- **Navigation**: single unified radio with CSS separator for mutual exclusion
- **SLA & Analytics**: page removed from this release

---

*Built for the AppSec team — powered by Streamlit + Plotly + Pandas*
