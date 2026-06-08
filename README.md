# AppSec SNOW Ticket Intelligence Dashboard

A light-theme Streamlit dashboard for Application Security workload management, built on ServiceNow GRC ticket data. Gives AppSec teams real-time visibility into their ticket pipeline — workload analytics, engineer assignment tracking, and AI-assisted briefing — with no live SNOW API connection required.

---

## Navigation (Sidebar)

The sidebar contains a single unified radio for navigation. All 8 items below are mutually exclusive — selecting one always deselects the others.

```
Operations
  ├── Overview
  ├── Workload Distribution
  ├── Unassigned Queue
  └── Ticket Tracker
─────────────────────
AI AGENTS (separator)
  ├── AI Copilot
  ├── Weekly Briefing
  └── ServiceNow Sync
```

The sidebar also shows:
- **Data Source panel** — CSV file uploader (or auto-loads `sn_grc_application_security.csv` from the project directory)
- **Quick Stats** — live counts for Total, Pending for Review, Sent for Clarification, Rejected, Closed, Unassigned
- **Refresh Data** button — clears cached data and re-processes the CSV
- **Live timestamp** at the bottom

---

## Pages

### Overview
- 8 KPI cards: Total Tickets, Pending for Review, Sent for Clarification, Closed, Unassigned, Rejected, Active Engineers, Open Tickets
- State distribution donut chart
- Tickets by Request Type (top 10) horizontal bar chart
- Tickets by Assigned Group horizontal bar chart

### Workload Distribution
- **Group filter** dropdown (All Groups / CSAppSec / ITSSDLC / CSSDLC)
- 4 KPI cards: Total Assigned, Active Engineers, Open Issues, High/Critical count
- **Engineer Workload bar chart** — grouped bars showing `Pending for Review` and `Sent for Clarification` per engineer (Closed and Rejected excluded)
- **Engineer Summary Table** columns: Engineer, Assigned Group, Application ID, Pending for Review (count), Sent for Clarification (count), Workload (Optimal / Moderate / Overloaded)
  - Workload labels: Optimal ≤5 tickets, Moderate ≤10, Overloaded >10
- Export Summary CSV button

### Unassigned Queue
- Filters: App Security Prioritization, Request Type
- 3 KPI cards: Unassigned Tickets, High/Critical, No Prioritization
- Filtered table: Request ID, Application ID, Portfolio Name, Application Name, Request Type, State, App Exposure, Application Security Prioritization, Assigned Group
- **Quick Assign widget** — select ticket + engineer → saves assignment to SQLite + reprocesses data

### Ticket Tracker
- **Row 1 filters**: Search (App name / Request ID / App ID), State, Request Type
- **Row 2 filters**: Portfolio Name, Application ID, Assigned Group
- **Row 3 filter**: Engineer — dynamically scoped to engineers in the selected Assigned Group(s); shows all engineers if no group is selected
- Table columns: Request ID, Application ID, Portfolio Name, Application Name, Request Type, State, Assigned To, Assigned Group, App Exposure, Application Security Prioritization, Signed-off By(ITSecurityChamp)
- Export CSV button (filtered rows only)
- **Update Ticket State** expander — inline state change saved to SQLite

### AI Copilot
- Intent + subject detection engine — no API key required
- Typo normalization: e.g. `enginner` → engineer, `critcal` → critical
- Suggested question buttons that pre-fill and submit queries
- Example queries that work:
  - `How many engineers are there?` — returns direct count
  - `Give me the engineer list` — returns full engineer table
  - `Who is overloaded?` — returns most-loaded engineer
  - `How many critical tickets?` — returns per-priority breakdown
  - `Which tickets are unassigned?` — returns unassigned count by priority
  - `What is the SLA breach rate?` — returns breach rate and counts
  - `Show me a workload summary` — returns group-level summary
- If Claude API key is configured in the sidebar, responses are AI-generated; otherwise the rule engine handles all queries

### Weekly Briefing
Auto-generates a structured professional briefing from live ticket data. No API key required (Claude API enhances output if configured).

Briefing sections:
1. Executive Summary (health status, breach rate, unassigned count)
2. Stage Breakdown by Group:
   - Stage 1 — CSAppSec (`ITIT-CSAppSec-Global-Support-L1`)
   - Stage 2 — ITSSDLC (`ITIT-ITSSDLC-Global-Support-L1`)
   - Stage 3 — CSSDLC (`ITIT-CSSDLC-Global-Support-L1`)
   - Each group shows: New/Pending Review, In Progress/Clarification, Approved/Closed, Cancelled/Rejected counts with % and unassigned count
3. Overall Volume & Pipeline table
4. SLA Performance (breach rate, avg days open, avg resolution time, per-priority compliance table)
5. Workload & Capacity (unassigned, overloaded engineers, top/lightest engineer)
6. Top Risks This Week
7. Recommended Actions

Header shows: `Week of DD Mon – DD Mon YYYY` and report date. Download as `.md` file.

### ServiceNow Sync
- Requires `requests` package (included in `requirements.txt`)
- Configure: SNOW instance URL, username, password, table name
- **Test Connection** — GET request to verify credentials and table access
- Reads queued state changes and assignment changes from SQLite
- **Sync to ServiceNow** — sends PATCH requests to `api/now/table/{table}/{sys_id}` for each queued change
- Displays sync results: Synced OK / Skipped (no sys_id) / Failed
- Expandable sync log with per-ticket status
- Note: requires `sys_id` column in the CSV export for write-back to work

---

## Tech Stack

| Layer | Library | Version |
|-------|---------|---------|
| UI | Streamlit | >= 1.32 |
| Charts | Plotly | >= 5.18 |
| Data | Pandas | >= 2.0 |
| Numerics | NumPy | >= 1.24 |
| Storage | SQLite | auto-created as `appsec_dashboard.db` |
| AI (optional) | Anthropic SDK | >= 0.40 |
| SNOW sync (optional) | requests | >= 2.31 |

---

## Quick Start

### GitHub Codespace (Recommended)

The repo includes a `.devcontainer/devcontainer.json` — Codespaces builds the container and auto-runs `pip install -r requirements.txt` on creation.

```bash
# 1. Open the repo in a Codespace:
#    github.com → Code → Codespaces → New codespace on main
# 2. Wait for the postCreateCommand to finish (dependencies install automatically)
# 3. In the terminal, run:
python -m streamlit run app.py --server.port 8501 --server.address 0.0.0.0

# 4. Ports tab → right-click 8501 → Port Visibility → Public
# 5. Share the *.app.github.dev URL
```

> Always use `python -m streamlit run app.py` in Codespaces — not `streamlit run` — to ensure the correct Python environment is used.

### Local — Windows

```bat
pip install -r requirements.txt
start.bat
```

`stop.bat` shuts the app down. Runs at `http://localhost:8501`.

### Local — Linux / macOS

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

---

## Data Setup

Place your ServiceNow GRC export as **`sn_grc_application_security.csv`** in the project root directory, or upload it via the **Data Source** panel in the sidebar.

The app auto-detects encoding (UTF-8, Latin-1, CP1252) so no manual conversion is needed.

### CSV Columns Used

| Column | Used For |
|--------|----------|
| `Request ID` | Unique ticket identifier |
| `Request Type` | Shown directly; falls back to keyword detection from Description if blank |
| `Assessment Request Description` | Keyword detection for Request Type when blank |
| `State` | Shown directly if valid; derived if blank or unrecognised |
| `Assigned To` | Blank → Pending for Review; non-blank → drives state derivation |
| `Assigned Group` | Comma-separated; first value used as Primary Group |
| `Application Name` | Ticket context |
| `Application ID` | Shown in tables; decimal suffix (e.g. `12345.0`) auto-stripped to `12345` |
| `Portfolio Name` | Filter / grouping |
| `BCM criticality` | Combined with AppSec Prioritization to derive Priority score |
| `Application Security Prioritization` | Combined with BCM criticality for Priority |
| `App Exposure` | Shown in tables and queue |
| `Application Status` | Included in processing |
| `Signed-off By(ITSecurityChamp)` | Shown in Ticket Tracker table |
| `sys_id` | Required for ServiceNow Sync write-back (optional column) |

### Derived / Computed Columns

| Column | How It's Derived |
|--------|-----------------|
| `Priority` | Score = BCM×0.6 + AppSec×0.4 → Critical (≥3.4) / High (≥2.5) / Medium (≥1.5) / Low |
| `Priority Score` | Raw numeric score from BCM + AppSec weights |
| `SLA Days` | Critical=7, High=14, Medium=21, Low=30 |
| `Created Date` | Seeded random spread over last 90 days (seed=42, reproducible) |
| `Days Open` | Today − Created Date |
| `SLA Breached` | Days Open > SLA Days |
| `State` | DB override → blank Assigned To → Pending for Review → CSV value → hash-based stable derivation |
| `Primary Group` | First value in `Assigned Group` (comma-split) |
| `Assigned To Clean` | Blank/null/N/A → empty string; else stripped value |

### State Derivation Logic (when no override and CSV state is missing)

- Empty `Assigned To` → `Pending for Review`
- MD5 hash of `Request ID` mod 100:
  - 0–17 → `Closed`
  - 18–37 → `Rejected`
  - 38–57 → `Sent for Clarification`
  - 58–99 → `Pending for Review`

### Engineer Group Override

One hard-coded override is applied after processing:
- `Sriram Balasubramanian` is always assigned to `ITIT-CSAppSec-Global-Support-L1`

---

## Key Groups (Stages)

| Stage | Group Name |
|-------|-----------|
| Stage 1 | `ITIT-CSAppSec-Global-Support-L1` |
| Stage 2 | `ITIT-ITSSDLC-Global-Support-L1` |
| Stage 3 | `ITIT-CSSDLC-Global-Support-L1` |

The Workload Distribution page ensures ITSSDLC engineers never appear under the CSAppSec filter.

---

## Request Type Detection (Keyword Rules)

If `Request Type` in the CSV is blank, the app detects it from `Assessment Request Description` using these keyword rules:

| Keywords | Detected Type |
|----------|--------------|
| `dast false positive`, `false positive dast` | DAST False Positive reviews |
| `manual dast`, `manual dynamic` | Manual DAST Assessments |
| `sast false positive`, `false positive sast` | SAST False Positive reviews |
| `manual sast`, `manual static` | Manual SAST Assessments |
| `masa` | MASA Request |
| `oss false positive`, `open source false positive`, `sca false positive` | OSS False Positive Reviews |
| `security requirement`, `design review`, `architecture review` | Security Requirements/Design Review |
| `sign off`, `signoff`, `sign-off`, `security approval`, `security sign` | Security Sign-off request |

---

## SQLite Persistence

`appsec_dashboard.db` is auto-created at startup with two tables:

| Table | Purpose |
|-------|---------|
| `ticket_states` | Stores state, priority, notes overrides per `request_id` |
| `assignments` | Stores engineer assignment overrides per `request_id` |

These overrides take priority over CSV values on every data reload. Use **Refresh Data** in the sidebar to re-apply them against the latest CSV.

---

## File Structure

```
AppSec SNOW Ticket Intelligence Dashboard/
├── app.py                              # Full Streamlit app (~3200 lines, single file)
├── requirements.txt                    # Python dependencies
├── sn_grc_application_security.csv     # Your ServiceNow data export (not committed)
├── appsec_dashboard.db                 # Auto-created SQLite at runtime (not committed)
├── start.bat                           # Windows launcher
├── stop.bat                            # Windows process killer
├── .devcontainer/
│   └── devcontainer.json               # GitHub Codespaces auto-setup
└── README.md
```

---

## ServiceNow Integration (Sync Page)

The ServiceNow Sync page sends PATCH requests using the SNOW Table REST API:

```
PATCH https://<instance>.service-now.com/api/now/table/<table>/<sys_id>
Authorization: Basic <base64(user:pass)>
Content-Type: application/json

{ "state": "In Progress" }          # state change
{ "assigned_to": "<sys_id>",        # assignment change
  "assignment_group": "<sys_id>" }
```

To enable write-back, obtain from your SNOW admin:
- Instance URL (e.g. `https://yourcompany.service-now.com`)
- Service account credentials with `rest_service` role
- Table name (e.g. `sn_grc_application_security`)
- Re-export your CSV with the `sys_id` field included — the app uses it to match records

---

## Changelog

### Current Release
- **Light theme**: white/purple Asana-style design (was dark purple/black)
- **Workload Distribution**: bar chart shows only Pending for Review + Sent for Clarification (Closed/Rejected removed); Engineer Summary Table replaced Unique Apps + Total Assigned with per-state counts
- **Ticket Tracker**: engineer filter dynamically scoped to selected Assigned Group; SLA Breached column removed
- **Weekly Briefing**: week period in header; Stage 1/2/3 per-group breakdown with New/In Progress/Approved/Cancelled sub-status counts and unassigned counts per state
- **AI Copilot**: intent + subject detection engine with typo normalization; suggested question buttons; data-driven answers
- **Navigation**: single unified radio with CSS separator for guaranteed mutual exclusion
- **Codespace**: `.devcontainer/devcontainer.json` added for auto dependency install and port forwarding
- **SLA & Analytics** page hidden from navigation for this release (code retained)

---

*Built for the AppSec team — Streamlit + Plotly + Pandas + SQLite*
