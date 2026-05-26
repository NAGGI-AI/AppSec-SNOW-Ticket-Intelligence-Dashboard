# AppSec SNOW Ticket Intelligence Dashboard

A futuristic dark-theme Streamlit dashboard for Application Security workload management, built on ServiceNow GRC ticket data.

## Features

- **Overview** — KPIs, state distribution, request type breakdown, group workload, trend line
- **Workload Distribution** — Engineer assignment heatmap, group bar charts, summary table
- **Unassigned Queue** — Priority-sorted unassigned tickets with quick-assign widget
- **Ticket Tracker** — Full searchable/filterable ticket registry with CSV export and inline state updates
- **SLA & Analytics** — Breach rates, histograms, scatter plots, monthly trends
- **Assignment AI** — Recommendation engine scoring engineers by active load and SLA breaches

## Tech Stack

| Layer | Library |
|-------|---------|
| UI | Streamlit >= 1.32 |
| Charts | Plotly >= 5.18 |
| Data | Pandas >= 2.0, NumPy >= 1.24 |
| Storage | SQLite (auto-created) |

## Setup

### Local (Windows)

```bat
pip install -r requirements.txt
start.bat
```

> Use `start.bat` to launch and `stop.bat` to shut down the app.

### GitHub Codespace / Linux

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

> `streamlit` may not be on PATH in some environments — always use `python -m streamlit run app.py`.

## Data

Place your ServiceNow GRC export as `sn_grc_application_security.csv` in the project directory, or upload it via the sidebar file uploader when the app starts.

Expected CSV columns:
- `Request ID`, `Request Type`, `State`
- `Application Name`, `Application ID`, `Portfolio Name`
- `Assigned To`, `Assigned Group`
- `App Exposure`, `Application Security Prioritization`
- `Signed-off By(ITSecurityChamp)`

## Deployment

### Option 1 — GitHub Codespace (Recommended for sharing)
1. Open this repo in a Codespace
2. Run `python -m streamlit run app.py` in the terminal
3. Go to the **Ports** tab → right-click port `8501` → **Port Visibility → Public**
4. Share the generated `*.app.github.dev` URL

### Option 2 — Local Windows
Use the included `start.bat` / `stop.bat` scripts. App runs at `http://localhost:8501`.

### Option 3 — Streamlit Community Cloud *(if allowed by your org)*
Connect this GitHub repository at [share.streamlit.io](https://share.streamlit.io) and deploy `app.py` from the `main` branch.
