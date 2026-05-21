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

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Data

Place your ServiceNow GRC export as `sn_grc_application_security.csv` in the project directory, or upload it via the sidebar file uploader when the app starts.

Expected CSV columns:
- `Request ID`, `Request Type`, `State`
- `Application Name`, `Application ID`, `Portfolio Name`
- `Assigned To`, `Assigned Group`
- `App Exposure`, `Application Security Prioritization`
- `Signed-off By(ITSecurityChamp)`

## Deployment

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)

Deploy for free on [Streamlit Community Cloud](https://share.streamlit.io) by connecting this GitHub repository.
