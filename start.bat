@echo off
title AppSec SNOW Ticket Intelligence Dashboard
echo Starting AppSec SNOW Ticket Intelligence Dashboard...
echo.
cd /d "%~dp0"
python -m streamlit run app.py --server.port 8501 --server.headless false
pause
