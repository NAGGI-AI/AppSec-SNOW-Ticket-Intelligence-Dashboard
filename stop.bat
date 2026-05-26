@echo off
title Stop AppSec Dashboard
echo Stopping AppSec SNOW Ticket Intelligence Dashboard...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq AppSec SNOW Ticket Intelligence Dashboard" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq AppSec SNOW Ticket Intelligence Dashboard" >nul 2>&1
echo Done. Dashboard stopped.
pause
