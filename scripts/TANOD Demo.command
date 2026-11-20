#!/bin/zsh
# Double-click to start the TANOD presentation demo and open the dashboard.
cd "$HOME/LifeOS/apps/tanod" || exit 1
pkill -f "dashboard.demo" 2>/dev/null && sleep 1   # stop an older demo if one is still running
(sleep 5; open "http://localhost:8000") &
.venv/bin/python -m dashboard.demo --lan --cameras "${TANOD_CAMERAS:-1}"
