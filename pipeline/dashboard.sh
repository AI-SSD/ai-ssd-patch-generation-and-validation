#!/usr/bin/env bash
# =============================================================================
# dashboard.sh — live terminal grid for a run_all.sh run (refreshes every 5s).
# Also (re)writes runs/<run_id>/dashboard.html each tick for browser viewing.
#
#   ./dashboard.sh                 # newest run under runs/
#   ./dashboard.sh runs/<run_id>   # a specific run
#   REFRESH=2 ./dashboard.sh       # faster refresh
#
# Browser view (from your laptop):
#   ssh -L 8099:localhost:8099 vm-dei
#   ( cd ~/pipeline/runs/latest && python3 -m http.server 8099 )
#   open http://localhost:8099/dashboard.html
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUN_DIR="${1:-}"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$(ls -dt "$HERE"/runs/*/ 2>/dev/null | grep -v '/latest/$' | head -1)"
fi
if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
  echo "No runs found under $HERE/runs/  (start one with ./run_all.sh)"; exit 1
fi

echo "Watching ${RUN_DIR}  —  Ctrl-C to stop"; sleep 1
while true; do
  clear
  python3 "$HERE/dashboard.py" "$RUN_DIR" --term --html
  sleep "${REFRESH:-5}"
done
