#!/usr/bin/env bash
# =============================================================================
# serve_dashboard.sh — live web dashboard + LOG VIEWER (dashboard_server.py).
# Renders the project x profile grid where each cell links to its full logs
# (orchestration + detailed per-phase output), ANSI-stripped and auto-refreshing.
#
#   ./serve_dashboard.sh                       # 127.0.0.1:8080 (behind nginx auth)
#   PORT=8080 BIND=127.0.0.1 ./serve_dashboard.sh runs/<run_id>
#
# The dashboard now has run-control + DELETE endpoints, so it binds 127.0.0.1 by
# default and is meant to sit BEHIND the nginx basic-auth reverse proxy on 80/443
# (see setup/setup_dashboard_nginx.sh). nginx terminates auth and proxies to this
# localhost port; the mutating endpoints additionally refuse any non-localhost
# client, so even an accidental BIND=0.0.0.0 stays read-only from the network.
#
#   Browser (after running setup_dashboard_nginx.sh):  http://<vm-ip>/  (auth)
#   Or tunnel straight to the app:  ssh -L 8080:localhost:8080 vm-dei
#
# Run detached so it survives ssh disconnect:
#   tmux new -d -s webdash './serve_dashboard.sh'
#
# ⚠ Do NOT set BIND=0.0.0.0 in production: it would expose the (read-only) status
#   and logs unauthenticated on the internal network. Keep it localhost + nginx.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8080}"
BIND="${BIND:-127.0.0.1}"
RUN_DIR="${1:-$HERE/runs/latest}"
[[ -d "$RUN_DIR" ]] || echo "Note: $RUN_DIR not found — dashboard starts without a run grid (start a run via Run Control)"
exec python3 "$HERE/dashboard_server.py" "$RUN_DIR" --port "$PORT" --bind "$BIND"
