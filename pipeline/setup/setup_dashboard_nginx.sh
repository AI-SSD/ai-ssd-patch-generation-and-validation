#!/usr/bin/env bash
# =============================================================================
# setup_dashboard_nginx.sh — put the AI-SSD dashboard behind nginx basic-auth.
#
# Installs nginx + apache2-utils (htpasswd), creates two bcrypt accounts
# (tiagoalmeida, joaorcampos), installs the reverse-proxy site that fronts the
# localhost dashboard (127.0.0.1:8080) on port 80, and reloads nginx.
#
# Passwords: by default STRONG RANDOM ones are generated and PRINTED ONCE at the
# end (share the professor's with him; change anytime). To choose your own:
#   TIAGO_PW='...' JOAO_PW='...' sudo -E ./setup/setup_dashboard_nginx.sh
#
# Idempotent: re-running updates the site + (re)creates the htpasswd file.
# Run on the VM (needs sudo — passwordless sudo is configured for admin):
#   ./setup/setup_dashboard_nginx.sh
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../pipeline/setup
SITE_SRC="${HERE}/nginx/ai-ssd-dashboard.conf"
SITE_DST="/etc/nginx/sites-available/ai-ssd-dashboard"
HTPASSWD="/etc/nginx/.htpasswd-ai-ssd"
UNIT_SRC="${HERE}/ai-ssd-dashboard.service"
UNIT_DST="/etc/systemd/system/ai-ssd-dashboard.service"

SUDO=""; [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

echo "==> Installing nginx + apache2-utils (if missing) ..."
if ! command -v nginx >/dev/null 2>&1 || ! command -v htpasswd >/dev/null 2>&1; then
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq nginx apache2-utils
fi

# ---- dashboard systemd unit ------------------------------------------------
# Install/refresh the dashboard service. KillMode=process (in the unit) is what
# stops a dashboard restart from killing the active benchmark run — see the long
# comment in ai-ssd-dashboard.service. daemon-reload picks up edits WITHOUT
# restarting the running dashboard, so installing this never kills a live run.
echo "==> Installing dashboard systemd unit (${UNIT_DST}) ..."
$SUDO install -m 0644 "$UNIT_SRC" "$UNIT_DST"
$SUDO systemctl daemon-reload
$SUDO systemctl enable ai-ssd-dashboard >/dev/null 2>&1 || true
# Start it only if it isn't already running (avoid an unnecessary restart that a
# careful operator would otherwise schedule around an active run).
$SUDO systemctl is-active --quiet ai-ssd-dashboard || $SUDO systemctl start ai-ssd-dashboard
if systemctl show ai-ssd-dashboard -p KillMode | grep -q "KillMode=process"; then
    echo "    KillMode=process confirmed — dashboard restarts will NOT kill active runs."
else
    echo "    WARNING: KillMode is not 'process' — a dashboard restart may kill runs!" >&2
fi

# ---- passwords -------------------------------------------------------------
# `tr | head` makes head close the pipe early → tr gets SIGPIPE (141), which
# under `set -o pipefail` + `set -e` would abort the script. The trailing
# `|| true` neutralises that expected SIGPIPE so generation is reliable.
gen_pw() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 18 || true; }
TIAGO_PW="${TIAGO_PW:-$(gen_pw)}"
JOAO_PW="${JOAO_PW:-$(gen_pw)}"

echo "==> Creating bcrypt htpasswd (${HTPASSWD}) for tiagoalmeida, joaorcampos ..."
# -c creates/truncates (first user), -B = bcrypt, -b = password on cmdline.
$SUDO htpasswd -cbB "$HTPASSWD" tiagoalmeida "$TIAGO_PW"
$SUDO htpasswd -bB  "$HTPASSWD" joaorcampos  "$JOAO_PW"
$SUDO chown root:www-data "$HTPASSWD" 2>/dev/null || true
$SUDO chmod 640 "$HTPASSWD"

# ---- site ------------------------------------------------------------------
echo "==> Installing nginx site (${SITE_DST}) ..."
$SUDO cp "$SITE_SRC" "$SITE_DST"
$SUDO ln -sfn "$SITE_DST" /etc/nginx/sites-enabled/ai-ssd-dashboard
# Drop the stock default site so our default_server wins on port 80.
[[ -e /etc/nginx/sites-enabled/default ]] && $SUDO rm -f /etc/nginx/sites-enabled/default

echo "==> Testing + reloading nginx ..."
$SUDO nginx -t
$SUDO systemctl enable nginx >/dev/null 2>&1 || true
$SUDO systemctl reload nginx 2>/dev/null || $SUDO systemctl restart nginx

# ---- dashboard server bind reminder ---------------------------------------
cat <<EOF

==> nginx is up on port 80 with basic-auth, proxying to 127.0.0.1:8080.

   Make sure the dashboard server is running bound to localhost (the default now):
     tmux new -d -s webdash '$(cd "$HERE/.." && pwd)/serve_dashboard.sh'

   Open it (basic-auth will prompt):   http://<vm-ip>/

=============================================================================
  CREDENTIALS  (store these now — the random ones are not saved anywhere)
=============================================================================
  tiagoalmeida : ${TIAGO_PW}
  joaorcampos  : ${JOAO_PW}
=============================================================================
  Change a password later:   sudo htpasswd -B ${HTPASSWD} <user>
  Add HTTPS:                 sudo apt-get install -y certbot python3-certbot-nginx && sudo certbot --nginx
EOF
