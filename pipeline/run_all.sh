#!/usr/bin/env bash
# =============================================================================
# run_all.sh — push-button benchmark of ALL projects × ALL profiles, sequenced
# so it survives an 8-core box and one shared proxy GPU.
#
#   Stage 1  baselines once   : Phase 0+1 per project (heavy build, done 3× not 24×)
#   Stage 2  OpenAI sweep      : Phase 2/3/4 for the OpenAI profiles, in parallel
#                                (cloud inference → light VM load), capped
#   Stage 3  Ollama sweep      : Phase 2/3/4 for the Ollama profiles, serialized
#                                (they share ONE proxy GPU)
#
# Tracking: runs/<run_id>/ holds orchestrator.log (global), logs/<cell>.log (per
# project×profile), cells/<cell>.state (machine-readable status for the dashboard).
# Watch live with ./dashboard.sh. Get a phone push on finish via ntfy (see below).
#
# Usage:
#   tmux new -s benchmark            # so it survives ssh disconnect
#   export NTFY_TOPIC=my-uniq-topic  # optional push notifications (see docs)
#   ./run_all.sh
#
# Knobs (env vars, all optional):
#   PROJECTS="glibc tcpdump openssl"
#   OPENAI_PROFILES="openai-fast openai-mix openai-high openai-codex"
#   OLLAMA_PROFILES="ollama-proxy-qwen-coder ollama-proxy-deepseek ollama-proxy-devstral ollama-proxy-frontier-coder"
#   BASELINE_PROFILE=openai-fast     # builds Phase 0/1 once; all profiles reuse it
#   MAX_PARALLEL=3                   # OpenAI-sweep concurrency (VM cores/RAM)
#   OLLAMA_PARALLEL=1                # keep 1 unless the proxy GPU has lots of VRAM
#   SWEEP_PHASES="2 3 4"  BASELINE_PHASES="0 1"
#   NTFY_TOPIC / NTFY_SERVER / SLACK_WEBHOOK / DISCORD_WEBHOOK  (notifications)
#     ntfy also auto-reads config.yaml's `notifications:` block (ntfy_url /
#     ntfy_token / enabled) when NTFY_TOPIC isn't set — the env var still wins.
# =============================================================================
set -uo pipefail   # NOT -e: per-cell failures are handled, never abort the run

PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PIPELINE_ROOT"

# ---- configuration -------------------------------------------------------
# Focused profile set (current campaign). Full set kept here for reference:
#   openai: openai-fast openai-mix openai-high openai-codex
#   ollama: ollama-proxy-qwen-coder ollama-proxy-qwen ollama-proxy-deepseek \
#           ollama-proxy-devstral ollama-proxy-frontier-coder
# Override any of these via env vars (e.g. OPENAI_PROFILES="..." ./run_all.sh).
read -ra PROJECTS        <<< "${PROJECTS:-glibc tcpdump openssl}"
read -ra OPENAI_PROFILES <<< "${OPENAI_PROFILES:-openai-fast openai-codex}"
read -ra OLLAMA_PROFILES <<< "${OLLAMA_PROFILES:-ollama-proxy-qwen-coder ollama-proxy-qwen}"
BASELINE_PROFILE="${BASELINE_PROFILE:-openai-fast}"
MAX_PARALLEL="${MAX_PARALLEL:-3}"
OLLAMA_PARALLEL="${OLLAMA_PARALLEL:-1}"
SWEEP_PHASES="${SWEEP_PHASES:-2 3 4}"
BASELINE_PHASES="${BASELINE_PHASES:-0 1}"

RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
RUN_DIR="$PIPELINE_ROOT/runs/$RUN_ID"
mkdir -p "$RUN_DIR/cells" "$RUN_DIR/logs"
ln -sfn "$RUN_DIR" "$PIPELINE_ROOT/runs/latest"
GLOBAL_LOG="$RUN_DIR/orchestrator.log"
START_EPOCH="$(date +%s)"

# Record this run's process-group id so the dashboard can stop/pause/resume the
# whole run via `kill -<SIG> -<pgid>`. run_all.sh is the group leader here
# (whether launched interactively or detached with setsid), so $$ == PGID.
echo $$ > "$RUN_DIR/run_all.pgid"

# ---- helpers -------------------------------------------------------------
log() { echo "[$(date '+%F %T')] $*" | tee -a "$GLOBAL_LOG"; }

# Read one key from config.yaml's `notifications:` block (pure awk; no yq/PyYAML
# dependency, since run_all.sh may run before any venv is active).
_cfg_notif() {   # _cfg_notif <key> -> value (quotes + trailing comment stripped)
  awk -v k="$1" '
    /^[^[:space:]]/ { inblk = ($0 ~ /^notifications:/) }   # toggle on at the block, off at next top-level key
    inblk && $1 == k":" {
      sub(/^[[:space:]]*[^:]*:[[:space:]]*/, "")           # drop "key:"
      sub(/[[:space:]]*#.*$/, "")                          # drop trailing comment
      gsub(/"/, ""); sub(/[[:space:]]+$/, "")              # drop quotes + rtrim
      print; exit
    }' "$PIPELINE_ROOT/config.yaml" 2>/dev/null
}

# Read the granularity toggles + default priority from config.yaml ONCE, always
# (regardless of whether the topic came from env or config). Missing key => "true"
# so an un-tuned config is "complete" by default. These gate notify_evt below.
NOTIFY_RUN="$(_cfg_notif notify_run)";          NOTIFY_RUN="${NOTIFY_RUN:-true}"
NOTIFY_STAGE="$(_cfg_notif notify_stage)";      NOTIFY_STAGE="${NOTIFY_STAGE:-true}"
NOTIFY_PROJECT="$(_cfg_notif notify_project)";  NOTIFY_PROJECT="${NOTIFY_PROJECT:-true}"
NOTIFY_CELL="$(_cfg_notif notify_cell)";        NOTIFY_CELL="${NOTIFY_CELL:-true}"
NTFY_DEFAULT_PRIO="$(_cfg_notif default_priority)"; NTFY_DEFAULT_PRIO="${NTFY_DEFAULT_PRIO:-default}"

# If NTFY_TOPIC isn't set in the env, honor the config.yaml notifications: block
# so the user's `ntfy_url`/`enabled` there actually drives the phone push.
if [[ -z "${NTFY_TOPIC:-}" ]]; then
  _ntfy_enabled="$(_cfg_notif enabled)"
  _ntfy_url="$(_cfg_notif ntfy_url)"
  _ntfy_tok="$(_cfg_notif ntfy_token)"
  if [[ "$_ntfy_enabled" == "true" && -n "$_ntfy_url" ]]; then
    NTFY_SERVER="${_ntfy_url%/*}"     # https://ntfy.sh
    NTFY_TOPIC="${_ntfy_url##*/}"     # ai-ssd-tiago-7f3a
    [[ -n "$_ntfy_tok" ]] && NTFY_TOKEN="$_ntfy_tok"
    export NTFY_SERVER NTFY_TOPIC NTFY_TOKEN
  fi
fi

notify() {   # notify "<message>" [priority]   — ALWAYS sends (used for issues)
  local msg="$1" prio="${2:-$NTFY_DEFAULT_PRIO}"
  local auth=(); [[ -n "${NTFY_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer ${NTFY_TOKEN}")
  [[ -n "${NTFY_TOPIC:-}" ]] && curl -fsS "${auth[@]}" -H "Title: AI-SSD ${RUN_ID}" -H "Priority: ${prio}" \
       -d "$msg" "${NTFY_SERVER:-https://ntfy.sh}/${NTFY_TOPIC}" >/dev/null 2>&1
  [[ -n "${SLACK_WEBHOOK:-}" ]] && curl -fsS -X POST -H 'Content-type: application/json' \
       --data "$(printf '{"text":"%s"}' "$msg")" "$SLACK_WEBHOOK" >/dev/null 2>&1
  [[ -n "${DISCORD_WEBHOOK:-}" ]] && curl -fsS -H 'Content-type: application/json' \
       --data "$(printf '{"content":"%s"}' "$msg")" "$DISCORD_WEBHOOK" >/dev/null 2>&1
  return 0
}

notify_evt() {   # notify_evt <toggle_value> "<message>" [priority]  — gated state-change push
  local flag="$1" msg="$2" prio="${3:-$NTFY_DEFAULT_PRIO}"
  [[ "$flag" == "false" ]] && return 0
  notify "$msg" "$prio"
}

# cells/<cell>.state  ->  STATE|STAGE|STARTED|ENDED|EXIT|LOGFILE  (atomic write)
write_state() {
  local cell="$1" f="$RUN_DIR/cells/$1.state"
  printf '%s|%s|%s|%s|%s|%s\n' "$2" "$3" "$4" "$5" "$6" "$7" > "$f.tmp" && mv "$f.tmp" "$f"
}

attempt1_model() {   # echo the first model of a profile's ramp
  local f="$PIPELINE_ROOT/profiles/$1.env" m
  [[ -f "$f" ]] || { echo ""; return; }
  m="$(grep -oE 'LLM_MODELS_BY_ATTEMPT="[^"]*"' "$f" | cut -d'"' -f2 | cut -d, -f1)"
  [[ -z "$m" ]] && m="$(grep -oE 'LLM_(OPENAI_MODEL|MODEL)="[^"]*"' "$f" | head -1 | cut -d'"' -f2)"
  echo "$m"
}

# Patched Docker image tags are keyed by CVE + attempt-1 model, so parallel cells
# only collide if two profiles share an attempt-1 model. Warn loudly if so.
check_distinct_attempt1() {
  declare -A seen=(); local prof m dup=0
  for prof in "${OPENAI_PROFILES[@]}" "${OLLAMA_PROFILES[@]}"; do
    m="$(attempt1_model "$prof")"
    [[ -z "$m" ]] && { log "WARN: profile '$prof' has no resolvable attempt-1 model"; continue; }
    if [[ -n "${seen[$m]:-}" ]]; then
      log "WARN: '${seen[$m]}' and '$prof' share attempt-1 model '$m' — patched image tags WILL collide in parallel. Set MAX_PARALLEL=1 or give them distinct attempt-1 models."
      dup=1
    fi
    seen[$m]="$prof"
  done
  return $dup
}

stat_size() { stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || echo -1; }

# Copy the once-built Phase 0/1 outputs into a sweep profile's working dir so its
# Phase 2/3/4 finds the CSV + baseline manifest + PoCs. (Docker images are global.)
# Returns non-zero on a FAILED/INCOMPLETE copy so the caller can skip the cell —
# otherwise a missing/truncated manifest yields a silent all-"No Phase 1 Baseline"
# run that looks like a real (bad) result. A baseline that legitimately produced
# NO manifest (a project that reproduces 0 CVEs) is NOT an error: there is nothing
# to verify, so the sweep runs and honestly reports no baseline.
seed_cell() {
  local proj="$1" prof="$2" d
  [[ "$prof" == "$BASELINE_PROFILE" ]] && return 0   # baseline dir already has it
  local src="$PIPELINE_ROOT/projects/${proj}__${BASELINE_PROFILE}"
  local dst="$PIPELINE_ROOT/projects/${proj}__${prof}"
  [[ -d "$src" ]] || { log "WARN: no baseline dir to seed from: $src"; return 1; }
  mkdir -p "$dst"
  for d in results exploits documentation manual_supervision; do
    if [[ -d "$src/$d" ]]; then
      mkdir -p "$dst/$d"
      if ! cp -a "$src/$d/." "$dst/$d/"; then
        log "WARN: cp failed: $src/$d -> $dst/$d"; return 1
      fi
    fi
  done
  # Verify the copy is COMPLETE for the files Phase 2/3 actually read: every
  # manifest + Phase-0 CSV present in src/results must exist in dst/results with
  # an identical size. (If src has none, the project produced no baseline — fine.)
  local rel s t
  while IFS= read -r rel; do
    [[ -z "$rel" ]] && continue
    s="$src/results/$rel"; t="$dst/results/$rel"
    if [[ ! -f "$t" ]] || [[ "$(stat_size "$s")" != "$(stat_size "$t")" ]]; then
      log "WARN: incomplete seed for ${proj}__${prof}: '$rel' missing or size-mismatched in dst."
      return 1
    fi
  done < <(cd "$src/results" 2>/dev/null && ls -1 ./*image_manifest*.json ./*_cve_poc_complete.csv 2>/dev/null | sed 's#^\./##')
  return 0
}

# Run ONE (project, profile) cell in the foreground (inline) and record state.
run_cell() {
  local proj="$1" prof="$2" phases="$3" stage="$4"
  local cell="${proj}__${prof}" clog="$RUN_DIR/logs/${proj}__${prof}.log"
  local started; started="$(date +%s)"
  write_state "$cell" RUNNING "$stage" "$started" "" "" "$clog"
  log "START  $cell  [$stage]  phases='$phases'"
  notify_evt "$NOTIFY_CELL" "▶️ ${cell} started [${stage}] — phases '${phases}'"
  RUN_INLINE=1 ./run_project.sh "$proj" --profile "$prof" --phases $phases >"$clog" 2>&1
  local rc=$? ended; ended="$(date +%s)"
  local st=DONE; (( rc != 0 )) && st=FAILED
  write_state "$cell" "$st" "$stage" "$started" "$ended" "$rc" "$clog"
  log "END    $cell  $st  exit=$rc  ($((ended-started))s)"
  if (( rc != 0 )); then
    notify "❌ ${cell} FAILED (exit ${rc}) [${stage}] — runs/${RUN_ID}/logs/${cell}.log" high
  else
    notify_evt "$NOTIFY_CELL" "✅ ${cell} done [${stage}] ($((ended-started))s)"
  fi
  return $rc
}

# Run a list of "proj:prof" specs with at most $1 in flight.
run_pool() {
  local maxp="$1" stage="$2" phases="$3"; shift 3
  local spec proj prof
  for spec in "$@"; do
    proj="${spec%%:*}"; prof="${spec##*:}"
    run_cell "$proj" "$prof" "$phases" "$stage" &
    while (( $(jobs -rp | wc -l) >= maxp )); do sleep 2; done
  done
  wait
}

summarize() {   # echo "DONE FAILED OTHER"
  local f st d=0 fa=0 o=0
  for f in "$RUN_DIR"/cells/*.state; do
    [[ -e "$f" ]] || continue
    st="$(cut -d'|' -f1 "$f")"
    case "$st" in DONE) ((d++));; FAILED) ((fa++));; *) ((o++));; esac
  done
  echo "$d $fa $o"
}

# On Ctrl-C / SIGTERM: stamp every still-RUNNING cell ABORTED (so the dashboard
# never shows phantom RUNNING rows), then stop the whole process group. Disarm
# first so `kill 0` hitting ourselves doesn't re-enter the trap.
cleanup_running() {
  local f st stg started ended ex logf cell
  for f in "$RUN_DIR"/cells/*.state; do
    [[ -e "$f" ]] || continue
    IFS='|' read -r st stg started ended ex logf < "$f"
    [[ "$st" == "RUNNING" ]] || continue
    cell="$(basename "$f" .state)"
    write_state "$cell" ABORTED "$stg" "$started" "$(date +%s)" 130 "$logf"
  done
}
trap 'trap - INT TERM; log "Interrupted — aborting."; cleanup_running; rm -f "$RUN_DIR/run_all.pgid"; notify "🛑 ${RUN_ID} aborted" high; kill 0 2>/dev/null; exit 130' INT TERM

# ---- preflight -----------------------------------------------------------
log "RUN $RUN_ID  | projects: ${PROJECTS[*]}  | openai: ${OPENAI_PROFILES[*]}  | ollama: ${OLLAMA_PROFILES[*]}"
log "baseline=$BASELINE_PROFILE  max_parallel=$MAX_PARALLEL  ollama_parallel=$OLLAMA_PARALLEL"
log "Dashboard:  ./dashboard.sh $RUN_DIR     Global log: $GLOBAL_LOG"
check_distinct_attempt1 || log "NOTE: duplicate attempt-1 models above — keep MAX_PARALLEL low for affected cells."

# Provision the venv ONCE, gated on a completion sentinel (.deps-ready) — NOT on
# bin/activate, which exists before pip finishes, so an interrupted/parallel
# provision could otherwise hand cells a dependency-less venv. flock serialises it.
ensure_venv() {
  local v="$PIPELINE_ROOT/.venv"
  [[ -f "$v/.deps-ready" ]] && return 0
  exec 9>"$PIPELINE_ROOT/.venv.lock"
  if command -v flock >/dev/null 2>&1; then flock 9 || true; fi
  if [[ ! -f "$v/.deps-ready" ]]; then
    log "Provisioning virtualenv (.venv) ..."
    [[ -x "$v/bin/python3" ]] || python3 -m venv "$v"
    "$v/bin/pip" install -q --upgrade pip
    "$v/bin/pip" install -q -r "$PIPELINE_ROOT/requirements.txt" && touch "$v/.deps-ready"
  fi
  exec 9>&-
}
ensure_venv

# Initialise every (project, profile) cell as PENDING for the dashboard.
declare -A _all_profiles=()
for p in "${OPENAI_PROFILES[@]}" "${OLLAMA_PROFILES[@]}"; do _all_profiles["$p"]=1; done
for proj in "${PROJECTS[@]}"; do
  for prof in "${!_all_profiles[@]}"; do write_state "${proj}__${prof}" PENDING "" "" "" "" ""; done
done

notify_evt "$NOTIFY_RUN" "▶️ Benchmark ${RUN_ID} started: ${#PROJECTS[@]} projects × ${#_all_profiles[@]} profiles"

# ---- Stage 1: baselines once (sequential — heaviest, one cold build per project)
log "===== STAGE 1: baselines (profile=$BASELINE_PROFILE, phases='$BASELINE_PHASES') ====="
notify_evt "$NOTIFY_STAGE" "🔧 Stage 1 starting: baselines for ${#PROJECTS[@]} project(s) [profile=$BASELINE_PROFILE, phases '$BASELINE_PHASES']"
GOOD_PROJECTS=()
for proj in "${PROJECTS[@]}"; do
  notify_evt "$NOTIFY_PROJECT" "📦 Project '${proj}': building baseline (phases '$BASELINE_PHASES')"
  if run_cell "$proj" "$BASELINE_PROFILE" "$BASELINE_PHASES" baseline; then
    GOOD_PROJECTS+=("$proj")
  else
    log "WARN: baseline FAILED for $proj — skipping its sweep."
    notify "⚠️ ${RUN_ID}: baseline failed for $proj (its sweep is skipped)" high
    for prof in "${!_all_profiles[@]}"; do
      [[ "$prof" == "$BASELINE_PROFILE" ]] && continue
      write_state "${proj}__${prof}" SKIPPED "baseline-failed" "" "" "" ""
    done
  fi
done
notify_evt "$NOTIFY_STAGE" "✅ Stage 1 baselines done (${#GOOD_PROJECTS[@]}/${#PROJECTS[@]} ok)"

# Seed sweep dirs from the (now static) baseline dirs BEFORE any sweep starts.
# A failed/incomplete seed marks the cell SKIPPED so it does NOT run and report a
# bogus all-"No Phase 1 Baseline" result.
declare -A SEED_FAILED=()
log "Seeding baseline artifacts into sweep profile dirs ..."
for proj in "${GOOD_PROJECTS[@]}"; do
  for prof in "${!_all_profiles[@]}"; do
    [[ "$prof" == "$BASELINE_PROFILE" ]] && continue
    if ! seed_cell "$proj" "$prof"; then
      SEED_FAILED["${proj}__${prof}"]=1
      write_state "${proj}__${prof}" SKIPPED "seed-failed" "" "" "" ""
      log "WARN: seeding failed/incomplete for ${proj}__${prof} — skipping its sweep."
      notify "⚠️ ${RUN_ID}: seeding failed for ${proj}__${prof} (sweep skipped)" high
    fi
  done
done

# ---- Stage 2: OpenAI sweep (parallel) ------------------------------------
log "===== STAGE 2: OpenAI sweep (max_parallel=$MAX_PARALLEL, phases='$SWEEP_PHASES') ====="
specs=()
for proj in "${GOOD_PROJECTS[@]}"; do for prof in "${OPENAI_PROFILES[@]}"; do
  [[ -n "${SEED_FAILED[${proj}__${prof}]:-}" ]] && continue
  specs+=("$proj:$prof")
done; done
notify_evt "$NOTIFY_STAGE" "🔧 Stage 2 starting: OpenAI sweep — ${#specs[@]} cell(s) [max_parallel=$MAX_PARALLEL, phases '$SWEEP_PHASES']"
(( ${#specs[@]} )) && run_pool "$MAX_PARALLEL" openai-sweep "$SWEEP_PHASES" "${specs[@]}"
notify_evt "$NOTIFY_STAGE" "✅ Stage 2 OpenAI sweep done (${#specs[@]} cell(s))"

# ---- Stage 3: Ollama sweep (serialized — shared GPU) ---------------------
log "===== STAGE 3: Ollama sweep (max_parallel=$OLLAMA_PARALLEL, phases='$SWEEP_PHASES') ====="
specs=()
for proj in "${GOOD_PROJECTS[@]}"; do for prof in "${OLLAMA_PROFILES[@]}"; do
  [[ -n "${SEED_FAILED[${proj}__${prof}]:-}" ]] && continue
  specs+=("$proj:$prof")
done; done
notify_evt "$NOTIFY_STAGE" "🔧 Stage 3 starting: Ollama sweep — ${#specs[@]} cell(s) [max_parallel=$OLLAMA_PARALLEL, phases '$SWEEP_PHASES']"
(( ${#specs[@]} )) && run_pool "$OLLAMA_PARALLEL" ollama-sweep "$SWEEP_PHASES" "${specs[@]}"
notify_evt "$NOTIFY_STAGE" "✅ Stage 3 Ollama sweep done (${#specs[@]} cell(s))"

# ---- done ----------------------------------------------------------------
read -r DONE FAILED OTHER < <(summarize)
ELAPSED=$(( $(date +%s) - START_EPOCH ))
touch "$RUN_DIR/COMPLETE"
rm -f "$RUN_DIR/run_all.pgid"   # run finished — no group left to signal
MSG="🏁 ${RUN_ID} finished: ${DONE} done, ${FAILED} failed, ${OTHER} other in $((ELAPSED/3600))h$(((ELAPSED%3600)/60))m"
log "$MSG"
# Always alert when something failed (issue); otherwise gate the clean summary on notify_run.
if (( FAILED > 0 )); then
  notify "$MSG" high
else
  notify_evt "$NOTIFY_RUN" "$MSG"
fi
