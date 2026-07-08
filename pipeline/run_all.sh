#!/usr/bin/env bash
# =============================================================================
# run_all.sh — push-button benchmark of ALL projects × ALL profiles, sequenced
# so it survives an 8-core box and one shared proxy GPU.
#
#   Stage 1  baselines once   : Phase 0+1 per project (heavy build, done 3× not 24×)
#   Stage 2  OpenAI sweep      : Phase 2/3/4 for the OpenAI profiles, in parallel
#                                (cloud inference → light VM load), capped
#   Stage 3  Ollama sweep      : two-lane pipeline for the Ollama profiles:
#                                Phase 2 generation feeds a Phase 3/4 validation
#                                lane so validation can overlap the next cell's
#                                generation. GPU-bound inference still serializes
#                                safely via the host-global gpu_lock.
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
#   OLLAMA_PARALLEL=1                # Phase-2 generation lane width (currently 1)
#   OLLAMA_VALIDATE_PARALLEL=1       # Phase-3/4 validation lane width
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
OLLAMA_VALIDATE_PARALLEL="${OLLAMA_VALIDATE_PARALLEL:-1}"
SWEEP_PHASES="${SWEEP_PHASES:-2 3 4}"
BASELINE_PHASES="${BASELINE_PHASES:-0 1}"
# Repeat the SWEEP (Phase 2/3/4) this many times over the SAME once-built baseline
# (Phase 0/1) — for run-to-run variance on the stochastic generation/feedback.
# Each repeat writes to its own projects/<proj>__<prof>__rep<K>/ dir. 1 = today's
# single sweep, byte-identical (no RUN_TAG, no repeat loop overhead).
REPEATS="${REPEATS:-1}"
[[ "$REPEATS" =~ ^[0-9]+$ ]] && (( REPEATS >= 1 )) || REPEATS=1
# When "true", skip the Stage-1 baseline BUILD for any project that already has a
# usable baseline (image manifest + Phase-0 CSV) in its baseline dir, and just run
# the sweep(s). Lets repeated campaigns reuse a baseline instead of rebuilding it.
REUSE_BASELINE="${REUSE_BASELINE:-false}"
# OVERLAP_FAMILIES=true runs the OpenAI sweep (Stage 2) and the Ollama sweep
# (Stage 3) CONCURRENTLY instead of one after the other, so the remote Ollama GPU
# is kept busy during the (CPU/API-bound) OpenAI sweep. Safe: OpenAI cells use no
# GPU, the Python-side gpu_lock serialises Ollama inference, and patched
# image/container names are now per-cell-unique. CAVEAT: builds are make -j$(nproc);
# concurrent Stage-2 + Stage-3 builds share the CPU, so keep MAX_PARALLEL and
# OLLAMA_VALIDATE_PARALLEL modest when overlapping. Default false = sequential.
OVERLAP_FAMILIES="${OVERLAP_FAMILIES:-false}"
# REPEAT_PARALLEL=true runs the REPEATS concurrently (each repeat is independent;
# generation is network-bound, only compiles queue on CPU). Relies on the
# per-repeat-unique patched image tags. Same make -j$(nproc) CPU caveat as above.
# Default false = repeats run sequentially.
REPEAT_PARALLEL="${REPEAT_PARALLEL:-false}"

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
  local tag="${RUN_TAG:+__${RUN_TAG}}"
  # An UNTAGGED sweep of the baseline profile reuses the baseline dir in place
  # (today's behavior); a TAGGED repeat sweep always needs its own dir seeded
  # from the once-built baseline dir.
  [[ "$prof" == "$BASELINE_PROFILE" && -z "$tag" ]] && return 0
  local src="$PIPELINE_ROOT/projects/${proj}__${BASELINE_PROFILE}"
  local dst="$PIPELINE_ROOT/projects/${proj}__${prof}${tag}"
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

# True when a project already has a usable Phase 0/1 baseline (image manifest +
# Phase-0 CSV) in its baseline dir — so REUSE_BASELINE can skip the rebuild.
baseline_exists() {
  local proj="$1" d="$PIPELINE_ROOT/projects/${proj}__${BASELINE_PROFILE}/results"
  [[ -d "$d" ]] || return 1
  compgen -G "$d"/*image_manifest*.json >/dev/null 2>&1 || return 1
  compgen -G "$d"/*_cve_poc_complete.csv >/dev/null 2>&1 || return 1
  return 0
}

# Run ONE (project, profile) cell in the foreground (inline) and record state.
# RUN_TAG (exported per repeat) suffixes the cell name + the run_project.sh base
# dir; empty ⇒ the historical untagged cell.
run_cell() {
  local proj="$1" prof="$2" phases="$3" stage="$4"
  local tag="${RUN_TAG:+__${RUN_TAG}}"
  local cell="${proj}__${prof}${tag}" clog="$RUN_DIR/logs/${proj}__${prof}${tag}.log"
  local started; started="$(date +%s)"
  mkdir -p "$(dirname "$clog")"
  write_state "$cell" RUNNING "$stage" "$started" "" "" "$clog"
  log "START  $cell  [$stage]  phases='$phases'"
  notify_evt "$NOTIFY_CELL" "▶️ ${cell} started [${stage}] — phases '${phases}'"
  printf '\n[%s] ===== %s [%s] phases=%s =====\n' "$(date '+%F %T')" "$cell" "$stage" "$phases" >>"$clog"
  RUN_INLINE=1 ./run_project.sh "$proj" --profile "$prof" --phases $phases >>"$clog" 2>&1
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

queue_cell_stage() {   # queue_cell_stage <project> <profile> <stage>
  local proj="$1" prof="$2" stage="$3"
  local tag="${RUN_TAG:+__${RUN_TAG}}"
  local cell="${proj}__${prof}${tag}" clog="$RUN_DIR/logs/${proj}__${prof}${tag}.log"
  write_state "$cell" PENDING "$stage" "" "" "" "$clog"
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

run_ollama_two_lane() {
  local validate_parallel="$1"; shift
  local specs=("$@")
  local -a validate_queue=()
  local -a validate_pids=()
  local -a validate_specs=()
  local spec proj prof

  if (( OLLAMA_PARALLEL != 1 )); then
    log "WARN: OLLAMA_PARALLEL=${OLLAMA_PARALLEL} requested, but the two-lane Ollama scheduler currently runs a single Phase-2 generation lane. Using 1 generation lane."
  fi
  if (( validate_parallel < 1 )); then
    log "WARN: OLLAMA_VALIDATE_PARALLEL=${validate_parallel} is invalid; using 1."
    validate_parallel=1
  fi

  _reap_validate_jobs() {
    local -a keep_pids=()
    local -a keep_specs=()
    local idx vpid
    for idx in "${!validate_pids[@]}"; do
      vpid="${validate_pids[$idx]}"
      [[ -n "$vpid" ]] || continue
      if kill -0 "$vpid" 2>/dev/null; then
        keep_pids+=("$vpid")
        keep_specs+=("${validate_specs[$idx]}")
      else
        wait "$vpid" || true
      fi
    done
    validate_pids=("${keep_pids[@]}")
    validate_specs=("${keep_specs[@]}")
  }

  _start_validate_job() {
    local vspec="$1" vproj vprof
    vproj="${vspec%%:*}"; vprof="${vspec##*:}"
    run_cell "$vproj" "$vprof" "3 4" "ollama-validate" &
    validate_pids+=("$!")
    validate_specs+=("$vspec")
  }

  _pump_validate_jobs() {
    _reap_validate_jobs
    while (( ${#validate_queue[@]} > 0 && ${#validate_pids[@]} < validate_parallel )); do
      _start_validate_job "${validate_queue[0]}"
      validate_queue=("${validate_queue[@]:1}")
    done
  }

  for spec in "${specs[@]}"; do
    proj="${spec%%:*}"; prof="${spec##*:}"
    _pump_validate_jobs
    if run_cell "$proj" "$prof" "2" "ollama-generate"; then
      queue_cell_stage "$proj" "$prof" "ollama-validate-queued"
      validate_queue+=("$spec")
      _pump_validate_jobs
    else
      log "WARN: skipping validation for ${proj}__${prof} because Phase 2 failed."
    fi
  done

  while (( ${#validate_queue[@]} > 0 || ${#validate_pids[@]} > 0 )); do
    _pump_validate_jobs
    (( ${#validate_queue[@]} == 0 && ${#validate_pids[@]} == 0 )) && break
    sleep 2
  done
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
    [[ "$st" == "RUNNING" || ( "$st" == "PENDING" && "$stg" == "ollama-validate-queued" ) ]] || continue
    cell="$(basename "$f" .state)"
    write_state "$cell" ABORTED "$stg" "$started" "$(date +%s)" 130 "$logf"
  done
}
trap 'trap - INT TERM; log "Interrupted — aborting."; cleanup_running; rm -f "$RUN_DIR/run_all.pgid"; notify "🛑 ${RUN_ID} aborted" high; kill 0 2>/dev/null; exit 130' INT TERM

# ---- preflight -----------------------------------------------------------
log "RUN $RUN_ID  | projects: ${PROJECTS[*]}  | openai: ${OPENAI_PROFILES[*]}  | ollama: ${OLLAMA_PROFILES[*]}"
log "baseline=$BASELINE_PROFILE  max_parallel=$MAX_PARALLEL  ollama_parallel=$OLLAMA_PARALLEL  ollama_validate_parallel=$OLLAMA_VALIDATE_PARALLEL"
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
  # The untagged baseline cell (Stage 1) always shows.
  write_state "${proj}__${BASELINE_PROFILE}" PENDING "" "" "" "" ""
  for prof in "${!_all_profiles[@]}"; do
    if (( REPEATS > 1 )); then
      for (( rep=1; rep<=REPEATS; rep++ )); do
        write_state "${proj}__${prof}__rep${rep}" PENDING "" "" "" "" ""
      done
    else
      write_state "${proj}__${prof}" PENDING "" "" "" "" ""
    fi
  done
done

notify_evt "$NOTIFY_RUN" "▶️ Benchmark ${RUN_ID} started: ${#PROJECTS[@]} projects × ${#_all_profiles[@]} profiles"

# ---- Stage 1: baselines once (sequential — heaviest, one cold build per project)
log "===== STAGE 1: baselines (profile=$BASELINE_PROFILE, phases='$BASELINE_PHASES') ====="
notify_evt "$NOTIFY_STAGE" "🔧 Stage 1 starting: baselines for ${#PROJECTS[@]} project(s) [profile=$BASELINE_PROFILE, phases '$BASELINE_PHASES']"
GOOD_PROJECTS=()
export RUN_TAG=""   # baseline is ALWAYS untagged; only the sweep loop sets RUN_TAG
for proj in "${PROJECTS[@]}"; do
  if [[ "$REUSE_BASELINE" == "true" ]] && baseline_exists "$proj"; then
    log "REUSE: existing baseline found for $proj — skipping Phase '$BASELINE_PHASES' build."
    write_state "${proj}__${BASELINE_PROFILE}" DONE baseline-reused "" "$(date +%s)" 0 ""
    GOOD_PROJECTS+=("$proj")
    notify_evt "$NOTIFY_PROJECT" "♻️ Project '${proj}': reusing existing baseline"
    continue
  fi
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

# Sweep — optionally repeated REPEATS times over the SAME (static) baseline, each
# repeat isolated in its own RUN_TAG dir, for run-to-run variance on the stochastic
# generation/feedback. REPEATS=1 ⇒ exactly one untagged sweep (today's behavior).
# OVERLAP_FAMILIES overlaps Stage 2 & 3; REPEAT_PARALLEL runs repeats concurrently.

# Run ONE repeat (index $1): set its own RUN_TAG, seed its sweep dirs, then run the
# OpenAI (Stage 2) and Ollama (Stage 3) sweeps — sequentially, or overlapped when
# OVERLAP_FAMILIES=true. Safe to background (REPEAT_PARALLEL): RUN_TAG is exported
# inside this function, so a backgrounded subshell gets its OWN tag; SEED_FAILED
# and the spec arrays are local; per-repeat dirs + per-cell image tags isolate it.
run_one_repeat() {
  local rep="$1"
  if (( REPEATS > 1 )); then
    export RUN_TAG="rep${rep}"
    log "########## SWEEP REPEAT ${rep}/${REPEATS}  (tag=${RUN_TAG}) ##########"
    notify_evt "$NOTIFY_STAGE" "🔁 Sweep repeat ${rep}/${REPEATS} starting"
  else
    export RUN_TAG=""
  fi
  local TAG_SUFFIX="${RUN_TAG:+__${RUN_TAG}}"

  # Seed each sweep dir from the (now static) baseline dir BEFORE the sweep starts.
  # A failed/incomplete seed marks the cell SKIPPED so it does NOT run and report a
  # bogus all-"No Phase 1 Baseline" result.
  local -A SEED_FAILED=()
  local proj prof
  log "Seeding baseline artifacts into sweep dirs${TAG_SUFFIX:+ ($RUN_TAG)} ..."
  for proj in "${GOOD_PROJECTS[@]}"; do
    for prof in "${!_all_profiles[@]}"; do
      [[ "$prof" == "$BASELINE_PROFILE" && -z "$TAG_SUFFIX" ]] && continue
      if ! seed_cell "$proj" "$prof"; then
        SEED_FAILED["${proj}__${prof}${TAG_SUFFIX}"]=1
        write_state "${proj}__${prof}${TAG_SUFFIX}" SKIPPED "seed-failed" "" "" "" ""
        log "WARN: seeding failed/incomplete for ${proj}__${prof}${TAG_SUFFIX} — skipping its sweep."
        notify "⚠️ ${RUN_ID}: seeding failed for ${proj}__${prof}${TAG_SUFFIX} (sweep skipped)" high
      fi
    done
  done

  # Build BOTH spec lists up front (separate arrays so an overlapped run never
  # clobbers the other stage's specs).
  local -a openai_specs=() ollama_specs=()
  for proj in "${GOOD_PROJECTS[@]}"; do for prof in "${OPENAI_PROFILES[@]}"; do
    [[ -n "${SEED_FAILED[${proj}__${prof}${TAG_SUFFIX}]:-}" ]] && continue
    openai_specs+=("$proj:$prof")
  done; done
  for proj in "${GOOD_PROJECTS[@]}"; do for prof in "${OLLAMA_PROFILES[@]}"; do
    [[ -n "${SEED_FAILED[${proj}__${prof}${TAG_SUFFIX}]:-}" ]] && continue
    ollama_specs+=("$proj:$prof")
  done; done

  # Stage runners (read the locals above via bash dynamic scope; safe when
  # backgrounded — the subshell forks with the current scope).
  _stage2_openai() {
    log "===== STAGE 2: OpenAI sweep${TAG_SUFFIX:+ ($RUN_TAG)} (max_parallel=$MAX_PARALLEL, phases='$SWEEP_PHASES') ====="
    notify_evt "$NOTIFY_STAGE" "🔧 Stage 2${TAG_SUFFIX:+ ($RUN_TAG)}: OpenAI sweep — ${#openai_specs[@]} cell(s) [max_parallel=$MAX_PARALLEL, phases '$SWEEP_PHASES']"
    (( ${#openai_specs[@]} )) && run_pool "$MAX_PARALLEL" openai-sweep "$SWEEP_PHASES" "${openai_specs[@]}"
    notify_evt "$NOTIFY_STAGE" "✅ Stage 2${TAG_SUFFIX:+ ($RUN_TAG)} OpenAI sweep done (${#openai_specs[@]} cell(s))"
  }
  _stage3_ollama() {
    log "===== STAGE 3: Ollama sweep${TAG_SUFFIX:+ ($RUN_TAG)} (gen_parallel=$OLLAMA_PARALLEL, validate_parallel=$OLLAMA_VALIDATE_PARALLEL, phases='$SWEEP_PHASES') ====="
    notify_evt "$NOTIFY_STAGE" "🔧 Stage 3${TAG_SUFFIX:+ ($RUN_TAG)}: Ollama two-lane sweep — ${#ollama_specs[@]} cell(s) [gen_parallel=$OLLAMA_PARALLEL, validate_parallel=$OLLAMA_VALIDATE_PARALLEL, phases '$SWEEP_PHASES']"
    (( ${#ollama_specs[@]} )) && run_ollama_two_lane "$OLLAMA_VALIDATE_PARALLEL" "${ollama_specs[@]}"
    notify_evt "$NOTIFY_STAGE" "✅ Stage 3${TAG_SUFFIX:+ ($RUN_TAG)} Ollama sweep done (${#ollama_specs[@]} cell(s))"
  }

  if [[ "$OVERLAP_FAMILIES" == "true" ]]; then
    log "OVERLAP_FAMILIES${TAG_SUFFIX:+ ($RUN_TAG)}: OpenAI (Stage 2) & Ollama (Stage 3) sweeps run concurrently."
    _stage2_openai &
    local _s2pid=$!
    _stage3_ollama
    wait "$_s2pid"
  else
    _stage2_openai
    _stage3_ollama
  fi
}

_repeat_pids=()
for (( rep=1; rep<=REPEATS; rep++ )); do
  if [[ "$REPEAT_PARALLEL" == "true" ]] && (( REPEATS > 1 )); then
    run_one_repeat "$rep" &
    _repeat_pids+=("$!")
  else
    run_one_repeat "$rep"
  fi
done
# Wait for any backgrounded repeats before the run is marked COMPLETE.
if (( ${#_repeat_pids[@]} )); then
  for _p in "${_repeat_pids[@]}"; do wait "$_p" 2>/dev/null || true; done
fi
export RUN_TAG=""

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
