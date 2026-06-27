#!/usr/bin/env bash
# =============================================================================
# run_project.sh – Launch a pipeline run for a specific project in a tmux
# session.  Each project gets its own working directory under projects/<name>/
# and a tmux session named after the project.
#
# Usage:
#   ./run_project.sh <project> [extra pipeline.py flags...]
#
# Examples:
#   ./run_project.sh glibc                        # Phase 0 only (default)
#   ./run_project.sh tomcat --phases 0 1 2 3 4    # full pipeline
#   ./run_project.sh linux-kernel --phases 0      # Phase 0 only
#
# To re-attach later:
#   tmux attach -t glibc
#   tmux attach -t tomcat
#   tmux attach -t linux-kernel
#
# Detach from a session: Ctrl-B then D
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve the pipeline root (directory where this script lives)
# ---------------------------------------------------------------------------
PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Map project name → Phase 0 config file
# ---------------------------------------------------------------------------
declare -A CONFIG_MAP=(
    [glibc]="cve_aggregator/glibc_config.yaml"
    [tomcat]="cve_aggregator/tomcat_config.yaml"
    [linux-kernel]="cve_aggregator/kernel_config.yaml"
    [libxml2]="cve_aggregator/libxml2_config.yaml"
    [openssl]="cve_aggregator/openssl_config.yaml"
    [ffmpeg]="cve_aggregator/ffmpeg_config.yaml"
    [libtasn1]="cve_aggregator/libtasn1_config.yaml"
    [libtiff]="cve_aggregator/libtiff_config.yaml"
    [expat]="cve_aggregator/expat_config.yaml"
    [pcre2]="cve_aggregator/pcre2_config.yaml"
    [file]="cve_aggregator/file_config.yaml"
    [gnutls]="cve_aggregator/gnutls_config.yaml"
    [tcpdump]="cve_aggregator/tcpdump_config.yaml"
)

# ---------------------------------------------------------------------------
# Usage / argument parsing
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <project> [extra pipeline.py flags...]"
    echo ""
    echo "Available projects: ${!CONFIG_MAP[*]}"
    exit 1
fi

PROJECT="$1"
shift  # remaining args forwarded to pipeline.py

if [[ -z "${CONFIG_MAP[$PROJECT]+x}" ]]; then
    echo "Error: unknown project '$PROJECT'."
    echo "Available projects: ${!CONFIG_MAP[*]}"
    exit 1
fi

# ---------------------------------------------------------------------------
# LLM provider profile (default = openai-fast, i.e. the legacy behaviour).
# Parse `--profile <name>` out of the forwarded args; everything else is passed
# through to pipeline.py unchanged.
# ---------------------------------------------------------------------------
PROFILE="openai-fast"
FORWARD_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="${2:-}"; shift 2;;
        --profile=*)
            PROFILE="${1#*=}"; shift;;
        *)
            FORWARD_ARGS+=("$1"); shift;;
    esac
done
set -- "${FORWARD_ARGS[@]}"

PROFILE_FILE="${PIPELINE_ROOT}/profiles/${PROFILE}.env"
if [[ ! -f "${PROFILE_FILE}" ]]; then
    echo "Error: unknown profile '${PROFILE}' (no ${PROFILE_FILE})."
    echo "Available profiles:"
    ls -1 "${PIPELINE_ROOT}/profiles/"*.env 2>/dev/null | sed 's#.*/##; s#\.env$##; s/^/  - /'
    exit 1
fi

# Source the profile → exports LLM_*/OLLAMA_* into this shell.
# shellcheck disable=SC1090
source "${PROFILE_FILE}"

# Proxy basic-auth secret (gitignored, single line "username:password").
PROXY_SECRET_FILE="${PIPELINE_ROOT}/API-ollama-proxy"
if [[ -f "${PROXY_SECRET_FILE}" ]]; then
    OLLAMA_USERNAME="$(cut -d: -f1 "${PROXY_SECRET_FILE}")"
    OLLAMA_PASSWORD="$(cut -d: -f2- "${PROXY_SECRET_FILE}")"
    export OLLAMA_USERNAME OLLAMA_PASSWORD
fi

PHASE0_CONFIG="${PIPELINE_ROOT}/${CONFIG_MAP[$PROJECT]}"
# Isolate every (project, profile) run so AI families never overwrite each
# other's results/patches/manifest.
PROJECT_DIR="${PIPELINE_ROOT}/projects/${PROJECT}__${PROFILE}"

# Default to Phase 0 if no --phases flag is given
EXTRA_ARGS=("$@")
if ! printf '%s\n' "${EXTRA_ARGS[@]}" | grep -q -- '--phases'; then
    EXTRA_ARGS=("--phases" "0" "${EXTRA_ARGS[@]}")
fi

# ---------------------------------------------------------------------------
# Create project working directory (with common subdirectories)
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}"/{logs,results,manual_supervision}

# ---------------------------------------------------------------------------
# Virtual-env setup (create and populate if not present)
# ---------------------------------------------------------------------------
VENV_DIR="${PIPELINE_ROOT}/.venv"

# Provision gated on a completion sentinel (.deps-ready), serialised with flock —
# bin/activate appears before pip finishes, so gating on it can hand a parallel or
# interrupted run a dependency-less venv (→ ModuleNotFoundError in the cells).
if [[ ! -f "${VENV_DIR}/.deps-ready" ]]; then
    exec 9>"${PIPELINE_ROOT}/.venv.lock"
    if command -v flock >/dev/null 2>&1; then flock 9 || true; fi
    if [[ ! -f "${VENV_DIR}/.deps-ready" ]]; then
        echo "Provisioning virtualenv at ${VENV_DIR} ..."
        [[ -x "${VENV_DIR}/bin/python3" ]] || python3 -m venv "${VENV_DIR}"
        "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
        "${VENV_DIR}/bin/pip" install -r "${PIPELINE_ROOT}/requirements.txt" --quiet \
            && touch "${VENV_DIR}/.deps-ready"
        echo "Virtualenv ready."
    fi
    exec 9>&-
fi

VENV_ACTIVATE="source ${VENV_DIR}/bin/activate"

# ---------------------------------------------------------------------------

# Build the pipeline command
# ---------------------------------------------------------------------------
# Export API keys from secret files before running the pipeline
OPENAI_KEY_FILE="${PIPELINE_ROOT}/API-openai-key"
NVD_KEY_FILE="${PIPELINE_ROOT}/API-nvd-key"

EXPORT_API_KEYS=""
if [[ -f "${OPENAI_KEY_FILE}" ]]; then
    EXPORT_API_KEYS="export OPENAI_API_KEY=\"$(cat ${OPENAI_KEY_FILE})\"; ${EXPORT_API_KEYS}"
fi
if [[ -f "${NVD_KEY_FILE}" ]]; then
    EXPORT_API_KEYS="export NVD_API_KEY=\"$(cat ${NVD_KEY_FILE})\"; ${EXPORT_API_KEYS}"
fi

# Re-export the profile's LLM_*/OLLAMA_* vars INTO the tmux command string, so
# the python subprocess sees the selected backend regardless of the tmux
# server's ambient environment.
PROFILE_VARS=(LLM_PROVIDER LLM_OPENAI_MODEL LLM_OPENAI_BASE_URL LLM_ENDPOINT \
              LLM_MODEL LLM_MODELS LLM_MODELS_BY_ATTEMPT LLM_NUM_CTX \
              LLM_TEMPERATURE LLM_MAX_TOKENS LLM_TIMEOUT \
              OLLAMA_USERNAME OLLAMA_PASSWORD)
EXPORT_PROFILE=""
for _v in "${PROFILE_VARS[@]}"; do
    if [[ -n "${!_v:-}" ]]; then
        EXPORT_PROFILE="export ${_v}=\"${!_v}\"; ${EXPORT_PROFILE}"
    fi
done

PIPELINE_CMD="cd ${PIPELINE_ROOT}"
PIPELINE_CMD="${PIPELINE_CMD} && ${VENV_ACTIVATE}"
PIPELINE_CMD="${PIPELINE_CMD} && ${EXPORT_API_KEYS} ${EXPORT_PROFILE} python3 pipeline.py"
PIPELINE_CMD="${PIPELINE_CMD} --base-dir ${PROJECT_DIR}"
PIPELINE_CMD="${PIPELINE_CMD} --phase0-config ${PHASE0_CONFIG}"
PIPELINE_CMD="${PIPELINE_CMD} --cleanup"
for arg in "${EXTRA_ARGS[@]}"; do
    PIPELINE_CMD="${PIPELINE_CMD} ${arg}"
done

# Tee output to a timestamped log file
LOG_FILE="${PROJECT_DIR}/logs/run_$(date +%Y%m%d_%H%M%S).log"
PIPELINE_CMD="${PIPELINE_CMD} 2>&1 | tee ${LOG_FILE}"

# ---------------------------------------------------------------------------
# Inline mode (used by run_all.sh): run the pipeline in the FOREGROUND and exit
# with its real exit code (no tmux), so an orchestrator can background+wait it.
# ---------------------------------------------------------------------------
if [[ "${RUN_INLINE:-0}" == "1" ]]; then
    echo "[inline] ${PROJECT}__${PROFILE} | provider=${LLM_PROVIDER:-?} | model(s)=${LLM_MODELS_BY_ATTEMPT:-${LLM_OPENAI_MODEL:-${LLM_MODEL:-?}}}"
    set +e
    bash -lc "set -o pipefail; ${PIPELINE_CMD}"
    exit $?
fi

# ---------------------------------------------------------------------------
# Launch (or reuse) a tmux session (one per project+profile)
# ---------------------------------------------------------------------------
SESSION="${PROJECT}__${PROFILE}"
if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "tmux session '$SESSION' already exists – killing and restarting..."
    tmux kill-session -t "$SESSION"
fi

# Provenance banner: which AI backend this run uses (password never printed).
_BANNER_MODEL="${LLM_MODELS_BY_ATTEMPT:-${LLM_OPENAI_MODEL:-${LLM_MODEL:-?}}}"
_BANNER_ENDPOINT="${LLM_ENDPOINT:-${LLM_OPENAI_BASE_URL:-<OpenAI default>}}"
_BANNER_AUTH="none"; [[ -n "${OLLAMA_USERNAME:-}" && -n "${OLLAMA_PASSWORD:-}" ]] && _BANNER_AUTH="basic"

echo "Starting project '$PROJECT' in tmux session..."
echo "  Profile     : ${PROFILE}"
echo "  LLM provider: ${LLM_PROVIDER:-?}"
echo "  LLM model(s): ${_BANNER_MODEL}"
echo "  LLM endpoint: ${_BANNER_ENDPOINT}"
echo "  LLM auth    : ${_BANNER_AUTH}"
echo "  Working dir : ${PROJECT_DIR}"
echo "  Phase 0 cfg : ${PHASE0_CONFIG}"
echo "  Log file    : ${LOG_FILE}"
echo ""
echo "  Attach with : tmux attach -t ${SESSION}"
echo "  Detach      : Ctrl-B then D"

tmux new-session -d -s "$SESSION" bash -lc "${PIPELINE_CMD}; echo '--- Pipeline finished (exit \$?) ---'; exec bash"

