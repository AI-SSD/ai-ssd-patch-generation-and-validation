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

PHASE0_CONFIG="${PIPELINE_ROOT}/${CONFIG_MAP[$PROJECT]}"
PROJECT_DIR="${PIPELINE_ROOT}/projects/${PROJECT}"

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

if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
    echo "No .venv found – creating virtualenv at ${VENV_DIR} ..."
    python3 -m venv "${VENV_DIR}"
    echo "Installing dependencies from requirements.txt ..."
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
    "${VENV_DIR}/bin/pip" install -r "${PIPELINE_ROOT}/requirements.txt" --quiet
    echo "Virtualenv ready."
fi

VENV_ACTIVATE="source ${VENV_DIR}/bin/activate"

# ---------------------------------------------------------------------------

# Build the pipeline command
# ---------------------------------------------------------------------------
# Export API keys from secret files before running the pipeline
OPENAI_KEY_FILE="${PIPELINE_ROOT}/cve_aggregator/API-openai-key"
NVD_KEY_FILE="${PIPELINE_ROOT}/cve_aggregator/API-nvd-key"

EXPORT_API_KEYS=""
if [[ -f "${OPENAI_KEY_FILE}" ]]; then
    EXPORT_API_KEYS="export OPENAI_API_KEY=\"$(cat ${OPENAI_KEY_FILE})\"; ${EXPORT_API_KEYS}"
fi
if [[ -f "${NVD_KEY_FILE}" ]]; then
    EXPORT_API_KEYS="export NVD_API_KEY=\"$(cat ${NVD_KEY_FILE})\"; ${EXPORT_API_KEYS}"
fi

PIPELINE_CMD="cd ${PIPELINE_ROOT}"
PIPELINE_CMD="${PIPELINE_CMD} && ${VENV_ACTIVATE}"
PIPELINE_CMD="${PIPELINE_CMD} && ${EXPORT_API_KEYS} python3 pipeline.py"
PIPELINE_CMD="${PIPELINE_CMD} --base-dir ${PROJECT_DIR}"
PIPELINE_CMD="${PIPELINE_CMD} --phase0-config ${PHASE0_CONFIG}"
for arg in "${EXTRA_ARGS[@]}"; do
    PIPELINE_CMD="${PIPELINE_CMD} ${arg}"
done

# Tee output to a timestamped log file
LOG_FILE="${PROJECT_DIR}/logs/run_$(date +%Y%m%d_%H%M%S).log"
PIPELINE_CMD="${PIPELINE_CMD} 2>&1 | tee ${LOG_FILE}"

# ---------------------------------------------------------------------------
# Launch (or reuse) a tmux session
# ---------------------------------------------------------------------------
if tmux has-session -t "$PROJECT" 2>/dev/null; then
    echo "tmux session '$PROJECT' already exists – killing and restarting..."
    tmux kill-session -t "$PROJECT"
fi

echo "Starting project '$PROJECT' in tmux session..."
echo "  Working dir : ${PROJECT_DIR}"
echo "  Phase 0 cfg : ${PHASE0_CONFIG}"
echo "  Log file    : ${LOG_FILE}"
echo ""
echo "  Attach with : tmux attach -t ${PROJECT}"
echo "  Detach      : Ctrl-B then D"

tmux new-session -d -s "$PROJECT" bash -lc "${PIPELINE_CMD}; echo '--- Pipeline finished (exit \$?) ---'; exec bash"
