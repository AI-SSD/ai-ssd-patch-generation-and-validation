#!/usr/bin/env bash
# =============================================================================
# run_matrix.sh – run one provider profile across the benchmark projects.
#
#   ./run_matrix.sh <profile> [extra pipeline.py flags...]
#
# Examples:
#   ./run_matrix.sh openai-fast --phases 0 1 2 3 4
#   ./run_matrix.sh ollama-proxy-qwen-coder --phases 2 3
#
# Each (project, profile) launches in its own tmux session "<project>__<profile>"
# and writes to projects/<project>__<profile>/, so families never collide.
#
# NOTE: for an Ollama profile the proxy serves ONE GPU, so three concurrent runs
# contend. Either run projects one at a time, or rely on the built-in GPU wait.
# =============================================================================
set -euo pipefail

PIPELINE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Projects benchmarked together. Edit to taste.
PROJECTS=(glibc tcpdump openssl)

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <profile> [extra pipeline.py flags...]"
    echo "Profiles:"
    ls -1 "${PIPELINE_ROOT}/profiles/"*.env 2>/dev/null | sed 's#.*/##; s#\.env$##; s/^/  - /'
    exit 1
fi

PROFILE="$1"; shift

for proj in "${PROJECTS[@]}"; do
    echo "==> ${proj}  (profile: ${PROFILE})"
    "${PIPELINE_ROOT}/run_project.sh" "${proj}" --profile "${PROFILE}" "$@"
    echo
done

echo "Launched ${#PROJECTS[@]} sessions. List: tmux ls"
