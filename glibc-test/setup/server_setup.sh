#!/usr/bin/env bash
set -euo pipefail

# Installer for Ubuntu server to prepare environment for the glibc test pipeline
# Usage: sudo ./install_ubuntu.sh [--pull-models]
# If run without sudo, the script will use sudo where required.

# By default, automatically pull models and run the pipeline
PULL_MODELS=1
RUN_PIPELINE=1
for arg in "$@"; do
  case "$arg" in
    --no-pull-models) PULL_MODELS=0 ;;
    --no-run) RUN_PIPELINE=0 ;;
    --pull-models) PULL_MODELS=1 ;;
    --run) RUN_PIPELINE=1 ;;
    --help|-h) echo "Usage: sudo ./server_setup.sh [--no-pull-models] [--no-run]"; exit 0 ;;
  esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
USER_NAME="$(logname 2>/dev/null || echo ${SUDO_USER:-${USER}})"

# If USER_NAME is root, try to detect real user from path if possible
if [ "$USER_NAME" = "root" ]; then
    if [[ "$REPO_DIR" == /home/* ]]; then
        POSSIBLE_USER=$(echo "$REPO_DIR" | cut -d/ -f3)
        if [ -n "$POSSIBLE_USER" ] && [ "$POSSIBLE_USER" != "root" ]; then
             echo "Warning: Detected user is root, but path suggests user '$POSSIBLE_USER'. Using '$POSSIBLE_USER'."
             USER_NAME="$POSSIBLE_USER"
        fi
    fi
fi

echo "Repository root: $REPO_DIR"
echo "Installer will create a Python venv at: $VENV_DIR"
echo "Target user for docker group: $USER_NAME"

# 1) Basic apt packages
echo "\n[1/6] Updating apt, enabling repositories and installing base packages..."
sudo apt-get update -y

# Ensure 'universe' is enabled (needed for python3-venv on many Ubuntu releases)
if ! grep -h ^lo /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | grep -q "universe"; then
  echo "Enabling universe repository"
  sudo apt-get install -y software-properties-common || true
  sudo add-apt-repository -y universe || true
  sudo apt-get update -y
fi

echo "Installing common packages"
sudo apt-get install -y \
  ca-certificates curl wget gnupg lsb-release software-properties-common \
  git build-essential python3 python3-pip pkg-config || true

# Try to install generic python3-venv first; if missing, try the versioned package
echo "Ensuring python venv support is available"
if ! apt-cache policy python3-venv | grep -q 'Candidate:'; then
  echo "python3-venv not available in package index, attempting versioned package"
fi
if ! sudo apt-get install -y python3-venv; then
  # Detect python3 version and attempt pythonX.Y-venv
  PY_MAJOR=$(python3 -c 'import sys;print(sys.version_info.major)')
  PY_MINOR=$(python3 -c 'import sys;print(sys.version_info.minor)')
  PKG="python${PY_MAJOR}.${PY_MINOR}-venv"
  echo "Attempting to install ${PKG}"
  sudo apt-get install -y "${PKG}" || \
    { echo "Failed to install python venv package (tried python3-venv and ${PKG})."; }
fi


# 2) Docker install (official repo)
echo "\n[2/6] Installing Docker Engine..."
if ! command -v docker >/dev/null 2>&1; then
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  echo "Docker installed."
else
  echo "Docker already installed. Skipping." 
fi

# Ensure Docker service is running
echo "Starting Docker service (enable --now)..."
sudo systemctl enable --now docker || true
sleep 2
if ! systemctl is-active --quiet docker; then
  echo "Warning: Docker service is not active. Check 'sudo systemctl status docker' for details."
fi

# Add user to docker group (so they can run docker without sudo)
if id -nG "$USER_NAME" | grep -qw docker; then
  echo "User $USER_NAME already in docker group"
else
  echo "Adding $USER_NAME to docker group"
  sudo usermod -aG docker "$USER_NAME" || true
  echo "Note: You must log out and back in (or reboot) for group changes to take effect."

  # Verify docker access for the user
  echo "Verifying docker access for user '$USER_NAME'..."
  if su - "$USER_NAME" -c "docker run --rm hello-world > /dev/null 2>&1"; then
    echo "Verification successful: User '$USER_NAME' can run docker commands."
  else
    echo "Verification failed (expected until re-login): User '$USER_NAME' cannot run docker commands yet."
    echo "Please log out and log back in (or run 'newgrp docker') to apply the group change."
  fi
fi

# 3) Python venv & pip packages
echo "\n[3/6] Creating Python virtual environment and installing Python packages..."
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
# Activate venv for pip operations
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

pip install --upgrade pip setuptools wheel
# Install core Python requirements
REQ_FILE="$REPO_DIR/glibc-test/requirements.txt"
if [ -f "$REQ_FILE" ]; then
  pip install -r "$REQ_FILE"
else
  pip install pandas requests tabulate
fi

# 4) Ollama install - DISABLED (Using External API)
# echo "\n[4/6] Installing Ollama..."
# ... (Ollama installation skipped)

# 5) Start Ollama daemon - DISABLED (Using External API)
# echo "\n[5/6] Starting Ollama daemon (if installed)..."
# ... (Ollama daemon start skipped)

# 6) Optional: pull models - DISABLED (Using External API)
# if [ "$PULL_MODELS" -eq 1 ]; then
#   echo "\n[6/6] Pulling recommended models (this may take a long time and consume lots of disk)."
#   ... (Model pulling skipped)
# fi

# 7) Optionally run the full pipeline automatically
if [ "$RUN_PIPELINE" -eq 1 ]; then
  echo "\n[7/7] Running full methodology pipeline automatically. This will run Phases 1-4 and may take a long time."
  PIPE_LOG="$REPO_DIR/pipeline_run.log"
  echo "Pipeline logs will be written to: $PIPE_LOG"
  # Ensure venv is active (we already sourced it earlier)
  if [ -f "$VENV_DIR/bin/activate" ]; then
    # run pipeline in background so installer can finish
    nohup bash -lc "source $VENV_DIR/bin/activate && python3 $REPO_DIR/run_methodology.py" > "$PIPE_LOG" 2>&1 &
    PID=$!
    echo "Pipeline started (PID: $PID). Tail the logs with: tail -f $PIPE_LOG"
  else
    echo "Virtualenv not found at $VENV_DIR; cannot start pipeline."
  fi
else
  echo "Pipeline run skipped by request. To run manually: source $VENV_DIR/bin/activate && python3 $REPO_DIR/run_methodology.py"
fi

# Ensure repo files are owned by the target user to avoid permission issues
echo "\nFixing ownership of repository files for user: $USER_NAME"
sudo chown -R "$USER_NAME":"$USER_NAME" "$REPO_DIR" || {
  echo "Warning: failed to chown $REPO_DIR to $USER_NAME. You may need to run this manually.";
}

# Final notes
echo "\nInstallation finished. Quick checklist and next steps:"
cat <<EOF
- Activate project virtualenv: source $VENV_DIR/bin/activate
- Ensure you logged out and back in after the 'docker' group change, or run: newgrp docker
- Confirm Ollama is running: ollama list
- (Optional) Pull models: ollama pull <model>

To run the full pipeline:
  source $VENV_DIR/bin/activate
  python3 glibc-test/run_methodology.py
EOF

echo "Installer completed."
