#!/usr/bin/env bash
set -euo pipefail

# Installer for Ubuntu server to prepare environment for the glibc test pipeline
# Usage: sudo ./install_ubuntu.sh [--pull-models]
# If run without sudo, the script will use sudo where required.

PULL_MODELS=0
for arg in "$@"; do
  case "$arg" in
    --pull-models) PULL_MODELS=1 ;;
    --help|-h) echo "Usage: sudo ./install_ubuntu.sh [--pull-models]"; exit 0 ;;
  esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
USER_NAME="$(logname 2>/dev/null || echo $SUDO_USER || echo $USER)"

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

# Add user to docker group (so they can run docker without sudo)
if id -nG "$USER_NAME" | grep -qw docker; then
  echo "User $USER_NAME already in docker group"
else
  echo "Adding $USER_NAME to docker group"
  sudo usermod -aG docker "$USER_NAME" || true
  echo "Note: You must log out and back in (or reboot) for group changes to take effect."
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
  pip install pandas ollama
fi

# 4) Ollama install
echo "\n[4/6] Installing Ollama..."
if ! command -v ollama >/dev/null 2>&1; then
  echo "Installing Ollama via install script (requires sudo)..."
  curl -fsSL https://ollama.com/install.sh | sudo bash || {
    echo "Ollama install script failed. Please follow https://ollama.com/docs to install manually.";
  }
else
  echo "Ollama already installed."
fi

# 5) Start Ollama daemon
echo "\n[5/6] Starting Ollama daemon (if installed)..."
if command -v ollama >/dev/null 2>&1; then
  # Try to start daemon; if system has systemd service, enable it; otherwise use daemon start
  if sudo systemctl list-unit-files | grep -q '^ollama'; then
    sudo systemctl enable --now ollama || true
  else
    # Attempt user-level daemon start
    ollama daemon start || true
  fi
  echo "Waiting for ollama to become responsive (max 60s)"
  for i in {1..30}; do
    if ollama list >/dev/null 2>&1; then
      echo "Ollama is responsive." && break
    fi
    sleep 2
  done
else
  echo "Ollama not found. Skipping daemon start."
fi

# 6) Optional: pull models
if [ "$PULL_MODELS" -eq 1 ]; then
  echo "\n[6/6] Pulling recommended models (this may take a long time and consume lots of disk)."
  MODELS=("qwen2.5-coder:1.5b" "qwen2.5-coder:7b" "qwen2.5:1.5b" "qwen2.5:7b")
  for m in "${MODELS[@]}"; do
    echo "Pulling model: $m"
    ollama pull "$m" || echo "Failed to pull $m"
  done
else
  echo "\n[6/6] Skipping model pulls. To pull models automatically, run: sudo ./install_ubuntu.sh --pull-models"
fi

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
