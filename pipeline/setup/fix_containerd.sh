#!/bin/bash
# =============================================================================
# AI-SSD Project - Fix Containerd Metadata Database
# =============================================================================
# Fixes the error:
# failed to open database file: open /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/metadata.db: no such file or directory
#
# This error typically occurs when containerd state is corrupted or inconsistent.
# =============================================================================

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (or with sudo)"
   exit 1
fi

echo "[1/4] Stopping Docker and containerd services..."
systemctl stop docker 2>/dev/null || true
systemctl stop containerd 2>/dev/null || true

echo "[2/4] Cleaning up problematic containerd metadata..."
# Target the specific database file reported in the error
METADATA_DIR="/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
if [ -d "$METADATA_DIR" ]; then
    echo "Removing $METADATA_DIR/metadata.db..."
    rm -f "$METADATA_DIR/metadata.db"
    # If the DB is missing but the dir exists, sometimes recreate it
    mkdir -p "$METADATA_DIR"
else
    echo "Metadata directory $METADATA_DIR not found. Creating it..."
    mkdir -p "$METADATA_DIR"
fi

# Also check for common Docker/containerd lock files
rm -f /var/lib/docker/network/files/local-kv.db

echo "[3/4] Restarting services..."
systemctl start containerd
systemctl start docker

echo "[4/4] Verifying fix..."
if docker info &>/dev/null; then
    echo "Docker daemon is responsive."
    echo "Running test build..."
    echo "FROM scratch" > Dockerfile.test
    if docker build -t ai-ssd-test-fix -f Dockerfile.test . &>/dev/null; then
        echo "SUCCESS: Docker build test passed!"
        docker rmi ai-ssd-test-fix &>/dev/null
    else
        echo "WARNING: Docker build still failing. Full state reset may be required."
        echo "To perform a FULL reset (WARNING: DELETES ALL IMAGES/VOLUMES):"
        echo "  sudo systemctl stop docker containerd"
        echo "  sudo rm -rf /var/lib/docker /var/lib/containerd"
        echo "  sudo systemctl start containerd docker"
    fi
    rm -f Dockerfile.test
else
    echo "ERROR: Docker daemon failed to start. Check 'journalctl -u docker'"
fi

echo "============================================="
echo "Fix script completed."
