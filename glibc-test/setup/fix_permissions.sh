#!/bin/bash
# Fix permissions for the repository
# Usage: ./fix_permissions.sh

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Detect the real user (even if run with sudo)
if [ -n "$SUDO_USER" ]; then
    TARGET_USER="$SUDO_USER"
else
    TARGET_USER="$(whoami)"
fi

echo "Fixing permissions for $REPO_DIR"
echo "Setting owner to $TARGET_USER"

# If we are root (via sudo), we don't need 'sudo' command, but if we are not root, we might need it.
# However, this script is intended to be run with sudo if files are owned by root.
if [ "$(id -u)" -eq 0 ]; then
    chown -R "$TARGET_USER":"$TARGET_USER" "$REPO_DIR"
else
    sudo chown -R "$TARGET_USER":"$TARGET_USER" "$REPO_DIR"
fi

echo "Permissions fixed."
