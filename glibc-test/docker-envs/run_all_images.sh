#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECT_DIR="$ROOT_DIR/collected_reports"
mkdir -p "$COLLECT_DIR"

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
    echo "Docker requires sudo or is not running. Switching to sudo..."
    DOCKER_CMD="sudo docker"
fi

IMAGES=()
images_found=0
while IFS= read -r img; do
  if [ -n "$img" ]; then
    IMAGES+=("$img")
    images_found=1
  fi
done < <($DOCKER_CMD images --format '{{.Repository}}:{{.Tag}}' | grep '^glibc-test:' || true)

if [ "$images_found" -eq 0 ]; then
  echo "No images found matching 'glibc-test:*'. Build images first."
  exit 1
fi

SUMMARY_FILE="$COLLECT_DIR/summary.txt"
: > "$SUMMARY_FILE"

for img in "${IMAGES[@]}"; do
  echo "\n=== Running image: $img ==="
  safe=$(echo "$img" | sed 's/:/_/; s|/|-|g')
  outdir="$COLLECT_DIR/$safe"
  mkdir -p "$outdir"

  echo "  Output directory: $outdir"

  echo "  Starting container..."
  if $DOCKER_CMD run --rm -v "$outdir:/output" "$img" > "$outdir/container.log" 2>&1; then
    echo "  Completed successfully. Log: $outdir/container.log"
  else
    echo "  Container exited with non-zero status. Log: $outdir/container.log"
  fi

  if compgen -G "$outdir/report_*.txt" >/dev/null; then
    for r in "$outdir"/report_*.txt; do
      echo "----- Report from $img ($r) -----" >> "$SUMMARY_FILE"
      cat "$r" >> "$SUMMARY_FILE"
      echo "\n" >> "$SUMMARY_FILE"
    done
  else
    echo "  No report_*.txt found in $outdir" >> "$SUMMARY_FILE"
  fi

done

echo "\nAll done. Collected reports are in: $COLLECT_DIR"
echo "Summary file: $SUMMARY_FILE"
ls -la "$COLLECT_DIR"
