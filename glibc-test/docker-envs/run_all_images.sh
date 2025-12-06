#!/usr/bin/env bash
set -euo pipefail

# run_all_images.sh
# Finds all Docker images tagged with repository 'glibc-test' and runs each one.
# Each container writes its report file(s) to /output inside the container; we map
# that to a host folder: ./collected_reports/<image_tag_safe>/
# At the end we create a summary file ./collected_reports/summary.txt

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECT_DIR="$ROOT_DIR/collected_reports"
mkdir -p "$COLLECT_DIR"

# Get all images matching glibc-test:*
# `mapfile` / `readarray` is not available on older macOS bash; use a portable loop
IMAGES=()
images_found=0
while IFS= read -r img; do
  if [ -n "$img" ]; then
    IMAGES+=("$img")
    images_found=1
  fi
done < <(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^glibc-test:' || true)

if [ "$images_found" -eq 0 ]; then
  echo "No images found matching 'glibc-test:*'. Build images first."
  exit 1
fi

SUMMARY_FILE="$COLLECT_DIR/summary.txt"
: > "$SUMMARY_FILE"

for img in "${IMAGES[@]}"; do
  echo "\n=== Running image: $img ==="
  # Make a safe folder name (replace ':' with '_' and any '/' with '-')
  safe=$(echo "$img" | sed 's/:/_/; s|/|-|g')
  outdir="$COLLECT_DIR/$safe"
  mkdir -p "$outdir"

  echo "  Output directory: $outdir"

  # Run the image. Capture stdout/stderr to a log file.
  # We use --rm so the container is cleaned up, but we map the output dir.
  echo "  Starting container..."
  if docker run --rm -v "$outdir:/output" "$img" > "$outdir/container.log" 2>&1; then
    echo "  Completed successfully. Log: $outdir/container.log"
  else
    echo "  Container exited with non-zero status. Log: $outdir/container.log"
  fi

  # Find any report files produced and append a short summary to the overall summary
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
