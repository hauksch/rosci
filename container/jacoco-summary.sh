#!/usr/bin/env bash
# Prints a one-line line-coverage summary from a JaCoCo CSV report.
# Usage: jacoco-summary.sh <path/to/jacoco.csv>
set -euo pipefail
CSV="${1:?usage: jacoco-summary.sh <jacoco.csv>}"
if [ ! -f "$CSV" ]; then
  echo "jacoco summary unavailable ($CSV missing)"
  exit 0
fi
awk -F, 'NR > 1 { missed += $8; covered += $9 }
         END {
           total = missed + covered
           pct = (total > 0) ? 100 * covered / total : 0
           printf "bridge lines: %d covered, %d total (%.1f%%)\n", covered, total, pct
         }' "$CSV"
