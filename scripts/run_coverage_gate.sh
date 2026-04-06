#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
summary_file="$repo_root/coverage-summary.txt"

cd "$repo_root"
cargo llvm-cov \
  --workspace \
  --summary-only \
  --ignore-filename-regex '/src/main\.rs$' \
  | tee "$summary_file"
python3 scripts/check_coverage.py "$summary_file" 80 80
