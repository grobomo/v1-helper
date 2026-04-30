#!/usr/bin/env bash
# Run all test suites. Exit 1 if any fail.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

total_pass=0; total_fail=0; total_tests=0; suites=0; failed_suites=0

run_suite() {
  local name="$1" cmd="$2"
  suites=$((suites + 1))
  echo ""
  echo "======== $name ========"
  if output=$(eval "$cmd" 2>&1); then
    echo "$output"
  else
    echo "$output"
    failed_suites=$((failed_suites + 1))
  fi
  # Parse results — prefer "X/Y passed" format, fall back to "X passed, Y failed"
  local results=$(echo "$output" | grep -oP '\d+/\d+ passed' | tail -1)
  if [ -n "$results" ]; then
    local p=$(echo "$results" | grep -oP '^\d+')
    local t=$(echo "$results" | grep -oP '/\d+' | tr -d '/')
    total_pass=$((total_pass + p))
    total_tests=$((total_tests + t))
    total_fail=$((total_fail + t - p))
  else
    local results2=$(echo "$output" | grep -oP '\d+ passed, \d+ failed' | tail -1)
    if [ -n "$results2" ]; then
      local p=$(echo "$results2" | grep -oP '^\d+')
      local t_f=$(echo "$results2" | grep -oP ', \d+' | tr -dc '0-9')
      total_pass=$((total_pass + p))
      total_fail=$((total_fail + t_f))
      total_tests=$((total_tests + p + t_f))
    fi
  fi
}

run_suite "Extension Validation" "node '$PROJECT_ROOT/tests/extension-validate.js'"

for test_script in "$SCRIPT_DIR"/test-T*.sh; do
  [ -f "$test_script" ] || continue
  name=$(basename "$test_script" .sh | sed 's/test-//')
  run_suite "$name" "bash '$test_script'"
done

echo ""
echo "========================================"
echo "TOTAL: $total_pass/$total_tests passed across $suites suites"
[ "$failed_suites" -gt 0 ] && echo "FAILED SUITES: $failed_suites"
echo "========================================"
[ "$total_fail" -eq 0 ] && exit 0 || exit 1
