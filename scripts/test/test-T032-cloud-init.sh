#!/usr/bin/env bash
# Test T032: Cloud-init user data encoding — verify lab-provision.sh handles Windows correctly
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROVISION="$PROJECT_ROOT/scripts/aws/lab-provision.sh"

pass=0; fail=0; total=0

check() {
  total=$((total + 1))
  if eval "$2" > /dev/null 2>&1; then
    echo "  PASS: $1"; pass=$((pass + 1))
  else
    echo "  FAIL: $1"; fail=$((fail + 1))
  fi
}

echo "--- Cloud-Init: Encoding Strategy ---"

# Must NOT use pipe-to-base64 (broken on Windows/Git Bash with CRLF)
check "no pipe to base64" "! grep -q 'base64 -w' '$PROVISION'"
check "no echo pipe base64" "! grep -q 'echo.*| base64' '$PROVISION'"

# Must use file:// for user data (AWS CLI handles encoding)
check "uses file:// for user-data" "grep -q 'file://' '$PROVISION'"
check "writes user data to temp file" "grep -q 'mktemp\|TMPFILE\|tmp.*userdata' '$PROVISION'"
check "cleans up temp file" "grep -q 'rm.*tmp\|trap.*rm\|cleanup' '$PROVISION'"

echo ""
echo "--- Cloud-Init: Script Content ---"

check "user data starts with shebang" "grep -q '#!/bin/bash' '$PROVISION'"
check "installs microk8s" "grep -q 'snap install microk8s' '$PROVISION'"
check "enables dns and storage" "grep -q 'enable dns' '$PROVISION'"
check "creates status marker" "grep -q 'lab-status' '$PROVISION'"
check "waits for k8s ready" "grep -q 'wait.*Ready\|wait-ready' '$PROVISION'"

echo ""
echo "--- Cloud-Init: Dry Run ---"

# Verify dry run works without AWS credentials
check "dry run flag supported" "grep -q 'dry.run\|DRY_RUN' '$PROVISION'"
check "dry run shows user data" "grep -q 'dry-run.*user data\|USERDATA' '$PROVISION'"

echo ""
echo "=== Results: $pass/$total passed, $fail failed ==="
[ "$fail" -eq 0 ] && exit 0 || exit 1
