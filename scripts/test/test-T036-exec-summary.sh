#!/usr/bin/env bash
# Test T036: Executive summary in report HTML
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORT_GEN="$PROJECT_ROOT/scripts/report_generator.py"

pass=0; fail=0; total=0

check() {
  total=$((total + 1))
  if eval "$2" > /dev/null 2>&1; then
    echo "  PASS: $1"; pass=$((pass + 1))
  else
    echo "  FAIL: $1"; fail=$((fail + 1))
  fi
}

echo "--- Executive Summary: Source Code ---"

check "exec summary section exists" "grep -q 'Executive Summary' '$REPORT_GEN'"
check "exec summary has collapsible section" "grep -q 'data-section=\"exec-summary\"' '$REPORT_GEN'"
check "shows total CVE count" "grep -q 'total_cves\|total.*findings\|{total}' '$REPORT_GEN' && grep -q 'Executive Summary' '$REPORT_GEN'"
check "shows severity breakdown" "grep -q 'critical.*high.*medium\|sev_totals' '$REPORT_GEN'"
check "shows cluster count" "grep -q 'cluster.*count\|len(clusters)\|len(sorted_clusters)' '$REPORT_GEN'"
check "shows relevant CVE count" "grep -q 'relevant_count' '$REPORT_GEN'"
check "shows action needed count" "grep -q 'need_action\|action.*count' '$REPORT_GEN'"
check "summary inserted before Environment Context in HTML" "python -c \"import sys;t=open(sys.argv[1]).read();h1=t.find('<h1>');es=t.find('exec_summary',h1);ec=t.find('Environment Context',h1);sys.exit(0 if es>0 and ec>0 and es<ec else 1)\" '$REPORT_GEN'"

echo ""
echo "--- Executive Summary: Visual Elements ---"

check "has stat boxes or grid layout" "grep -q 'exec-stat\|summary-grid\|stat-box\|summary-stat' '$REPORT_GEN'"
check "shows diff delta if available" "grep -q 'diff_data.*delta\|net.*change\|diff_data.*added\|n_new\|n_res' '$REPORT_GEN'"

echo ""
echo "=== Results: $pass/$total passed, $fail failed ==="
[ "$fail" -eq 0 ] && exit 0 || exit 1
