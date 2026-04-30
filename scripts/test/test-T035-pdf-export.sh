#!/usr/bin/env bash
# Test T035: PDF export — verify html2pdf.js integration in generated HTML reports
# Checks report_generator.py output contains all PDF export components
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

echo "--- PDF Export: Source Code Checks ---"

# Verify report_generator.py has html2pdf.js integration
check "exportPDF function exists" "grep -q 'function exportPDF' '$REPORT_GEN'"
check "generatePDF function exists" "grep -q 'function generatePDF' '$REPORT_GEN'"
check "html2pdf CDN URL present" "grep -q 'cdnjs.cloudflare.com/ajax/libs/html2pdf.js' '$REPORT_GEN'"
check "CDN fallback to window.print" "grep -q 's.onerror' '$REPORT_GEN' && grep -q 'window.print' '$REPORT_GEN'"
check "PDF button has id=pdfBtn" "grep -q 'id=\"pdfBtn\"' '$REPORT_GEN'"
check "PDF button calls exportPDF()" "grep -q 'onclick=\"exportPDF()\"' '$REPORT_GEN'"

echo ""
echo "--- PDF Export: Print CSS Checks ---"

check "page-break-after: avoid for headings" "grep -q 'page-break-after: avoid' '$REPORT_GEN'"
check "page-break-inside: avoid for rows" "grep -q 'page-break-inside: avoid' '$REPORT_GEN'"
check "sections expand in print" "grep -q 'max-height: none' '$REPORT_GEN'"
check "no-print hides toolbar" "grep -q '.no-print.*display: none' '$REPORT_GEN'"

echo ""
echo "--- PDF Export: State Management ---"

check "expands collapsed sections" "grep -q 'collapsed' '$REPORT_GEN' && grep -q 'classList.remove' '$REPORT_GEN'"
check "forces light mode for PDF" "grep -q 'classList.*dark' '$REPORT_GEN'"
check "hides toolbar during export" "grep -q 'toolbar.*display' '$REPORT_GEN'"
check "restores state after export" "grep -q 'classList.add.*collapsed' '$REPORT_GEN'"
check "button shows loading state" "grep -q 'Loading' '$REPORT_GEN'"
check "button shows generating state" "grep -q 'Generating' '$REPORT_GEN'"

echo ""
echo "--- PDF Export: html2pdf.js Config ---"

check "A3 landscape format" "grep -q 'format.*a3' '$REPORT_GEN' && grep -q 'landscape' '$REPORT_GEN'"
check "html2canvas scale set" "grep -q 'scale.*1' '$REPORT_GEN'"
check "pagebreak config present" "grep -q 'pagebreak' '$REPORT_GEN'"
check "error handler falls back to print" "grep -q 'catch.*window.print' '$REPORT_GEN' || grep -q 'onerror.*print' '$REPORT_GEN'"

echo ""

# Check existing HTML report if available
SAMPLE_REPORT="$PROJECT_ROOT/reports/ep_Container_Security_2026-04-30.html"
if [ -f "$SAMPLE_REPORT" ]; then
  echo "--- PDF Export: Generated HTML Verification ---"
  check "HTML has exportPDF function" "grep -q 'function exportPDF' '$SAMPLE_REPORT'"
  check "HTML has generatePDF function" "grep -q 'function generatePDF' '$SAMPLE_REPORT'"
  check "HTML has html2pdf CDN" "grep -q 'html2pdf.js' '$SAMPLE_REPORT'"
  check "HTML has pdfBtn" "grep -q 'pdfBtn' '$SAMPLE_REPORT'"
  echo ""
fi

echo "=== Results: $pass/$total passed, $fail failed ==="
[ "$fail" -eq 0 ] && exit 0 || exit 1
