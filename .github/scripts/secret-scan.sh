#!/usr/bin/env bash
# Reusable secret & PII scanner for public repos.
# Called by GitHub Actions and can be run locally: bash .github/scripts/secret-scan.sh
set -euo pipefail

FAIL=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CUSTOMER_NAMES="$SCRIPT_DIR/../customer-names.txt"

# Standard file types to scan
INCLUDES='--include=*.py --include=*.sh --include=*.ps1 --include=*.tf --include=*.txt --include=*.json --include=*.yml --include=*.yaml --include=*.md --include=*.js --include=*.ts --include=*.html'
EXCLUDES='--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=archive --exclude-dir=worktrees --exclude-dir=.claude --exclude=secret-scan.sh'

echo "=== Secret & PII Scan ==="

# 1. Azure Storage Account Keys
if grep -rn $INCLUDES --include='*.py' --include='*.sh' --include='*.ps1' --include='*.tf' --include='*.txt' --include='*.json' --include='*.yml' --include='*.yaml' \
  -E '(account_key|STORAGE_KEY|storage_key|credential)\s*[=:]\s*"[A-Za-z0-9+/]{40,}={0,2}"' . $EXCLUDES 2>/dev/null; then
  echo "::error::BLOCKED: Azure Storage Account Key detected"
  FAIL=1
fi

# 2. Azure Subscription IDs
if grep -rn $INCLUDES --include='*.py' --include='*.sh' --include='*.ps1' --include='*.tf' --include='*.txt' --include='*.json' --include='*.yml' \
  -E 'subscription[_-]?id\s*[=:]\s*"?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' . $EXCLUDES 2>/dev/null; then
  echo "::error::BLOCKED: Azure Subscription ID detected"
  FAIL=1
fi

# 3. SAS tokens in URLs
if grep -rn $INCLUDES --include='*.py' --include='*.sh' --include='*.ps1' --include='*.tf' --include='*.txt' --include='*.json' --include='*.yml' \
  -E 'sig=[A-Za-z0-9%+/]{20,}' . $EXCLUDES 2>/dev/null; then
  echo "::error::BLOCKED: SAS token signature detected in URL"
  FAIL=1
fi

# 4. AWS keys
if grep -rn -E '(AKIA[0-9A-Z]{16}|aws_secret_access_key\s*=)' . $EXCLUDES 2>/dev/null; then
  echo "::error::BLOCKED: AWS credential detected"
  FAIL=1
fi

# 5. Generic API keys/tokens
if grep -rn --include='*.py' --include='*.sh' --include='*.ps1' --include='*.json' \
  -E '(api_key|API_KEY|token|TOKEN|secret|SECRET)\s*[=:]\s*"[A-Za-z0-9+/]{30,}={0,2}"' . $EXCLUDES 2>/dev/null; then
  echo "::error::BLOCKED: API key or token detected"
  FAIL=1
fi

# 6. Private keys
if grep -rn -l 'BEGIN.*PRIVATE KEY' . $EXCLUDES 2>/dev/null; then
  echo "::error::BLOCKED: Private key file detected"
  FAIL=1
fi

# 7. Terraform state files
if find . -name '*.tfstate' -o -name '*.tfstate.*' -o -name 'tfplan' 2>/dev/null | grep -q .; then
  echo "::error::BLOCKED: Terraform state/plan files should not be committed"
  FAIL=1
fi

# 8. Personal paths (Windows user paths)
if grep -rn --include='*.py' --include='*.sh' --include='*.ps1' --include='*.tf' --include='*.json' \
  -E 'C:\\Users\\[a-zA-Z]+\\' . $EXCLUDES --exclude='CLAUDE.md' 2>/dev/null; then
  echo "::error::BLOCKED: Personal file path detected"
  FAIL=1
fi

# 9. .env files with secrets
ENV_FILES=$(find . -name '.env' -not -path './.git/*' -not -path './.github/*' 2>/dev/null || true)
if [ -n "$ENV_FILES" ] && echo "$ENV_FILES" | xargs grep -l -E '(KEY|SECRET|TOKEN|PASSWORD)\s*=' 2>/dev/null; then
  echo "::error::BLOCKED: .env file with secrets detected"
  FAIL=1
fi

# 10. Customer names (from .github/customer-names.txt)
if [ -f "$CUSTOMER_NAMES" ]; then
  while IFS= read -r name; do
    # Skip comments and blank lines
    [[ "$name" =~ ^#.*$ || -z "$name" ]] && continue
    if grep -rni $INCLUDES "$name" . $EXCLUDES \
      --exclude='customer-names.txt' --exclude='secret-scan.sh' --exclude='secret-scan.yml' 2>/dev/null; then
      echo "::error::BLOCKED: Customer name '$name' found in repo files"
      FAIL=1
    fi
  done < "$CUSTOMER_NAMES"
else
  echo "Warning: $CUSTOMER_NAMES not found, skipping customer name scan"
fi

if [ "$FAIL" -eq 1 ]; then
  echo ""
  echo "=========================================="
  echo "PUSH BLOCKED: Fix the above issues first."
  echo "=========================================="
  exit 1
fi

echo "All checks passed."
