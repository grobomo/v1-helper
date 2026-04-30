#!/usr/bin/env bash
# SSH to V1 lab instance and run a command (or open interactive shell)
# Usage:
#   bash scripts/aws/lab-ssh.sh                    # interactive shell
#   bash scripts/aws/lab-ssh.sh 'microk8s status'  # run command
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/config"
CONFIG_FILE="$CONFIG_DIR/lab-instance.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "No lab instance config. Run scripts/aws/lab-provision.sh first."
  exit 1
fi

IP=$(grep -o '"public_ip": "[^"]*"' "$CONFIG_FILE" | cut -d'"' -f4)
KEY="$CONFIG_DIR/v1-lab-key.pem"

if [[ $# -gt 0 ]]; then
  ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 admin@"$IP" "$@"
else
  ssh -i "$KEY" -o StrictHostKeyChecking=no admin@"$IP"
fi
