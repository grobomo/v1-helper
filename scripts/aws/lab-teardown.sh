#!/usr/bin/env bash
# Tear down V1 lab instance and clean up resources
# Usage: bash scripts/aws/lab-teardown.sh [--all]
#   --all: also remove key pair and security group
set -euo pipefail

REMOVE_ALL=false
[[ "${1:-}" == "--all" ]] && REMOVE_ALL=true

REGION="us-east-2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/config"
CONFIG_FILE="$CONFIG_DIR/lab-instance.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "No lab instance config at $CONFIG_FILE"
  echo "Looking for tagged instances..."
  INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=v1-lab" "Name=instance-state-name,Values=running,pending,stopping" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")
  if [[ "$INSTANCE_ID" == "None" ]] || [[ -z "$INSTANCE_ID" ]]; then
    echo "No running v1-lab instance found."
    exit 0
  fi
else
  INSTANCE_ID=$(grep -o '"instance_id": "[^"]*"' "$CONFIG_FILE" | cut -d'"' -f4)
fi

echo "=== V1 Lab Teardown ==="
echo "Terminating instance: $INSTANCE_ID"

aws ec2 terminate-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --output table

echo "Waiting for termination..."
aws ec2 wait instance-terminated \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION"

echo "Instance terminated."

if $REMOVE_ALL; then
  echo ""
  echo "Cleaning up resources..."

  # Remove security group
  SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=v1-lab-sg" \
    --query 'SecurityGroups[0].GroupId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")
  if [[ "$SG_ID" != "None" ]] && [[ -n "$SG_ID" ]]; then
    aws ec2 delete-security-group --group-id "$SG_ID" --region "$REGION"
    echo "  Deleted security group: $SG_ID"
  fi

  # Remove key pair
  if aws ec2 describe-key-pairs --key-names "v1-lab-key" --region "$REGION" &>/dev/null; then
    aws ec2 delete-key-pair --key-name "v1-lab-key" --region "$REGION"
    echo "  Deleted key pair: v1-lab-key"
  fi

  # Remove local key file
  [[ -f "$CONFIG_DIR/v1-lab-key.pem" ]] && rm "$CONFIG_DIR/v1-lab-key.pem" && echo "  Removed local key file"
fi

# Clean up config
[[ -f "$CONFIG_FILE" ]] && rm "$CONFIG_FILE" && echo "Removed $CONFIG_FILE"

echo ""
echo "Done."
