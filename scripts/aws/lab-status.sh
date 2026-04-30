#!/usr/bin/env bash
# Check V1 lab instance status
set -euo pipefail

REGION="us-east-2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/config"
CONFIG_FILE="$CONFIG_DIR/lab-instance.json"

echo "=== V1 Lab Status ==="

# Find instance by tag
RESULT=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=v1-lab" "Name=instance-state-name,Values=running,pending,stopping,stopped" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,PublicIpAddress,State.Name,LaunchTime]' \
  --output text \
  --region "$REGION" 2>/dev/null || echo "")

if [[ -z "$RESULT" ]]; then
  echo "No v1-lab instance running."
  exit 0
fi

echo "$RESULT" | while read -r id type ip state launch; do
  echo "Instance: $id ($type)"
  echo "State:    $state"
  echo "IP:       $ip"
  echo "Launched: $launch"
done

# If running, try SSH check
IP=$(echo "$RESULT" | awk '{print $3}' | head -1)
KEY_FILE="$CONFIG_DIR/v1-lab-key.pem"

if [[ -f "$KEY_FILE" ]] && [[ "$IP" != "None" ]]; then
  echo ""
  echo "--- Cloud-init status ---"
  ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    admin@"$IP" 'cat /tmp/lab-status 2>/dev/null || echo "still provisioning..."' 2>/dev/null \
    || echo "(SSH not ready yet)"

  echo ""
  echo "--- microk8s status ---"
  ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    admin@"$IP" 'sudo microk8s status 2>/dev/null || echo "microk8s not installed yet"' 2>/dev/null \
    || echo "(SSH not ready yet)"

  echo ""
  echo "SSH: ssh -i $KEY_FILE admin@$IP"
fi
