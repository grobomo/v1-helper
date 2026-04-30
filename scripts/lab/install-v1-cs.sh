#!/usr/bin/env bash
# Install Vision One Container Security on microk8s lab
# Run ON the lab instance (via SSH) or remotely with --remote <ip>
#
# Prerequisites:
# 1. microk8s running (check: microk8s status)
# 2. V1 Container Security cluster enrollment token
#    Get from V1 Console > Container Security > + Add Kubernetes
#    Or pass via --token <enrollment_token>
#
# Usage:
#   bash scripts/lab/install-v1-cs.sh --token <enrollment_token>
#   bash scripts/lab/install-v1-cs.sh --remote <ip> --token <enrollment_token>
set -euo pipefail

TOKEN=""
REMOTE=""
KEY_FILE=""
NAMESPACE="trendmicro-system"
REGION="us-east-1"  # V1 region for API

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN="$2"; shift 2;;
    --remote) REMOTE="$2"; shift 2;;
    --key) KEY_FILE="$2"; shift 2;;
    --region) REGION="$2"; shift 2;;
    *) echo "Unknown: $1"; exit 1;;
  esac
done

if [[ -z "$TOKEN" ]]; then
  echo "Error: --token <enrollment_token> required"
  echo ""
  echo "Get the token from V1 Console:"
  echo "  1. Cloud Security > Container Security"
  echo "  2. + Add Kubernetes"
  echo "  3. Copy the enrollment token from the helm command"
  exit 1
fi

# V1 Container Security helm repo
HELM_REPO="https://cloudone.trendmicro.com/docs/container-security"
CS_CHART="trendmicro/cloudone-container-security"

# Build the install commands
INSTALL_CMDS=$(cat <<SCRIPT
set -ex

# Add Trend Micro helm repo
sudo microk8s.helm3 repo add trendmicro https://cloudone.trendmicro.com/docs/container-security || true
sudo microk8s.helm3 repo update

# Create namespace
sudo microk8s.kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | sudo microk8s.kubectl apply -f -

# Install Container Security
sudo microk8s.helm3 upgrade --install \
  trendmicro \
  trendmicro/cloudone-container-security \
  --namespace "$NAMESPACE" \
  --set cloudOne.apiKey="$TOKEN" \
  --set cloudOne.endpoint="https://container.$REGION.cloudone.trendmicro.com" \
  --wait \
  --timeout 300s

echo ""
echo "=== V1 Container Security Installed ==="
sudo microk8s.kubectl get pods -n "$NAMESPACE"
SCRIPT
)

if [[ -n "$REMOTE" ]]; then
  # Run remotely via SSH
  if [[ -z "$KEY_FILE" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    KEY_FILE="$(cd "$SCRIPT_DIR/../.." && pwd)/config/v1-lab-key.pem"
  fi
  echo "Installing V1 CS on remote: $REMOTE"
  ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no admin@"$REMOTE" bash -c "'$INSTALL_CMDS'"
else
  # Run locally
  echo "Installing V1 CS locally..."
  bash -c "$INSTALL_CMDS"
fi
