#!/usr/bin/env bash
# Provision V1 Container Security lab: EC2 spot + microk8s
# Usage: bash scripts/aws/lab-provision.sh [--dry-run]
set -euo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

# --- Config ---
INSTANCE_TYPE="t3.medium"
KEY_NAME="v1-lab-key"
SG_NAME="v1-lab-sg"
TAG_NAME="v1-lab"
VPC_ID="vpc-08890dbff777709ae"
SPOT_PRICE="0.02"  # max bid, actual ~$0.007
REGION="us-east-2"

# Debian 12 AMI (us-east-2) — official Debian cloud images
AMI_ID=$(aws ec2 describe-images \
  --owners 136693071363 \
  --filters "Name=name,Values=debian-12-amd64-*" "Name=state,Values=available" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text \
  --region "$REGION")

echo "=== V1 Lab Provision ==="
echo "Instance: $INSTANCE_TYPE spot (max \$$SPOT_PRICE/hr)"
echo "AMI: $AMI_ID (Debian 12)"
echo "Region: $REGION"
echo ""

# --- Key Pair ---
if aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" &>/dev/null; then
  echo "Key pair '$KEY_NAME' exists"
else
  echo "Creating key pair '$KEY_NAME'..."
  if $DRY_RUN; then
    echo "  [dry-run] would create key pair"
  else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    KEY_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/config"
    mkdir -p "$KEY_DIR"
    aws ec2 create-key-pair \
      --key-name "$KEY_NAME" \
      --key-type ed25519 \
      --query 'KeyMaterial' \
      --output text \
      --region "$REGION" > "$KEY_DIR/$KEY_NAME.pem"
    chmod 600 "$KEY_DIR/$KEY_NAME.pem"
    echo "  Saved to $KEY_DIR/$KEY_NAME.pem"
  fi
fi

# --- Security Group ---
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' \
  --output text \
  --region "$REGION" 2>/dev/null || echo "None")

if [[ "$SG_ID" == "None" ]] || [[ -z "$SG_ID" ]]; then
  echo "Creating security group '$SG_NAME'..."
  if $DRY_RUN; then
    echo "  [dry-run] would create SG with SSH + K8s API rules"
    SG_ID="sg-dryrun"
  else
    SG_ID=$(aws ec2 create-security-group \
      --group-name "$SG_NAME" \
      --description "V1 Container Security lab - SSH and K8s" \
      --vpc-id "$VPC_ID" \
      --region "$REGION" \
      --output text \
      --query 'GroupId')
    echo "  Created: $SG_ID"

    # SSH from anywhere (lab instance, short-lived)
    aws ec2 authorize-security-group-ingress \
      --group-id "$SG_ID" \
      --protocol tcp --port 22 \
      --cidr 0.0.0.0/0 \
      --region "$REGION" > /dev/null

    # K8s API (microk8s uses 16443)
    aws ec2 authorize-security-group-ingress \
      --group-id "$SG_ID" \
      --protocol tcp --port 16443 \
      --cidr 0.0.0.0/0 \
      --region "$REGION" > /dev/null

    # NodePort range for services
    aws ec2 authorize-security-group-ingress \
      --group-id "$SG_ID" \
      --protocol tcp --port 30000-32767 \
      --cidr 0.0.0.0/0 \
      --region "$REGION" > /dev/null

    echo "  Rules: SSH(22), K8s API(16443), NodePort(30000-32767)"
  fi
else
  echo "Security group '$SG_NAME' exists: $SG_ID"
fi

# --- User Data (cloud-init) ---
USERDATA=$(cat <<'CLOUD_INIT'
#!/bin/bash
set -ex

# Install microk8s
apt-get update
apt-get install -y snapd
snap install microk8s --classic --channel=1.29/stable

# Configure microk8s
microk8s status --wait-ready
microk8s enable dns storage helm3

# Alias kubectl and helm
snap alias microk8s.kubectl kubectl
snap alias microk8s.helm3 helm

# Add admin user to microk8s group
usermod -aG microk8s admin 2>/dev/null || true

# Wait for K8s to be fully ready
microk8s kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Create marker file
echo "microk8s-ready" > /tmp/lab-status
echo "=== Lab provisioning complete ==="
CLOUD_INIT
)

USERDATA_B64=$(echo "$USERDATA" | base64 -w 0)

# --- Launch Spot Instance ---
echo ""
echo "Launching spot instance..."

if $DRY_RUN; then
  echo "  [dry-run] would launch $INSTANCE_TYPE spot with $AMI_ID"
  echo "  Key: $KEY_NAME, SG: $SG_ID"
  echo ""
  echo "User data script:"
  echo "$USERDATA"
  exit 0
fi

# Request spot instance
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --instance-market-options '{"MarketType":"spot","SpotOptions":{"MaxPrice":"'"$SPOT_PRICE"'","SpotInstanceType":"one-time"}}' \
  --user-data "$USERDATA_B64" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG_NAME},{Key=project,Value=v1-helper}]" \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --region "$REGION" \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "  Instance: $INSTANCE_ID"
echo "  Waiting for running state..."

aws ec2 wait instance-running \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text \
  --region "$REGION")

echo ""
echo "=== Lab Instance Ready ==="
echo "Instance: $INSTANCE_ID"
echo "IP: $PUBLIC_IP"
echo "SSH: ssh -i config/$KEY_NAME.pem admin@$PUBLIC_IP"
echo ""
echo "microk8s will finish installing via cloud-init (2-5 min)."
echo "Check progress: ssh -i config/$KEY_NAME.pem admin@$PUBLIC_IP 'cat /tmp/lab-status'"
echo ""

# Save instance info
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/config"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/lab-instance.json" <<EOF
{
  "instance_id": "$INSTANCE_ID",
  "public_ip": "$PUBLIC_IP",
  "key_name": "$KEY_NAME",
  "key_file": "config/$KEY_NAME.pem",
  "security_group": "$SG_ID",
  "instance_type": "$INSTANCE_TYPE",
  "region": "$REGION",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
echo "Instance info saved to config/lab-instance.json"
