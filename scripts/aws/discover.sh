#!/usr/bin/env bash
# Discover existing AWS infrastructure for v1-helper lab
set -euo pipefail

echo "=== AWS Account ==="
aws sts get-caller-identity --output table

echo ""
echo "=== VPCs ==="
aws ec2 describe-vpcs \
  --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[0],CidrBlock,IsDefault]' \
  --output table

echo ""
echo "=== Key Pairs ==="
aws ec2 describe-key-pairs \
  --query 'KeyPairs[*].[KeyName,KeyPairId,KeyType]' \
  --output table

echo ""
echo "=== Security Groups ==="
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' \
  --output table

echo ""
echo "=== Running Instances ==="
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,Tags[?Key==`Name`].Value|[0],PublicIpAddress,State.Name]' \
  --output table

echo ""
echo "=== Spot Price (t3.medium us-east-1) ==="
aws ec2 describe-spot-price-history \
  --instance-types t3.medium \
  --product-descriptions "Linux/UNIX" \
  --max-items 3 \
  --query 'SpotPriceHistory[*].[AvailabilityZone,SpotPrice,Timestamp]' \
  --output table
