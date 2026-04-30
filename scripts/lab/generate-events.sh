#!/usr/bin/env bash
# Generate varied container security events for V1 XDR telemetry
# Deploys test workloads that trigger different detection types.
#
# Usage:
#   bash scripts/lab/generate-events.sh --remote <ip> [--key <pem>]
#   bash scripts/lab/generate-events.sh  # run locally on lab instance
set -euo pipefail

REMOTE=""
KEY_FILE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --remote) REMOTE="$2"; shift 2;;
    --key) KEY_FILE="$2"; shift 2;;
    *) echo "Unknown: $1"; exit 1;;
  esac
done

# Manifests for test workloads
MANIFESTS=$(cat <<'YAML'
---
# Namespace for test workloads
apiVersion: v1
kind: Namespace
metadata:
  name: v1-lab-tests
  labels:
    purpose: security-testing
---
# 1. Privileged container (policy violation)
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: v1-lab-tests
  labels:
    test: privileged-container
spec:
  containers:
  - name: priv
    image: debian:12-slim
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
---
# 2. Image with known CVEs (vulnerability scan trigger)
apiVersion: v1
kind: Pod
metadata:
  name: test-vuln-image
  namespace: v1-lab-tests
  labels:
    test: vulnerable-image
spec:
  containers:
  - name: vuln
    image: nginx:1.21
    ports:
    - containerPort: 80
---
# 3. Container running as root (policy violation)
apiVersion: v1
kind: Pod
metadata:
  name: test-root-user
  namespace: v1-lab-tests
  labels:
    test: root-user
spec:
  containers:
  - name: root
    image: alpine:3.18
    command: ["sleep", "3600"]
    securityContext:
      runAsUser: 0
---
# 4. Pod with hostNetwork (network policy trigger)
apiVersion: v1
kind: Pod
metadata:
  name: test-hostnetwork
  namespace: v1-lab-tests
  labels:
    test: host-network
spec:
  hostNetwork: true
  containers:
  - name: net
    image: alpine:3.18
    command: ["sleep", "3600"]
---
# 5. Pod with hostPID (sensor event trigger)
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpid
  namespace: v1-lab-tests
  labels:
    test: host-pid
spec:
  hostPID: true
  containers:
  - name: pid
    image: alpine:3.18
    command: ["sleep", "3600"]
---
# 6. Pod mounting host filesystem (evaluation event)
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpath
  namespace: v1-lab-tests
  labels:
    test: host-path-mount
spec:
  containers:
  - name: hostfs
    image: alpine:3.18
    command: ["sleep", "3600"]
    volumeMounts:
    - name: host-etc
      mountPath: /host-etc
      readOnly: true
  volumes:
  - name: host-etc
    hostPath:
      path: /etc
      type: Directory
---
# 7. Deployment with multiple replicas (scale test)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-multi-replica
  namespace: v1-lab-tests
  labels:
    test: multi-replica
spec:
  replicas: 3
  selector:
    matchLabels:
      app: multi-test
  template:
    metadata:
      labels:
        app: multi-test
    spec:
      containers:
      - name: web
        image: httpd:2.4
        ports:
        - containerPort: 80
YAML
)

# Runtime events script (runs inside containers after deploy)
RUNTIME_SCRIPT=$(cat <<'SCRIPT'
set -x

echo "=== Deploying test workloads ==="
echo "$MANIFESTS_DATA" | sudo microk8s.kubectl apply -f -

echo ""
echo "Waiting for pods..."
sudo microk8s.kubectl wait --for=condition=Ready pods --all -n v1-lab-tests --timeout=120s 2>/dev/null || true
sudo microk8s.kubectl get pods -n v1-lab-tests

echo ""
echo "=== Generating runtime events ==="

# Suspicious process execution in privileged container
sudo microk8s.kubectl exec -n v1-lab-tests test-privileged -- bash -c '
  # File integrity check — write to sensitive path
  echo "test" > /etc/test-file && rm /etc/test-file
  # Network tools (suspicious in container)
  apt-get update -qq && apt-get install -y -qq net-tools curl 2>/dev/null
  # DNS lookup to external host
  curl -s http://ifconfig.me > /dev/null 2>&1 || true
  # Process listing (recon behavior)
  ps aux > /dev/null
' 2>/dev/null || echo "(privileged container events sent)"

# Suspicious activity in root container
sudo microk8s.kubectl exec -n v1-lab-tests test-root-user -- sh -c '
  # Install package manager tools (suspicious)
  apk add --no-cache curl wget 2>/dev/null || true
  # Download from external URL
  wget -q -O /dev/null https://example.com 2>/dev/null || true
  # Write to /tmp (common malware behavior)
  echo "#!/bin/sh" > /tmp/test.sh
  chmod +x /tmp/test.sh
  rm /tmp/test.sh
' 2>/dev/null || echo "(root container events sent)"

# Read host filesystem
sudo microk8s.kubectl exec -n v1-lab-tests test-hostpath -- sh -c '
  cat /host-etc/passwd > /dev/null
  cat /host-etc/shadow > /dev/null 2>&1 || true
  ls /host-etc/ssh/ > /dev/null 2>&1 || true
' 2>/dev/null || echo "(hostpath events sent)"

echo ""
echo "=== Event Generation Complete ==="
echo "Test workloads deployed. Events will appear in V1 within 5-15 minutes."
echo ""
echo "Cleanup: sudo microk8s.kubectl delete namespace v1-lab-tests"
SCRIPT
)

RUN_CMD="export MANIFESTS_DATA='$MANIFESTS'; $RUNTIME_SCRIPT"

if [[ -n "$REMOTE" ]]; then
  if [[ -z "$KEY_FILE" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    KEY_FILE="$(cd "$SCRIPT_DIR/../.." && pwd)/config/v1-lab-key.pem"
  fi
  echo "Generating events on remote: $REMOTE"
  ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no admin@"$REMOTE" bash -c "'$RUN_CMD'"
else
  echo "Generating events locally..."
  bash -c "$RUN_CMD"
fi
