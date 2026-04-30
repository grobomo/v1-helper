"""
generate-report.py - LLM-powered container security analysis

Pulls V1 vuln data, enriches with K8s context from API, sends each finding
through Claude for environment-aware relevancy analysis, outputs clean HTML
with expandable reasoning so customer can validate/correct the logic.

Usage:
  python tools/generate-report.py                    # Full run
  python tools/generate-report.py --region us-east-1
  python tools/generate-report.py --skip-llm         # Just enrich, no Claude analysis
  python tools/generate-report.py --batch-size 20    # Findings per Claude call
"""

import os
import sys
import json
import html as html_mod
import datetime
import requests
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.expanduser("~/.claude/skills/credential-manager"))
from claude_cred import resolve as cred_resolve

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"


# ============================================================
# V1 API
# ============================================================

API_BASES = {
    "us-east-1": "https://api.xdr.trendmicro.com",
    "eu-central-1": "https://api.eu.xdr.trendmicro.com",
    "ap-southeast-1": "https://api.sg.xdr.trendmicro.com",
    "ap-northeast-1": "https://api.jp.xdr.trendmicro.com",
    "ap-southeast-2": "https://api.au.xdr.trendmicro.com",
}


class V1:
    def __init__(self, region="us-east-1", api_key_name="v1-api/V1_API_KEY"):
        self.key = cred_resolve(api_key_name)
        if not self.key:
            raise RuntimeError(f"No {api_key_name} in credential store. Run: python -c \"import sys; sys.path.insert(0,'~/.claude/skills/credential-manager'); from claude_cred import store; store('{api_key_name}', input('API Key: '))\"")
        self.key = self.key.strip()
        self.base = API_BASES.get(region, API_BASES["us-east-1"])
        self.h = {"Authorization": f"Bearer {self.key}"}

    def _pages(self, path, params=None, max_pages=20):
        import time
        items, url = [], f"{self.base}{path}"
        for _ in range(max_pages):
            for attempt in range(3):
                try:
                    r = requests.get(url, headers=self.h, params=params, timeout=30)
                    r.raise_for_status()
                    break
                except requests.exceptions.HTTPError as e:
                    if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                        wait = (attempt + 1) * 5
                        print(f"  V1 API {r.status_code}, retrying in {wait}s...")
                        time.sleep(wait)
                    else:
                        raise
            d = r.json()
            items.extend(d.get("items", []))
            nxt = d.get("nextLink")
            if not nxt: break
            url, params = nxt, None
        return items

    # Kubernetes
    def clusters(self): return self._pages("/v3.0/containerSecurity/kubernetesClusters")
    def vulns(self): return self._pages("/v3.0/containerSecurity/vulnerabilities", {"limit": 200})
    def image_occ(self): return self._pages("/v3.0/containerSecurity/kubernetesImageOccurrences")
    def eval_events(self): return self._pages("/v3.0/containerSecurity/kubernetesEvaluationEventLogs")
    def sensor_events(self): return self._pages("/v3.0/containerSecurity/kubernetesSensorEventLogs")
    def audit_events(self): return self._pages("/v3.0/containerSecurity/kubernetesAuditEventLogs")
    # Amazon ECS (fault-tolerant — V1 API sometimes 500s on pagination)
    def _pages_safe(self, path, params=None):
        try:
            return self._pages(path, params, max_pages=1)
        except Exception as e:
            print(f"  Warning: {path} failed on pagination: {e}")
            return []

    def ecs_clusters(self): return self._pages_safe("/v3.0/containerSecurity/amazonEcsClusters")
    def ecs_image_occ(self): return self._pages_safe("/v3.0/containerSecurity/amazonEcsImageOccurrences")
    def ecs_sensor_events(self): return self._pages_safe("/v3.0/containerSecurity/amazonEcsSensorEventLogs")

    def xdr_container_search(self, query, top=50):
        """Search container activity data via XDR search API."""
        url = f"{self.base}/v3.0/search/containerActivities"
        h = {**self.h, "TMV1-Query": query}
        try:
            r = requests.get(url, headers=h, params={"top": top}, timeout=30)
            r.raise_for_status()
            return r.json().get("items", [])
        except Exception as e:
            print(f"  XDR search failed: {e}")
            return []


# ============================================================
# Enrich with K8s context
# ============================================================

def enrich(vulns, clusters, occurrences):
    cluster_map = {c["id"]: c for c in clusters}
    occ_map = defaultdict(list)
    for o in occurrences:
        occ_map[o.get("imageId", "")].append(o)

    findings = []
    for v in vulns:
        cluster = cluster_map.get(v.get("clusterId", ""), {})
        occs = occ_map.get(v.get("imageId", ""), [])

        # Extract labels from image occurrences
        all_labels = {}
        for o in occs:
            for lbl in o.get("labels", []):
                if isinstance(lbl, dict):
                    all_labels[lbl.get("key", "")] = lbl.get("value", "")
                elif isinstance(lbl, str) and "=" in lbl:
                    k, _, val = lbl.partition("=")
                    all_labels[k] = val
        labels_str = ", ".join(f"{k}={v}" for k, v in sorted(all_labels.items())) if all_labels else ""

        for pkg in v.get("packages", [{}]):
            findings.append({
                "cve": v.get("name", ""),
                "severity": v.get("severity", "unknown"),
                "score": v.get("cvssRecords", [{}])[0].get("score", "") if v.get("cvssRecords") else "",
                "description": v.get("description", ""),
                "cveLink": v.get("cveLink", ""),
                "package": pkg.get("name", ""),
                "packageVersion": pkg.get("version", ""),
                "fixedVersion": pkg.get("fixedVersion", ""),
                "packageType": pkg.get("type", ""),
                # Cluster context
                "clusterName": cluster.get("name", v.get("clusterId", "?")[:20]),
                "clusterProtection": cluster.get("protectionStatus", "?"),
                "orchestrator": cluster.get("orchestrator", "?"),
                # Image context
                "registry": v.get("registry", ""),
                "repository": v.get("repository", ""),
                "imageDigest": v.get("digest", "")[:20],
                # K8s context from image occurrences
                "namespace": ", ".join(sorted({o["namespace"] for o in occs if o.get("namespace")})) or "(not deployed)",
                "resourceType": ", ".join(sorted({o["resourceType"] for o in occs if o.get("resourceType")})) or "-",
                "resourceName": ", ".join(sorted({o["resourceName"] for o in occs if o.get("resourceName")})) or "-",
                "containerName": ", ".join(sorted({o["containerName"] for o in occs if o.get("containerName")})) or "-",
                "labels": labels_str,
            })

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["package"]))
    return findings


def compute_diff(old_findings, new_findings):
    """Compare two sets of findings. Returns dict with new, resolved, and changed CVEs."""
    old_cves = {}
    for f in old_findings:
        key = (f["cve"], f["package"], f["clusterName"])
        old_cves[key] = f

    new_cves = {}
    for f in new_findings:
        key = (f["cve"], f["package"], f["clusterName"])
        new_cves[key] = f

    old_keys = set(old_cves.keys())
    new_keys = set(new_cves.keys())

    added = [new_cves[k] for k in sorted(new_keys - old_keys)]
    resolved = [old_cves[k] for k in sorted(old_keys - new_keys)]
    changed = []
    for k in old_keys & new_keys:
        old, new = old_cves[k], new_cves[k]
        if old["severity"] != new["severity"]:
            changed.append({"cve": new["cve"], "package": new["package"],
                            "cluster": new["clusterName"],
                            "old_severity": old["severity"],
                            "new_severity": new["severity"]})

    return {"added": added, "resolved": resolved, "changed": changed,
            "old_total": len(old_keys), "new_total": len(new_keys)}


# ============================================================
# Claude analysis
# ============================================================

def generate_customer_context(clusters, vulns, occurrences):
    """Auto-generate customer-context.md from V1 API data on first run."""
    # Gather facts from API data
    cluster_names = [c.get("name", "?") for c in clusters]
    orchestrators = sorted({c.get("orchestrator", "?") for c in clusters})
    node_names = []
    for c in clusters:
        for n in c.get("nodes", []):
            node_names.append(n.get("name", "?"))

    # Detect platform from orchestrator + node names + cluster names
    orch_str = ", ".join(orchestrators)
    is_eks = "eks" in orch_str.lower() or any("eks" in c.lower() for c in cluster_names)
    is_ecs = "ecs" in orch_str.lower() or any("ecs" in c.lower() for c in cluster_names)
    is_gke = "gke" in orch_str.lower() or any("gke" in c.lower() for c in cluster_names)
    is_aks = "aks" in orch_str.lower() or any("aks" in c.lower() for c in cluster_names)
    is_aws = is_eks or is_ecs or any(".compute.internal" in n for n in node_names) or any("ecr" in v.get("registry","") for v in vulns)
    managed = is_eks or is_ecs or is_gke or is_aks

    platforms = []
    if is_eks: platforms.append("Amazon EKS")
    if is_ecs: platforms.append("Amazon ECS")
    if is_gke: platforms.append("Google GKE")
    if is_aks: platforms.append("Azure AKS")
    if not platforms: platforms.append(orch_str)
    platform = " + ".join(platforms) + (" (managed Kubernetes on AWS)" if is_aws else " (managed)" if managed else "")

    host_kernel = "Amazon Linux 2/2023 (managed by AWS)" if is_aws else "managed by cloud provider" if managed else "managed by customer"

    # Images and registries
    registries = sorted({v.get("registry", "") for v in vulns if v.get("registry")})
    repositories = sorted({v.get("repository", "") for v in vulns if v.get("repository")})

    # Namespaces and workloads from occurrences — deduplicated
    namespaces = sorted({o.get("namespace", "") for o in occurrences if o.get("namespace")})
    seen_workloads = set()
    workloads = []
    for o in occurrences:
        rtype = o.get("resourceType", "")
        rname = o.get("resourceName", "")
        cname = o.get("containerName", "")
        img = o.get("repository", "")
        ns = o.get("namespace", "")
        key = f"{ns}/{rtype}/{rname}"
        if rname and key not in seen_workloads:
            seen_workloads.add(key)
            workloads.append(f"{rtype}: {rname} (container: {cname}, image: {img}, namespace: {ns})")

    # Package types found
    pkg_types = set()
    for v in vulns:
        for p in v.get("packages", []):
            if p.get("type"):
                pkg_types.add(p["type"])

    ctx = f"""# Customer Environment Context
# Auto-generated from V1 API data on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}

## Platform
- **{platform}**
- Host kernel: {host_kernel}
- Kernel CVEs in container images are {"NOT exploitable — host kernel is managed by the cloud provider" if managed else "potentially relevant — host kernel is customer-managed"}

## Clusters
{chr(10).join(f'- **{name}**' for name in cluster_names)}

## Nodes ({len(node_names)})
{chr(10).join(f'- {name}' for name in node_names[:10]) or '- (no node data)'}{"" if len(node_names) <= 10 else chr(10) + f'- ...and {len(node_names)-10} more'}

## Container Registries
{chr(10).join(f'- `{r}`' for r in registries) or '- (none detected)'}

## Deployed Images ({len(repositories)})
{chr(10).join(f'- `{r}`' for r in repositories) or '- (none detected)'}

## Namespaces
{', '.join(f'`{ns}`' for ns in namespaces) or '(none detected)'}

## Workloads ({len(workloads)})
{chr(10).join(f'- {w}' for w in workloads) or '- (none detected)'}

## Package Types in Images
{', '.join(sorted(pkg_types)) or '(none detected)'}
"""
    return ctx


CUSTOMERS_DIR = PROJECT_ROOT / "customers"


def load_customer_config(customer="demo"):
    """Load customer config (API key name, region) from customers/<name>.json.
    Auto-creates a default config on first run."""
    p = CUSTOMERS_DIR / f"{customer}.json"
    if p.exists():
        return json.load(open(p))
    # Default config
    config = {
        "api_key_name": f"v1-api/{customer.upper()}_API_KEY",
        "region": "us-east-1",
    }
    CUSTOMERS_DIR.mkdir(parents=True, exist_ok=True)
    json.dump(config, open(str(p), "w"), indent=2)
    print(f"  Created {p} — edit api_key_name and region as needed")
    return config


def load_customer_context(customer="demo", clusters=None, vulns=None, occurrences=None):
    p = CUSTOMERS_DIR / f"{customer}.md"
    if p.exists():
        return p.read_text()
    # Auto-generate on first run if we have API data
    if clusters and vulns and occurrences:
        print(f"  No customers/{customer}.md found — generating from V1 API data...")
        ctx = generate_customer_context(clusters, vulns, occurrences)
        CUSTOMERS_DIR.mkdir(parents=True, exist_ok=True)
        p.write_text(ctx)
        print(f"  Wrote {p} — review and edit for accurate analysis")
        return ctx
    return "No customer context file found. Analyze based on general container security best practices."


def extract_env_label(customer_context):
    """Extract a short environment label from customer context for display."""
    ctx = customer_context.lower()
    parts = []
    if "eks" in ctx: parts.append("EKS")
    if "ecs" in ctx: parts.append("ECS")
    if "gke" in ctx: parts.append("GKE")
    if "aks" in ctx: parts.append("AKS")
    if "openshift" in ctx: parts.append("OpenShift")
    if "microk8s" in ctx: parts.append("MicroK8s")
    if "k3s" in ctx: parts.append("K3s")
    if "rancher" in ctx: parts.append("Rancher")
    if not parts:
        if "container" in ctx: parts.append("Container")
        elif "kubernetes" in ctx or "k8s" in ctx: parts.append("Kubernetes")
        else: parts.append("General")
    return "/".join(parts)


def analyze_batch(findings_batch, customer_context, anthropic_key):
    """Send a batch of findings to Claude for environment-aware analysis."""
    # Build the findings summary for the prompt
    findings_text = ""
    for i, f in enumerate(findings_batch):
        findings_text += f"""
--- Finding {i+1} ---
CVE: {f['cve']} | Severity: {f['severity']} | CVSS: {f['score']}
Package: {f['package']} {f['packageVersion']} ({f['packageType']})
Fix: {f['fixedVersion'] or 'none available'}
Description: {f['description'][:500]}
Running on: cluster={f['clusterName']}, namespace={f['namespace']}, resourceType={f['resourceType']}, resourceName={f['resourceName']}, container={f['containerName']}
Image: {f['repository']}
"""

    prompt = f"""You are a container security analyst. For each CVE below, perform TWO separate analyses:

STEP 1 — ANALYSIS (generic, factual):
Describe what this vulnerability IS. What component is affected? What's the attack vector?
What's the impact (DoS, code execution, info disclosure)? Is it disputed? Does a fix exist?
Be specific — name the affected function/feature, not just the package.

STEP 2 — RELEVANCE (environment-specific):
Given the CUSTOMER CONTEXT below, decide if this CVE matters HERE. Consider:
- Is the vulnerable package/function actually used at runtime in this workload?
- Kernel vs userspace: containers share the host kernel, so kernel-level CVEs in container
  base images are NOT exploitable. But userspace library functions (libc, libssl) ARE linked.
- Is the package a transitive base image dependency that's never loaded?
- What would an attacker need to exploit this? (local access, crafted input, network access)
Do NOT repeat the analysis in the relevance section — only explain the environment-specific decision.

CUSTOMER CONTEXT:
{customer_context}

FINDINGS:
{findings_text}

Respond with a JSON array. Each element MUST have:
- "cve": the exact CVE ID from the finding (e.g. "CVE-2019-1010022")
- "relevant": "yes" | "no" | "low"
- "action": one-sentence specific action item (what to do)
- "reasoning": 2-4 sentences — the ANALYSIS (what this vulnerability is, technical details)
- "relevance_reasoning": 1-2 sentences — the RELEVANCE decision (why it does/doesn't matter in THIS environment, referencing the customer context)
- "owner": who should act ("dev team" | "SRE" | "security" | "none")

Return ONLY the JSON array, no other text."""

    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": anthropic_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 8192,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    r.raise_for_status()
    text = r.json()["content"][0]["text"]

    # Parse JSON from response (handle markdown code blocks)
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        text = text.rsplit("```", 1)[0]
    return json.loads(text)


def run_analysis(findings, customer_context, batch_size=15):
    """Run Claude analysis on all findings in batches. Returns dict keyed by CVE ID."""
    raw = cred_resolve("NEURAL_PIPELINE/CLAUDE_TOKEN") or os.environ.get("ANTHROPIC_API_KEY") or ""
    anthropic_key = raw.replace("\n", "").replace("\r", "").strip()
    if not anthropic_key:
        print("  WARNING: No Anthropic API key found (NEURAL_PIPELINE/API_KEY), skipping LLM analysis")
        return None

    # Deduplicate — analyze each CVE once even if it appears in multiple findings
    seen_cves = set()
    unique_findings = []
    for f in findings:
        if f["cve"] not in seen_cves:
            seen_cves.add(f["cve"])
            unique_findings.append(f)
    print(f"  {len(unique_findings)} unique CVEs to analyze (from {len(findings)} findings)")

    all_results = {}
    for i in range(0, len(unique_findings), batch_size):
        batch = unique_findings[i:i+batch_size]
        print(f"  Analyzing CVEs {i+1}-{i+len(batch)} of {len(unique_findings)}...")
        try:
            results = analyze_batch(batch, customer_context, anthropic_key)
            for r in results:
                cve_id = r.get("cve", "")
                if cve_id:
                    all_results[cve_id] = r
        except Exception as e:
            print(f"  ERROR on batch: {e}")
            for f in batch:
                all_results[f["cve"]] = {
                    "cve": f["cve"], "relevant": "maybe",
                    "action": "Analysis failed — review manually",
                    "reasoning": f"LLM analysis error: {str(e)[:80]}",
                    "owner": "security"
                }
    return all_results


def generate_relevance(analyses, customer_context):
    """Generate relevance reasoning for each CVE by comparing analysis against customer context.
    Runs at report time so relevance updates when customer context changes without re-analyzing CVEs."""
    ctx_lower = customer_context.lower()

    # Extract key facts from customer context
    managed_k8s = any(k in ctx_lower for k in ["eks", "ecs", "gke", "aks"])
    workloads = []
    for line in customer_context.split("\n"):
        line_l = line.strip().lower()
        if line_l.startswith("- ") and any(w in line_l for w in ["nginx", "node", "java", "python", "go", "redis", "postgres"]):
            workloads.append(line.strip("- ").strip())

    # Packages the workloads actually use (extract from context)
    runtime_packages = set()
    not_used_packages = set()
    in_runtime = False
    in_not_used = False
    for line in customer_context.split("\n"):
        ll = line.strip().lower()
        if "actually uses" in ll or "uses at runtime" in ll:
            in_runtime = True; in_not_used = False; continue
        if "not used" in ll or "likely not" in ll:
            in_not_used = True; in_runtime = False; continue
        if ll.startswith("#"):
            in_runtime = False; in_not_used = False; continue
        if (in_runtime or in_not_used) and ll.startswith("- "):
            pkgs = [p.strip().lower() for p in ll.lstrip("- ").split(",")]
            for p in pkgs:
                # Extract package name before parenthetical
                name = p.split("(")[0].split("/")[0].strip()
                if name:
                    if in_runtime:
                        runtime_packages.add(name)
                    else:
                        not_used_packages.add(name)

    for cve_id, a in analyses.items():
        reasoning = a.get("reasoning", "")
        action = a.get("action", "")
        relevant = a.get("relevant", "no")
        pkg_mentioned = a.get("action", "").lower()

        # Build relevance reasoning from context
        rel_parts = []

        # Check if package is in runtime or not-used lists
        for pkg in not_used_packages:
            if pkg in reasoning.lower() or pkg in action.lower():
                rel_parts.append(f"{pkg} is listed as NOT used at runtime in this environment")
                break
        for pkg in runtime_packages:
            if pkg in reasoning.lower() or pkg in action.lower():
                rel_parts.append(f"{pkg} IS used at runtime in this environment")
                break

        # Kernel vs userspace
        if "kernel" in reasoning.lower():
            if managed_k8s:
                rel_parts.append("managed K8s (host kernel controlled by cloud provider, not container image)")
            else:
                rel_parts.append("self-managed K8s (host kernel may need separate patching)")

        if "userspace" in reasoning.lower() or "libc" in reasoning.lower():
            rel_parts.append("userspace library — container links against its own copy at runtime")

        if "disputed" in reasoning.lower():
            rel_parts.append("upstream disputes this as a real vulnerability")

        if "transitive" in reasoning.lower() or "base image" in reasoning.lower():
            rel_parts.append("transitive base image dependency, not directly invoked")

        # Fallback based on relevant field
        if not rel_parts:
            if relevant == "yes":
                rel_parts.append("affects packages/functions active in this workload")
            elif relevant == "low":
                rel_parts.append("theoretical risk — requires specific conditions unlikely in this environment")
            else:
                rel_parts.append("package not used by this workload at runtime")

        a["relevance_reasoning"] = ". ".join(rel_parts) + "."


# ============================================================
# HTML Output
# ============================================================

VIOLATION_CONTEXT = {
    "podexec": {
        "analysis": "Someone ran a command inside a running pod (kubectl exec or equivalent). In production this may indicate debugging activity or unauthorized access.",
        "action": "Check who ran the command and whether it was authorized. Review RBAC policies for exec permissions.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:runtime AND ruleType:podExec AND clusterName:"{cluster}" AND namespaceName:"{namespace}"',
    },
    "unscannedImage": {
        "analysis": "A container image was deployed without being scanned for vulnerabilities first. This bypasses the security scanning pipeline.",
        "action": "Ensure all images go through TMAS scanning in CI/CD before deployment. Consider enabling admission control to block unscanned images.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:evaluation AND violationType:unscannedImage AND clusterName:"{cluster}"',
    },
    "unscannedImageRegistry": {
        "analysis": "Image pulled from a registry that hasn't been configured for scanning.",
        "action": "Configure admission control to block images from unscanned registries.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:evaluation AND violationType:unscannedImageRegistry AND clusterName:"{cluster}"',
    },
    "privilegedContainer": {
        "analysis": "Container running in privileged mode, which gives it full host access. This is a significant security risk.",
        "action": "Review if privileged mode is actually needed. Most containers don't require it. Use specific capabilities instead.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:evaluation AND violationType:privilegedContainer AND clusterName:"{cluster}"',
    },
    "hostNetwork": {
        "analysis": "Container using host network namespace. This bypasses network isolation.",
        "action": "Review if host networking is required. Consider using NodePort or LoadBalancer services instead.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:evaluation AND violationType:hostNetwork AND clusterName:"{cluster}"',
    },
    "hostPID": {
        "analysis": "Container sharing host PID namespace. Can see and interact with host processes.",
        "action": "Review if needed. Remove hostPID unless the container specifically needs to monitor host processes.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:evaluation AND violationType:hostPID AND clusterName:"{cluster}"',
    },
    "readOnlyRootFilesystem": {
        "analysis": "Container does not have a read-only root filesystem. Writable root increases attack surface.",
        "action": "Set readOnlyRootFilesystem: true in the security context. Use emptyDir volumes for writable paths.",
        "xdr_query": 'productName:"Trend Vision One - Container Security" AND eventType:evaluation AND violationType:readOnlyRootFilesystem AND clusterName:"{cluster}"',
    },
}


def _analyze_event(vtype, commands, images, objects, cluster, namespace):
    """Generate specific analysis for a runtime/policy event based on actual data."""
    if vtype == "podexec" and commands:
        cmd = commands[0]
        if "useradd" in cmd or "adduser" in cmd:
            user = cmd.split()[-1] if cmd.split() else "unknown"
            return {
                "severity": "high", "relevant": "yes",
                "title": f"User creation detected: <code>{cmd}</code>",
                "analysis": f"A new user account <code>{user}</code> was created inside a running container. In production, containers should be immutable — user creation suggests either: (1) an attacker establishing persistence after initial access (MITRE T1136.001), (2) a misconfigured entrypoint script, or (3) debugging activity. In managed Kubernetes environments,container user changes are ephemeral (lost on restart), but an attacker could use the new account to escalate privileges or evade detection during the current container lifetime.",
                "action": f"Verify who ran <code>kubectl exec</code> — check RBAC audit logs for exec permissions on namespace <code>{namespace}</code>. If unauthorized, investigate the source IP and user identity. Consider switching from LogOnlyPolicy to an enforcement policy that blocks podExec in production namespaces.",
            }
        elif "shadow" in cmd or "/etc/passwd" in cmd:
            return {
                "severity": "critical", "relevant": "yes",
                "title": f"Sensitive file access: <code>{cmd}</code>",
                "analysis": f"Reading <code>/etc/shadow</code> is a credential harvesting technique (MITRE T1003.008). In containers, /etc/shadow contains hashed passwords for system accounts in the base image. While these are typically non-functional service accounts, an attacker may attempt to crack them or use the access pattern to test what other sensitive files are readable. This is a common post-exploitation reconnaissance step.",
                "action": f"Check if the container runs as root (it shouldn't). Implement read-only root filesystem (<code>readOnlyRootFilesystem: true</code>) in the pod security context. Monitor for follow-up activity: if shadow read is followed by network connections or data exfiltration, treat as active compromise.",
            }
        elif "apt" in cmd or "yum" in cmd or "apk" in cmd:
            return {
                "severity": "medium", "relevant": "yes",
                "title": f"Package manager execution: <code>{cmd}</code>",
                "analysis": f"Running a package manager inside a container at runtime indicates either: (1) an attacker installing tools for lateral movement, exfiltration, or persistence (MITRE T1059.004), (2) a developer debugging, or (3) a poorly built image that installs packages at startup. In production containers on EKS/ECS, packages should be baked into the image at build time. Runtime package installation bypasses vulnerability scanning (TMAS) and introduces unvetted code.",
                "action": f"Block package manager execution via Container Security runtime rules (or OPA/Gatekeeper policies). Ensure images are built with all dependencies and package managers are removed or disabled in the final image layer. If this was debugging, use ephemeral debug containers (<code>kubectl debug</code>) instead.",
            }
        elif "curl" in cmd or "wget" in cmd:
            target = cmd.split()[-1] if cmd.split() else "unknown"
            return {
                "severity": "high", "relevant": "yes",
                "title": f"Outbound HTTP request: <code>{cmd}</code>",
                "analysis": f"An outbound HTTP connection to <code>{target}</code> was initiated from inside the container. This could be: (1) legitimate application behavior, (2) C2 callback to an attacker-controlled server (MITRE T1071.001), (3) data exfiltration, or (4) downloading additional tools. In managed Kubernetes environments,outbound traffic should be restricted via Network Policies or security groups. The target <code>{target}</code> should be verified against expected application dependencies.",
                "action": f"Review whether <code>{target}</code> is an expected dependency. Implement Kubernetes NetworkPolicy to restrict egress to known-good destinations. If unexpected, capture full network context: DNS resolution, response size, timing pattern. Check for data in the request body.",
            }
        else:
            return {
                "severity": "medium", "relevant": "yes",
                "title": f"Command executed in pod: <code>{cmd}</code>",
                "analysis": f"A command was executed inside a running container via kubectl exec or equivalent. Any interactive access to production containers should be audited. The command <code>{cmd}</code> should be reviewed in the context of normal operational procedures for this workload.",
                "action": f"Review RBAC audit logs to identify who executed this command. If this is routine debugging, consider implementing break-glass procedures with time-limited access and mandatory logging.",
            }
    elif vtype == "unscannedImage" and images:
        img = images[0]
        obj = objects[0] if objects else "?"
        return {
            "severity": "medium", "relevant": "yes",
            "title": f"Unscanned image deployed: <code>{img}</code>",
            "analysis": f"Container image <code>{img}</code> was deployed to pod <code>{obj}</code> without passing through vulnerability scanning. This means the image bypassed the CI/CD security pipeline — it could contain known CVEs, malware, embedded secrets, or supply-chain compromises. In managed Kubernetes environments,images should be scanned by TMAS (Trend Micro Artifact Scanner) in the CI/CD pipeline before deployment, and admission control should block unscanned images.",
            "action": f"Configure Container Security admission control to <b>block</b> unscanned images (currently set to log-only). Integrate TMAS scanning into your CI/CD pipeline: <code>tmas scan docker:{img}</code>. For existing deployments, trigger a manual scan from the V1 console. Consider using a private registry with mandatory scan policies.",
        }
    elif vtype == "unscannedImage":
        return {
            "severity": "medium", "relevant": "yes",
            "title": "Unscanned image deployed",
            "analysis": "A container image was deployed without being scanned for vulnerabilities. This bypasses the security scanning pipeline and introduces unknown risk.",
            "action": "Enable admission control to block unscanned images. Integrate TMAS scanning into CI/CD.",
        }
    else:
        ctx = VIOLATION_CONTEXT.get(vtype, {})
        if isinstance(ctx, dict):
            return {"severity": "medium", "relevant": "yes", "title": ctx.get("analysis", f"Policy violation: {vtype}"), "analysis": ctx.get("action", ""), "action": ""}
        return {"severity": "low", "relevant": "low", "title": str(ctx), "analysis": "", "action": ""}


def build_events_html(eval_events, sensor_events, xdr_results=None, v1_inventory_url=None, api_base=None):
    """Build HTML section for non-CVE runtime detections with analysis and XDR queries."""
    if not eval_events and not sensor_events:
        return ""
    xdr_results = xdr_results or {}

    # Sort eval events by severity (critical/high first)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    def _event_severity(ev):
        max_sev = 3
        for v in ev.get("violationReasons", []):
            vt = v.get("type", "")
            v_cmds = [r.get("command","") for r in v.get("resources",[]) if r.get("command")]
            v_imgs = [r.get("image","") for r in v.get("resources",[]) if r.get("image")]
            v_objs = [r.get("object","") for r in v.get("resources",[]) if r.get("object")]
            s = _analyze_event(vt, v_cmds, v_imgs, v_objs, ev.get("clusterName",""), ev.get("namespace","")).get("severity","low")
            max_sev = min(max_sev, sev_rank.get(s, 3))
        return max_sev
    eval_events = sorted(eval_events, key=_event_severity)

    rows = ""
    copy_id = 0
    for e_idx, e in enumerate(eval_events):
        violations = [v.get("type","") for v in e.get("violationReasons",[])]
        resources = []
        for v in e.get("violationReasons",[]):
            for r in v.get("resources",[]):
                parts = []
                if r.get("container"): parts.append(f"container: {r['container']}")
                if r.get("command"): parts.append(f"cmd: {r['command']}")
                if r.get("object"): parts.append(r["object"])
                resources.append(", ".join(parts) if parts else "-")

        cluster = e.get("clusterName", "?")
        namespace = e.get("namespace", "?")

        # Check if this specific event is critical for red border
        # Use per-violation resources, not all resources merged together
        _per_v = []
        for v in e.get("violationReasons", []):
            vt = v.get("type", "")
            v_cmds = [r.get("command","") for r in v.get("resources",[]) if r.get("command")]
            v_imgs = [r.get("image","") for r in v.get("resources",[]) if r.get("image")]
            v_objs = [r.get("object","") for r in v.get("resources",[]) if r.get("object")]
            _per_v.append(_analyze_event(vt, v_cmds, v_imgs, v_objs, cluster, namespace))
        _evt_max_sev = max(({"critical":3,"high":2,"medium":1,"low":0}.get(ev.get("severity","low"),0) for ev in _per_v), default=0)
        evt_crit_cls = ' class="crit-row"' if _evt_max_sev >= 2 else ''

        decision_color = "#44ff44" if e.get("decision") == "allow" else "#ff4444"
        rows += f"""<tr id="evt-{e_idx}"{evt_crit_cls} style="scroll-margin-top:50px">
<td>{e.get("createdDateTime","")[:19]}</td>
<td>{cluster}</td>
<td>{namespace}</td>
<td>{e.get("kind","?")}</td>
<td>{", ".join(violations)}</td>
<td style="color:{decision_color};font-weight:700">{e.get("decision","?")}</td>
<td>{e.get("action","?")}</td>
<td>{"; ".join(resources) or "-"}</td>
<td>{e.get("policyName","?")}</td>
<td></td>
</tr>"""

        # Build analysis row with event-specific context and XDR query
        # Extract commands from resources for specific analysis
        commands = []
        images = []
        objects = []
        for v in e.get("violationReasons", []):
            for r in v.get("resources", []):
                if r.get("command"): commands.append(r["command"])
                if r.get("image"): images.append(r["image"])
                if r.get("object"): objects.append(r["object"])

        analysis_html = ""
        for vtype in violations:
            ctx = VIOLATION_CONTEXT.get(vtype, {"analysis": f"Policy violation: {vtype}", "action": "Review in V1.", "xdr_query": ""})
            if isinstance(ctx, str):
                ctx = {"analysis": ctx, "action": "", "xdr_query": ""}

            # Event-specific analysis based on actual command/image
            specific = _analyze_event(vtype, commands, images, objects, cluster, namespace)
            ev_sev = specific.get("severity", "medium")
            ev_rel = specific.get("relevant", "yes")
            sev_colors = {"critical": "#f8d7da", "high": "#f8d7da", "medium": "#fff3cd", "low": "#d4edda"}
            sev_text_c = {"critical": "#721c24", "high": "#721c24", "medium": "#856404", "low": "#155724"}
            analysis_html += f'<span class="tag" style="background:{sev_colors.get("critical" if ev_rel=="yes" else "low","#eee")};color:{sev_text_c.get("critical" if ev_rel=="yes" else "low","#333")}">Relevant: {ev_rel.upper()}</span> '
            analysis_html += f'<span class="tag" style="background:{sev_colors.get(ev_sev,"#eee")};color:{sev_text_c.get(ev_sev,"#333")}">{ev_sev.upper()}</span> '
            analysis_html += f"<strong>{specific['title']}</strong>"
            analysis_html += f"<div class='reasoning'>{specific['analysis']}</div>"
            if specific.get("action"):
                analysis_html += f"<div class='note' style='margin-top:6px'><strong>Recommended:</strong> {specific['action']}</div>"

            xdr_q = ctx.get("xdr_query", "").format(cluster=cluster, namespace=namespace)

        # Raw event data + XDR query + results (all collapsed together)
        raw_json = json.dumps(e, indent=2, default=str)
        api_url = f"{api_base or API_BASES['us-east-1']}/v3.0/containerSecurity/kubernetesEvaluationEventLogs"
        copy_id += 1
        raw_inner = ""
        # XDR search query
        if xdr_q:
            raw_inner += f"""<div class="xdr-query-box" style="margin-bottom:8px">
<span class="xdr-label">XDR Search:</span>
<code id="xdr-{copy_id}">{xdr_q}</code>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('xdr-{copy_id}').textContent);this.textContent='Copied';setTimeout(()=>this.textContent='&#x2398;',1200)" title="Copy to clipboard">&#x2398;</button>
</div>"""
            # XDR results
            xdr_key = f"{vtype}:{cluster}:{namespace}"
            hits = xdr_results.get(xdr_key, [])
            if hits:
                raw_inner += f'<div class="xdr-results"><span class="xdr-label">XDR Results ({len(hits)} events):</span><table class="xdr-table">'
                raw_inner += '<tr><th>Time</th><th>Container</th><th>Process</th><th>Command</th><th>Parent</th><th>User</th></tr>'
                for h in hits[:10]:
                    raw_inner += f"""<tr>
<td>{h.get("eventTimeDT","")[:19]}</td>
<td>{h.get("containerName","?")}</td>
<td>{h.get("processName","?")}</td>
<td><code>{h.get("processCmd","?")[:80]}</code></td>
<td>{h.get("parentName","?")}</td>
<td>{h.get("objectUser","?")}</td>
</tr>"""
                if len(hits) > 10:
                    raw_inner += f'<tr><td colspan="6" style="text-align:center;font-style:italic">...and {len(hits)-10} more events. Run the query in V1 to see all.</td></tr>'
                raw_inner += '</table></div>'
            elif xdr_results:
                raw_inner += '<div class="xdr-results"><span class="xdr-label">XDR Results: No container activity telemetry indexed yet. Runtime sensor telemetry typically takes 15-60 min to appear in XDR search.</span></div>'
        # API curl — XDR container activity search with server-side filter
        if xdr_q:
            copy_id += 1
            xdr_curl = f'curl -s -H "Authorization: Bearer YOUR_API_KEY" -H \'TMV1-Query: clusterName:{cluster} and k8sNamespace:{namespace}\' "{api_base or API_BASES["us-east-1"]}/v3.0/search/containerActivities?top=50"'
            raw_inner += f"""<div class="xdr-query-box" style="margin-bottom:8px">
<span class="xdr-label">API:</span>
<code id="api-{copy_id}">{html_mod.escape(xdr_curl)}</code>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('api-{copy_id}').textContent);this.textContent='Copied';setTimeout(()=>this.textContent='&#x2398;',1200)" title="Copy to clipboard">&#x2398;</button>
</div>"""
        # Raw JSON
        raw_inner += f'<pre class="raw-json">{html_mod.escape(raw_json)}</pre>'

        analysis_html += f"""<details class="raw-event">
<summary>Review XDR Data</summary>
<div class="raw-event-body">{raw_inner}</div>
</details>"""

        if analysis_html:
            rows += f"""<tr class="analysis-row">
<td colspan="10"><div class="analysis-detail">{analysis_html}</div></td>
</tr>"""

    for e in sensor_events:
        cluster = e.get("clusterName", "?")
        namespace = e.get("namespace", e.get("k8s",{}).get("namespace","?"))
        rows += f"""<tr>
<td>{e.get("createdDateTime","")[:19]}</td>
<td>{cluster}</td>
<td>{namespace}</td>
<td>Sensor</td>
<td>{e.get("ruleName","?")}</td>
<td style="color:#f59e0b;font-weight:700">{e.get("mitigation","?")}</td>
<td>-</td>
<td>{e.get("k8s",{}).get("pod",{}).get("name","?")}</td>
<td>-</td>
</tr>"""
        copy_id += 1
        sensor_query = f'productName:"Trend Vision One - Container Security" AND eventType:runtime AND ruleName:"{e.get("ruleName","")}" AND clusterName:"{cluster}"'
        rows += f"""<tr class="analysis-row">
<td colspan="10"><div class="analysis-detail">
<strong>Runtime sensor detection.</strong> Investigate the process and context that triggered this rule.
<div class="xdr-query-box">
<span class="xdr-label">XDR Query:</span>
<code id="xdr-{copy_id}">{sensor_query}</code>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('xdr-{copy_id}').textContent);this.textContent='Copied';setTimeout(()=>this.textContent='&#x2398;',1200)" title="Copy to clipboard">&#x2398;</button>
</div>
</div></td>
</tr>"""

    return f"""<table>
<tr><th>Time</th><th>Cluster</th><th>Namespace</th><th>Kind</th><th>Violation</th><th>Decision</th><th>Action</th><th>Details</th><th>Policy</th><th style="text-align:center"><a href="{v1_inventory_url or 'https://portal.xdr.trendmicro.com/index.html#/app/server-cloud/container-inventory'}" target="_blank" style="text-decoration:none;color:#fff;background:#0066cc;padding:3px 10px;border-radius:4px;font-size:0.85em;font-weight:700;white-space:nowrap">Open in V1</a></th></tr>
{rows}
</table>"""


PORTAL_BASES = {
    "us-east-1": "https://portal.xdr.trendmicro.com",
    "eu-central-1": "https://portal.eu.xdr.trendmicro.com",
    "ap-southeast-1": "https://portal.sg.xdr.trendmicro.com",
    "ap-northeast-1": "https://portal.jp.xdr.trendmicro.com",
    "ap-southeast-2": "https://portal.au.xdr.trendmicro.com",
}


def write_html(findings, analyses, clusters, output_path, eval_events=None, sensor_events=None, xdr_results=None, customer_context=None, region="us-east-1", diff_data=None):
    now = datetime.datetime.now()
    customer_context = customer_context or "No customer context provided. Analysis based on general container security best practices."
    portal_base = PORTAL_BASES.get(region, PORTAL_BASES["us-east-1"])
    v1_container_vulns = f"{portal_base}/index.html#/app/server-cloud/container-protection"
    v1_container_inventory = f"{portal_base}/index.html#/app/server-cloud/container-inventory"
    env_label = extract_env_label(customer_context)
    sev_colors = {"critical": "#f8d7da", "high": "#f8d7da", "medium": "#fff3cd", "low": "#d4edda"}
    sev_text = {"critical": "#721c24", "high": "#721c24", "medium": "#856404", "low": "#155724"}

    # Build analysis lookup by CVE ID (handles both dict and list formats)
    analysis_map = {}
    if analyses:
        if isinstance(analyses, dict):
            analysis_map = analyses
        elif isinstance(analyses, list):
            for a in analyses:
                cve_id = a.get("cve", "")
                if cve_id:
                    analysis_map[cve_id] = a

    # Group findings by image + k8s location
    groups = defaultdict(list)
    for f in findings:
        key = (f["clusterName"], f["repository"], f["namespace"], f["resourceName"], f.get("labels", ""))
        groups[key].append(f)

    # Build cluster overview
    cluster_html = ""
    for c in clusters:
        cname = c.get("name", "?")
        orch = c.get("orchestrator", "?")
        status = c.get("protectionStatus", "?")
        helm_ver = c.get("applicationVersion", "?")
        policy_id = c.get("policyId", "?")
        # Extract policy name from policyId (format: PolicyName-hash)
        policy_name = policy_id.rsplit("-", 1)[0] if "-" in policy_id else policy_id
        nodes = c.get("nodes", [])
        node_count = len(nodes)
        total_pods = sum(len(n.get("pods", [])) for n in nodes)
        created = c.get("createdDateTime", "?")
        last_eval = c.get("lastEvaluatedDateTime", "?")

        # Protection status tag color and troubleshooting
        status_class = "healthy" if status == "HEALTHY" else "medium"
        status_note = ""
        if status == "UNKNOWN":
            status_note = """<div class="warn"><strong>Troubleshooting:</strong> Protection status shows UNKNOWN. This typically means the cluster was recently registered and V1 hasn't completed its first full health check yet. It can also indicate the Container Security agent pods are still initializing. Check: <code>kubectl get pods -n trendmicro-system</code> — all pods should be Running. If pods are CrashLoopBackOff, check logs with <code>kubectl logs -n trendmicro-system &lt;pod-name&gt;</code>. Status usually updates to HEALTHY within 5-15 minutes after all agent pods are ready.</div>"""

        # Module status
        modules = [
            ("Runtime Security", c.get("runtimeSecurityEnabled", False)),
            ("Vulnerability Scanning", c.get("vulnerabilityScanEnabled", False)),
            ("Malware Scanning", c.get("malwareScanEnabled", False)),
            ("Secret Scanning", c.get("secretScanEnabled", False)),
            ("File Integrity Monitoring", c.get("fileIntegrityMonitoringEnabled", False)),
            ("Audit Log Collection", c.get("auditLogCollectionEnabled", False)),
        ]
        modules_html = ""
        for mod_name, enabled in modules:
            tag = '<span class="tag healthy">Enabled</span>' if enabled else '<span class="tag" style="background:#f8d7da;color:#721c24">Disabled</span>'
            modules_html += f"<tr><td>{mod_name}</td><td>{tag}</td></tr>"

        # Node topology
        node_rows = ""
        for n in nodes:
            nname = n.get("name", "?")
            pod_count = len(n.get("pods", []))
            # Infer namespaces from pod names (V1 API doesn't include namespace in node pod data)
            ns_set = set()
            for p in n.get("pods", []):
                pname = p.get("name", "")
                if pname.startswith("trendmicro-"): ns_set.add("trendmicro-system")
                elif pname.startswith("calico-") or pname.startswith("coredns-") or pname.startswith("kube-"): ns_set.add("kube-system")
                elif pname.startswith("nginx-") or not any(pname.startswith(x) for x in ["trendmicro-","calico-","coredns-","kube-","hostpath-"]): ns_set.add("default")
            namespaces = sorted(ns_set) if ns_set else ["(unknown)"]
            node_rows += f"<tr><td><code>{nname}</code></td><td>{pod_count}</td><td><code>{', '.join(namespaces)}</code></td></tr>"

        cluster_html += f"""
<div class="status-box">
  <div class="grid">
    <div>
      <p class="kv"><strong>Cluster:</strong> {cname}</p>
      <p class="kv"><strong>Orchestrator:</strong> {orch}</p>
      <p class="kv"><strong>Helm Version:</strong> {helm_ver}</p>
      <p class="kv"><strong>Protection:</strong> <span class="tag {status_class}">{status}</span></p>
      <p class="kv"><strong>Policy:</strong> {policy_name}</p>
    </div>
    <div>
      <p class="kv"><strong>Nodes:</strong> {node_count}</p>
      <p class="kv"><strong>Pods Monitored:</strong> {total_pods}</p>
      <p class="kv"><strong>Created:</strong> {created}</p>
      <p class="kv"><strong>Last Evaluated:</strong> {last_eval}</p>
    </div>
  </div>
  {status_note}
</div>
<h3>Protection Modules</h3>
<table>
  <tr><th>Module</th><th>Status</th></tr>
  {modules_html}
</table>
<h3>Node Topology</h3>
<table>
  <tr><th>Node</th><th>Pods</th><th>Namespaces</th></tr>
  {node_rows}
</table>"""

    # Build image group sections — grouped by cluster
    cluster_map_info = {c.get("name", "?"): c for c in clusters}
    cluster_groups = defaultdict(list)
    for (cluster_name, repo, ns, res_name, labels), group_findings in groups.items():
        cluster_groups[cluster_name].append((repo, ns, res_name, labels, group_findings))

    # Sort clusters: most CVEs first
    sorted_clusters = sorted(cluster_groups.items(), key=lambda x: sum(len(gf) for _, _, _, _, gf in x[1]), reverse=True)

    groups_html = ""
    for cluster_name, image_groups in sorted_clusters:
        total_cves = sum(len(gf) for _, _, _, _, gf in image_groups)
        ci = cluster_map_info.get(cluster_name, {})
        orch = ci.get("orchestrator", "?")
        protection = ci.get("protectionStatus", "?")
        prot_class = "healthy" if protection == "HEALTHY" else "medium"

        groups_html += f"""
<div class="cluster-section">
  <h3 class="cluster-header"><span class="tag {prot_class}">{protection}</span> {html_mod.escape(cluster_name)} <span style="font-size:0.75em;color:var(--meta);font-weight:400">({orch}) &mdash; {total_cves} CVEs across {len(image_groups)} image{'s' if len(image_groups) != 1 else ''}</span></h3>"""

        for repo, ns, res_name, labels, group_findings in image_groups:
            sev_counts = defaultdict(int)
            for f in group_findings:
                sev_counts[f["severity"]] += 1
            sev_summary = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items(), key=lambda x: ["critical","high","medium","low"].index(x[0]) if x[0] in ["critical","high","medium","low"] else 9))

            f0 = group_findings[0]
            res_type = f0.get("resourceType", "-")
            container = f0.get("containerName", "-")
            lbl = f0.get("labels", "")

            groups_html += f"""
  <div class="status-box">
    <h4><span class="tag medium">{len(group_findings)} CVEs</span> {repo}</h4>
    <div class="grid">
      <div>
        <p class="kv"><strong>Registry:</strong> <code>{f0.get('registry','')}</code></p>
        <p class="kv"><strong>Repository:</strong> <code>{repo}</code></p>
        <p class="kv"><strong>Digest:</strong> <code>{f0.get('imageDigest','')}</code></p>
        <p class="kv"><strong>CVEs:</strong> {sev_summary}</p>
      </div>
      <div>
        <p class="kv"><strong>Namespace:</strong> <code>{ns}</code></p>
        <p class="kv"><strong>{res_type}:</strong> <code>{res_name}</code></p>
        <p class="kv"><strong>Container:</strong> <code>{container}</code></p>"""
            if lbl:
                groups_html += f"""
        <p class="kv"><strong>Labels:</strong> <code>{lbl}</code></p>"""
            groups_html += f"""
      </div>
    </div>
    <div class="note">
      <strong>SRE Fix:</strong> Update image in {res_type.lower()} <code>{res_name}</code> (namespace: <code>{ns}</code>):<br>
      <code>kubectl set image {res_type.lower()}/{res_name} {container}={repo}:&lt;patched-tag&gt; -n {ns}</code>
    </div>
  </div>"""

        groups_html += "\n</div>"

    # Build CVE detail table with full-width analysis rows
    total = len(findings)
    sev_totals = defaultdict(int)
    for f in findings:
        sev_totals[f["severity"]] += 1

    # Sort findings: relevant first (yes > low > maybe > no), then by severity
    rel_order = {"yes": 0, "low": 1, "maybe": 2, "no": 3}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4}
    findings.sort(key=lambda f: (
        rel_order.get(analysis_map.get(f["cve"], {}).get("relevant", "no"), 3),
        sev_order.get(f["severity"], 9),
    ))

    rows_html = ""
    for f in findings:
        sc = sev_colors.get(f["severity"], "#eee")
        st = sev_text.get(f["severity"], "#333")
        cve = f["cve"]
        analysis = analysis_map.get(cve, {})

        is_crit = analysis.get("relevant") == "yes" and f["severity"] in ("critical", "high")
        crit_cls = ' class="crit-row"' if is_crit else ''
        rows_html += f"""<tr id="cve-{cve}"{crit_cls} style="scroll-margin-top:50px">
<td><a href="{f['cveLink']}" target="_blank">{cve}</a></td>
<td><span class="tag" style="background:{sc};color:{st}">{f["severity"].upper()}</span></td>
<td>{f.get('score','')}</td>
<td>{f["package"]}</td>
<td><code>{f["packageVersion"]}</code></td>
<td><code>{f["namespace"]}</code></td>
<td><code>{f["resourceName"]}</code></td>
<td>{f.get("containerName","-")}</td>
<td>{f["repository"]}</td>
<td style="text-align:center"><a href="{v1_container_vulns}" target="_blank" class="v1-link" title="Open in V1 Console">V1</a> <button class="copy-btn" onclick="navigator.clipboard.writeText('{cve}');this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1200)" title="Copy {cve}" style="white-space:nowrap">Copy</button></td>
</tr>"""

        # Full-width analysis row under CVE
        if not analysis:
            rows_html += f"""<tr class="analysis-row">
<td colspan="10">
  <div class="analysis-detail">
    <span class="tag" style="background:#fff3cd;color:#856404">UNANALYZED</span>
    <strong>No analysis available for this CVE. Run report without --skip-llm to generate.</strong>
  </div>
</td>
</tr>"""
        if analysis:
            relevant = analysis.get("relevant", "?")
            rel_colors = {"yes": "#f8d7da", "no": "#d4edda", "low": "#fff3cd", "maybe": "#fff3cd"}
            rel_text = {"yes": "#721c24", "no": "#155724", "low": "#856404", "maybe": "#856404"}
            rel_bg = rel_colors.get(relevant, "#eee")
            rel_fg = rel_text.get(relevant, "#333")
            action = analysis.get("action", "")
            # Support both old (reasoning) and new (what + why_relevant) formats
            what = analysis.get("what", "")
            why_relevant = analysis.get("why_relevant", "")
            reasoning = analysis.get("reasoning", "")
            owner = analysis.get("owner", "")

            rows_html += f"""<tr class="analysis-row">
<td colspan="10">
  <div class="analysis-detail">
    <span class="tag" style="background:{rel_bg};color:{rel_fg}">Relevant: {relevant.upper()}</span>
    {f'<span class="owner-tag">{owner}</span>' if owner and owner != 'none' else ''}
    <strong>{action}</strong>
    <div class="reasoning">{reasoning}</div>
    <div class="reasoning" style="margin-top:4px"><strong style="color:var(--heading)">Relevance:</strong> {analysis.get('relevance_reasoning', '') or ('Relevant to this environment — see analysis above.' if relevant == 'yes' else 'Low priority — see analysis above.' if relevant == 'low' else 'Not relevant to this environment — see analysis above.')}</div>
  </div>
</td>
</tr>"""

    # Build critical findings summary (high relevance + high/critical severity)
    critical_items = []
    # From CVE analysis
    for f in findings:
        a = analysis_map.get(f["cve"], {})
        if a.get("relevant") == "yes" and f["severity"] in ("critical", "high"):
            critical_items.append({
                "type": "CVE", "id": f["cve"], "severity": f["severity"],
                "package": f["package"], "title": a.get("action", ""),
                "detail": a.get("reasoning", ""),
            })
    # From runtime events
    for e in (eval_events or []):
        cmds = [r.get("command","") for v in e.get("violationReasons",[]) for r in v.get("resources",[]) if r.get("command")]
        imgs = [r.get("image","") for v in e.get("violationReasons",[]) for r in v.get("resources",[]) if r.get("image")]
        objs = [r.get("object","") for v in e.get("violationReasons",[]) for r in v.get("resources",[]) if r.get("object")]
        vtypes = [v.get("type","") for v in e.get("violationReasons",[])]
        for vt in vtypes:
            ev = _analyze_event(vt, cmds, imgs, objs, e.get("clusterName",""), e.get("namespace",""))
            if ev.get("relevant") == "yes" and ev.get("severity") in ("critical", "high"):
                critical_items.append({
                    "type": "Runtime", "id": vt, "severity": ev["severity"],
                    "package": ", ".join(cmds) or ", ".join(imgs) or vt,
                    "title": ev["title"], "detail": ev["analysis"],
                })

    # Tag runtime event indices for anchor links
    for e_idx, e in enumerate(eval_events or []):
        cmds = [r.get("command","") for v in e.get("violationReasons",[]) for r in v.get("resources",[]) if r.get("command")]
        imgs = [r.get("image","") for v in e.get("violationReasons",[]) for r in v.get("resources",[]) if r.get("image")]
        objs = [r.get("object","") for v in e.get("violationReasons",[]) for r in v.get("resources",[]) if r.get("object")]
        vtypes = [v.get("type","") for v in e.get("violationReasons",[])]
        for vt in vtypes:
            ev = _analyze_event(vt, cmds, imgs, objs, e.get("clusterName",""), e.get("namespace",""))
            if ev.get("relevant") == "yes" and ev.get("severity") in ("critical", "high"):
                for ci in critical_items:
                    if ci["type"] == "Runtime" and ci["title"] == ev["title"] and "evt_idx" not in ci:
                        ci["evt_idx"] = e_idx
                        break

    import re as _re
    if critical_items:
        crit_html = ""
        for ci in critical_items:
            sc = sev_colors.get(ci["severity"], "#eee")
            st = sev_text.get(ci["severity"], "#333")
            anchor = f"cve-{ci['id']}" if ci["type"] == "CVE" else f"evt-{ci.get('evt_idx', 0)}"
            short = _re.sub(r'<[^>]+>', '', ci['title'])
            if len(short) > 120:
                short = short[:117] + "..."
            crit_html += f"""<a class="crit-item" href="#{anchor}" title="Click to view details">
  <span class="tag" style="background:{sc};color:{st}">{ci['severity'].upper()}</span>
  <span class="tag" style="background:{'#0066cc' if ci['type']=='CVE' else '#6f42c1'};color:#fff">{ci['type']}</span>
  <span class="crit-pkg">{ci['package']}</span>
  <span class="crit-title">{short}</span>
</a>"""
        critical_section = f"""<h2 style="color:#721c24;scroll-margin-top:50px">Critical Findings</h2>
<div class="section" data-section="critical">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p>{len(critical_items)} high-relevance, high-severity findings. Click any to jump to details.</p>
<div class="crit-list">{crit_html}</div>
  </div>
</div>"""
    else:
        critical_section = """<h2 style="color:#155724;scroll-margin-top:50px">Critical Findings</h2>
<div class="status-box" style="border-left:4px solid #155724">
  <span class="tag healthy">ALL CLEAR</span>
  <strong>No high-relevance, high-severity alerts found. Nice!</strong>
</div>"""

    # Build diff section if we have comparison data
    diff_section = ""
    if diff_data and (diff_data["added"] or diff_data["resolved"] or diff_data["changed"]):
        sev_order_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        diff_items = []
        for f in sorted(diff_data["added"], key=lambda x: sev_order_map.get(x["severity"], 9)):
            sc = sev_colors.get(f["severity"], "#eee")
            st = sev_text.get(f["severity"], "#333")
            diff_items.append(f'<div class="diff-item diff-new"><span class="tag" style="background:{sc};color:{st}">{f["severity"].upper()}</span> <strong>NEW</strong> <a href="#cve-{f["cve"]}">{f["cve"]}</a> in {html_mod.escape(f["package"])} ({html_mod.escape(f["clusterName"])})</div>')
        for f in sorted(diff_data["resolved"], key=lambda x: sev_order_map.get(x["severity"], 9)):
            sc = sev_colors.get(f["severity"], "#eee")
            st = sev_text.get(f["severity"], "#333")
            diff_items.append(f'<div class="diff-item diff-resolved"><span class="tag" style="background:{sc};color:{st}">{f["severity"].upper()}</span> <strong>RESOLVED</strong> {f["cve"]} in {html_mod.escape(f["package"])} ({html_mod.escape(f["clusterName"])})</div>')
        for c in diff_data["changed"]:
            diff_items.append(f'<div class="diff-item diff-changed"><strong>CHANGED</strong> <a href="#cve-{c["cve"]}">{c["cve"]}</a> in {html_mod.escape(c["package"])} — {c["old_severity"].upper()} &rarr; {c["new_severity"].upper()}</div>')

        n_new = len(diff_data["added"])
        n_res = len(diff_data["resolved"])
        n_chg = len(diff_data["changed"])
        delta = diff_data["new_total"] - diff_data["old_total"]
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        diff_section = f"""<h2 style="scroll-margin-top:50px">Changes Since Last Run</h2>
<div class="section" data-section="diff">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p><strong>{n_new} new</strong> | <strong>{n_res} resolved</strong> | <strong>{n_chg} severity changed</strong> | Net: {delta_str} ({diff_data['old_total']} &rarr; {diff_data['new_total']})</p>
<div class="diff-list">{''.join(diff_items)}</div>
  </div>
</div>"""

    # Count relevant CVEs and CVEs needing action
    relevant_count = sum(1 for f in findings if analysis_map.get(f["cve"], {}).get("relevant") in ("yes", "low"))
    need_action_count = sum(1 for ci in critical_items if ci["type"] == "CVE")
    unanalyzed_cves = set(f["cve"] for f in findings) - set(analysis_map.keys())
    unanalyzed_count = len(unanalyzed_cves)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Container Security Report — {now.strftime('%Y-%m-%d %H:%M')}</title>
<style>
  :root {{
    --bg: #f8f9fa; --fg: #1a1a2e; --bg2: #fff; --border: #ddd; --code-bg: #e8e8e8;
    --th-bg: #0f3460; --th-fg: #fff; --even-row: #f2f2f2; --link: #0f3460;
    --heading: #0f3460; --heading2: #16213e; --meta: #666; --reasoning: #444;
    --analysis-bg: #f0f4ff; --note-bg: #e3f2fd; --note-border: #1976d2;
    --warn-bg: #fff3cd; --warn-border: #ffc107; --owner-bg: #e8e8e8; --owner-fg: #333;
    --toolbar-bg: #eef0f3; --shadow: rgba(0,0,0,0.08);
  }}
  html.dark {{
    --bg: #111; --fg: #e0e0e0; --bg2: #1a1a1a; --border: #333; --code-bg: #2a2a2a;
    --th-bg: #1a2744; --th-fg: #ccc; --even-row: #181818; --link: #6db3f2;
    --heading: #6db3f2; --heading2: #8fc4f8; --meta: #888; --reasoning: #aaa;
    --analysis-bg: #141a28; --note-bg: #0d1f30; --note-border: #2a6cb0;
    --warn-bg: #2a2200; --warn-border: #b38600; --owner-bg: #2a2a2a; --owner-fg: #ccc;
    --toolbar-bg: #1a1a1a; --shadow: rgba(0,0,0,0.3);
  }}
  .toolbar, .theme-toggle .track, .theme-toggle .thumb, .section-bar, .section-bar .chev, .section-bar .expand-label, .export-btn, .copy-btn, .crit-item, .font-btn {{ transition: background-color 0.2s, color 0.2s, border-color 0.2s; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; background: var(--bg); color: var(--fg); font-size: var(--base-font, 18px); }}
  h1 {{ border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: var(--heading); margin-top: 30px; border-bottom: 1px solid var(--border); padding-bottom: 5px; scroll-margin-top: 50px; }}
  h3 {{ color: var(--heading2); margin-top: 20px; }}
  table {{ border-collapse: separate; border-spacing: 0; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid var(--border); padding: 8px 12px; text-align: left; font-size: 0.9em; }}
  th {{ background: var(--th-bg); color: var(--th-fg); position: sticky; top: 41px; z-index: 10; border: 1px solid var(--border); box-shadow: 0 -10px 0 var(--th-bg); }}
  tr:nth-child(even):not(.analysis-row) {{ background: var(--even-row); }}
  code {{ background: var(--code-bg); padding: 2px 6px; border-radius: 3px; font-size: 0.85em; color: var(--fg); }}
  a {{ color: var(--link); }}
  .meta {{ color: var(--meta); font-size: 0.85em; margin-top: 30px; border-top: 1px solid var(--border); padding-top: 10px; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; margin: 0 2px; }}
  .tag.healthy {{ background: #d4edda; color: #155724; }}
  .tag.medium {{ background: #fff3cd; color: #856404; }}
  .status-box {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 12px 0; box-shadow: 0 1px 3px var(--shadow); }}
  .cluster-section {{ margin: 20px 0; padding: 16px 0; border-top: 2px solid var(--border); }}
  .cluster-section:first-child {{ border-top: none; padding-top: 0; }}
  .cluster-header {{ margin-bottom: 8px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  .kv {{ margin: 4px 0; }}
  .kv strong {{ color: var(--heading); }}
  .note {{ background: var(--note-bg); border-left: 4px solid var(--note-border); padding: 10px 14px; margin: 10px 0; border-radius: 0 6px 6px 0; }}
  .warn {{ background: var(--warn-bg); border-left: 4px solid var(--warn-border); padding: 10px 14px; margin: 10px 0; border-radius: 0 6px 6px 0; }}
  .analysis-row {{ background: var(--analysis-bg) !important; }}
  .analysis-row td {{ border-top: none; padding: 6px 16px 12px; }}
  .analysis-detail {{ font-size: 0.88em; line-height: 1.6; }}
  .analysis-detail strong {{ display: block; margin: 4px 0; color: var(--heading); }}
  .reasoning {{ color: var(--reasoning); margin-top: 4px; }}
  .analysis-sections {{ margin-top: 6px; display: flex; flex-direction: column; gap: 4px; }}
  .analysis-label {{ font-weight: 700; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.3px; color: var(--heading); margin-right: 4px; }}
  .analysis-what {{ color: var(--fg); font-size: 0.9em; line-height: 1.5; }}
  .analysis-why {{ color: var(--reasoning); font-size: 0.9em; line-height: 1.5; padding-left: 12px; border-left: 3px solid var(--border); }}
  .owner-tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; background: var(--owner-bg); color: var(--owner-fg); margin-left: 4px; }}
  .xdr-query-box {{ margin-top: 8px; padding: 6px 10px; background: var(--code-bg); border-radius: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .xdr-query-box code {{ background: none; padding: 0; font-size: 0.82em; flex: 1; word-break: break-all; color: var(--fg); }}
  .xdr-label {{ font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: var(--meta); white-space: nowrap; }}
  .copy-btn {{ background: var(--th-bg); color: var(--th-fg); border: none; border-radius: 4px; padding: 3px 8px; font-size: 0.8em; cursor: pointer; white-space: nowrap; transition: background 0.15s; }}
  .copy-btn:hover {{ opacity: 0.85; }}
  .v1-link {{ display: inline-block; background: #0066cc; color: #fff; text-decoration: none; border-radius: 4px; padding: 3px 8px; font-size: 0.8em; font-weight: 700; white-space: nowrap; transition: background 0.15s; margin-right: 4px; }}
  .v1-link:hover {{ background: #0052a3; }}
  .diff-list {{ display: flex; flex-direction: column; gap: 4px; }}
  .diff-item {{ padding: 6px 10px; border-radius: 4px; font-size: 0.9em; border-left: 4px solid var(--border); }}
  .diff-new {{ border-left-color: #e94560; background: rgba(233,69,96,0.08); }}
  .diff-resolved {{ border-left-color: #155724; background: rgba(21,87,36,0.08); }}
  .diff-changed {{ border-left-color: #856404; background: rgba(133,100,4,0.08); }}
  .xdr-results {{ margin-top: 8px; }}
  .xdr-results .xdr-label {{ display: block; margin-bottom: 4px; }}
  .xdr-table {{ font-size: 0.82em; margin: 4px 0; }}
  .xdr-table th {{ background: var(--code-bg); color: var(--fg); font-size: 0.85em; padding: 4px 8px; }}
  .xdr-table td {{ padding: 3px 8px; font-size: 0.85em; }}
  /* Critical findings list */
  .crit-list {{ display: flex; flex-direction: column; gap: 2px; }}
  .crit-item {{ display: flex; align-items: center; gap: 8px; padding: 6px 10px; border-radius: 6px; text-decoration: none; color: var(--fg); border: 2px solid transparent; transition: border-color 0.15s, background 0.15s; cursor: pointer; }}
  .crit-item:hover {{ border-color: #f0c040; background: var(--bg2); }}
  .crit-pkg {{ font-weight: 700; font-size: 0.85em; min-width: 70px; }}
  .crit-title {{ font-size: 0.85em; color: var(--reasoning); }}
  /* Target highlight when jumping from critical findings */
  /* Target highlight — static yellow bg, removed by JS after 2s */
  tr.flash-target td, tr.flash-target + tr.analysis-row td {{ background: rgba(240,192,64,0.25) !important; }}
  /* Row pair borders — data row: top+sides, analysis row: bottom+sides */
  tr[id^="cve-"] td, tr[id^="evt-"] td {{ box-shadow: inset 0 1px 0 var(--border); }}
  tr[id^="cve-"] td:first-child, tr[id^="evt-"] td:first-child {{ box-shadow: inset 0 1px 0 var(--border), inset 1px 0 0 var(--border); }}
  tr[id^="cve-"] td:last-child, tr[id^="evt-"] td:last-child {{ box-shadow: inset 0 1px 0 var(--border), inset -1px 0 0 var(--border); }}
  tr[id] + tr.analysis-row td {{ box-shadow: inset 0 -1px 0 var(--border), inset 1px 0 0 var(--border), inset -1px 0 0 var(--border); }}
  /* Red override for critical — same structure, thicker */
  tr.crit-row td {{ box-shadow: inset 0 2px 0 #e94560; }}
  tr.crit-row td:first-child {{ box-shadow: inset 0 2px 0 #e94560, inset 2px 0 0 #e94560; }}
  tr.crit-row td:last-child {{ box-shadow: inset 0 2px 0 #e94560, inset -2px 0 0 #e94560; }}
  tr.crit-row + tr.analysis-row td {{ box-shadow: inset 0 -2px 0 #e94560, inset 2px 0 0 #e94560, inset -2px 0 0 #e94560; }}
  .raw-event {{ margin-top: 10px; }}
  .raw-event {{ margin-top: 10px; }}
  .raw-event summary {{ cursor: pointer; font-size: 0.8em; font-weight: 700; color: var(--fg); background: var(--code-bg); display: block; padding: 8px 12px; border-radius: 6px; text-align: center; letter-spacing: 0.3px; transition: background 0.15s; }}
  .raw-event summary:hover {{ background: var(--border); }}
  .raw-event[open] summary {{ border-radius: 6px 6px 0 0; }}
  .raw-event-body {{ margin-top: 6px; }}
  .raw-json {{ background: var(--code-bg); padding: 10px 14px; border-radius: 6px; font-size: 0.78em; line-height: 1.5; overflow-x: auto; max-height: 400px; overflow-y: auto; white-space: pre; font-family: 'Cascadia Code', 'Fira Code', monospace; color: var(--fg); }}
  ul {{ margin: 6px 0; }}
  li {{ margin: 4px 0; }}
  /* Collapsible sections */
  .section {{ display: flex; align-items: stretch; margin: 0 0 4px; }}
  .section-bar {{ width: 18px; min-width: 18px; background: var(--border); border-radius: 4px 0 0 4px; cursor: pointer; display: flex; flex-direction: column; align-items: center; padding: 10px 0 16px; gap: 6px; flex-shrink: 0; user-select: none; }}
  .section-bar:hover {{ background: var(--heading); }}
  .section-bar:hover .chev {{ stroke: var(--th-fg); }}
  .section-bar:hover .expand-label {{ color: var(--th-fg); }}
  .section-bar .chev {{ width: 10px; height: 10px; stroke: var(--meta); fill: none; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; transition: transform 0.2s, stroke 0.15s; transform: rotate(90deg); }}
  .section.collapsed .section-bar .chev {{ transform: rotate(0deg); }}
  .section-bar .expand-label {{ font-size: 0.65em; font-weight: 700; color: var(--meta); writing-mode: vertical-lr; text-orientation: mixed; letter-spacing: 1px; text-transform: uppercase; opacity: 0; transition: opacity 0.2s; pointer-events: none; }}
  .section.collapsed .section-bar {{ width: 28px; min-width: 28px; }}
  .section.collapsed .section-bar .expand-label {{ opacity: 1; }}
  .section-body {{ flex: 1; min-width: 0; }}
  .section.collapsed .section-body {{ display: none; }}
  .section:not(.collapsed) .section-body {{ display: block; }}
  /* Theme toggle */
  .theme-toggle {{ display: flex; align-items: center; gap: 6px; }}
  .theme-toggle label {{ position: relative; width: 36px; height: 20px; cursor: pointer; }}
  .theme-toggle input {{ display: none; }}
  .theme-toggle .track {{ position: absolute; inset: 0; background: #ccc; border-radius: 10px; transition: background 0.2s; }}
  html.dark .theme-toggle .track {{ background: #444; }}
  .theme-toggle .thumb {{ position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; background: #fff; border-radius: 50%; transition: transform 0.2s; box-shadow: 0 1px 2px rgba(0,0,0,0.2); }}
  .theme-toggle input:checked ~ .thumb {{ transform: translateX(16px); }}
  .theme-toggle svg {{ width: 14px; height: 14px; stroke: var(--meta); fill: none; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }}
  /* Floating toolbar */
  .toolbar {{ position: sticky; top: 0; z-index: 200; display: flex; align-items: center; justify-content: flex-end; gap: 12px; padding: 8px 12px; background: var(--toolbar-bg); border-bottom: 1px solid var(--border); margin: -20px -20px 20px; box-shadow: 0 2px 8px var(--shadow); }}
  .toolbar::before {{ content: ''; position: absolute; top: -20px; left: 0; right: 0; height: 20px; background: var(--bg); }}
  .font-ctrl {{ display: flex; align-items: center; gap: 2px; }}
  .font-btn {{ width: 22px; height: 22px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg2); color: var(--fg); font-weight: 700; font-size: 13px; cursor: pointer; display: flex; align-items: center; justify-content: center; line-height: 1; transition: background 0.15s; }}
  .font-btn:hover {{ background: var(--heading); color: var(--th-fg); }}
  .export-btn {{ padding: 3px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg2); color: var(--fg); font-size: 0.72em; font-weight: 600; cursor: pointer; transition: background 0.15s; }}
  .export-btn:hover {{ background: var(--heading); color: var(--th-fg); }}
  @media print {{ body {{ margin: 0; font-size: var(--base-font, 18px) !important; }} .no-print {{ display: none; }} .section-bar {{ display: none; }} .section-body {{ max-height: none !important; opacity: 1 !important; overflow: visible !important; }} .section {{ display: block; }} }}
</style>
</head><body>

<div class="toolbar no-print">
  <span style="font-weight:700;font-size:0.85em;margin-right:auto;color:var(--heading)">V1 Container Security Report</span>
  <div class="font-ctrl">
    <button class="font-btn" onclick="changeFontSize(-2)" title="Decrease font">&#x2212;</button>
    <span style="font-size:0.75em;font-weight:600;color:var(--meta)">Aa</span>
    <button class="font-btn" onclick="changeFontSize(2)" title="Increase font">+</button>
  </div>
  <button class="export-btn" onclick="exportCSV()" title="Export CVE table as CSV">CSV</button>
  <button class="export-btn" onclick="window.print()" title="Print / Save as PDF">PDF</button>
  <div class="theme-toggle">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
    <label><input type="checkbox" id="themeSwitch"><span class="track"></span><span class="thumb"></span></label>
    <svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
  </div>
</div>
<script>
  const sw=document.getElementById('themeSwitch');
  const saved=localStorage.getItem('theme');
  if(saved==='dark'||(!saved&&matchMedia('(prefers-color-scheme:dark)').matches)){{sw.checked=true;document.documentElement.classList.add('dark');}}
  sw.onchange=()=>{{document.documentElement.classList.toggle('dark',sw.checked);localStorage.setItem('theme',sw.checked?'dark':'light');}};
  let _fs=parseInt(localStorage.getItem('fontSize'))||18;
  document.documentElement.style.setProperty('--base-font',_fs+'px');
  function changeFontSize(d){{_fs=Math.max(12,Math.min(28,_fs+d));document.documentElement.style.setProperty('--base-font',_fs+'px');localStorage.setItem('fontSize',_fs);}}
</script>

<h1>V1 Container Security Report</h1>
<p><strong>Generated:</strong> {now.strftime('%Y-%m-%d %H:%M')} | <strong>Source:</strong> Vision One API + Claude Analysis</p>

<h2 style="scroll-margin-top:50px">Environment Context</h2>
<div class="section" data-section="env-ctx">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<div class="status-box">
  <p>Analysis assumptions based on <code>customer-context.md</code>. <strong>Review and correct if inaccurate.</strong></p>
  <pre class="raw-json" id="env-display" style="max-height:300px">{html_mod.escape(customer_context)}</pre>
  <textarea id="env-editor" style="display:none;width:100%;min-height:300px;font-family:'Cascadia Code','Fira Code',monospace;font-size:0.85em;background:var(--code-bg);color:var(--fg);border:2px solid var(--heading);border-radius:6px;padding:10px;resize:vertical">{html_mod.escape(customer_context)}</textarea>
  <div style="margin-top:8px;display:flex;gap:8px;align-items:center">
    <button class="export-btn" id="env-edit-btn" onclick="startEditEnv()">Edit</button>
    <button class="export-btn" id="env-save-btn" style="display:none;background:var(--heading);color:var(--th-fg)" onclick="saveEnv()">Save to disk</button>
    <button class="export-btn" id="env-cancel-btn" style="display:none" onclick="cancelEditEnv()">Cancel</button>
    <span class="meta" style="border:none;margin:0" id="env-status"></span>
    <span class="meta" style="border:none;margin:0;margin-left:auto" id="env-path-hint"></span>
  </div>
</div>
  </div>
</div>

{critical_section}

{diff_section}

<h2>1. Cluster Overview</h2>
<div class="section" data-section="cluster">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
{cluster_html}
  </div>
</div>

<h2>2. Affected Images &amp; K8s Location</h2>
<div class="section" data-section="images">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p>Vulnerable images grouped by cluster, then by K8s location. {len(sorted_clusters)} cluster{'s' if len(sorted_clusters) != 1 else ''}, {len(groups)} image group{'s' if len(groups) != 1 else ''}.</p>
{groups_html}
  </div>
</div>

<h2>3. Vulnerability Detail with Analysis</h2>
<div class="section" data-section="vulns">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p><strong>Total:</strong> {total} | <strong>Relevant:</strong> {relevant_count} | <strong>Need action:</strong> {need_action_count}{"" if not unanalyzed_count else f' | <span style="color:#856404"><strong>Unanalyzed:</strong> {unanalyzed_count}</span>'}</p>
<p>CVSS scores: <strong>Critical:</strong> {sev_totals.get('critical',0)} | <strong>High:</strong> {sev_totals.get('high',0)} | <strong>Medium:</strong> {sev_totals.get('medium',0)} | <strong>Low:</strong> {sev_totals.get('low',0)}</p>
<p><em>Each CVE has an analysis row below it. <span style="color:#e94560">Red border</span> = needs action.</em></p>
<table>
  <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Version</th><th>Namespace</th><th>Deployment</th><th>Container</th><th>Image</th><th style="text-align:center"><a href="{v1_container_vulns}" target="_blank" style="text-decoration:none;color:#fff;background:#0066cc;padding:3px 10px;border-radius:4px;font-size:0.85em;font-weight:700;white-space:nowrap">Open in V1</a></th></tr>
{rows_html}
</table>
  </div>
</div>

<h2>4. Runtime &amp; Policy Events</h2>
<div class="section" data-section="events">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p><strong>Total:</strong> {len(eval_events or []) + len(sensor_events or [])} events | <strong>Need action:</strong> {sum(1 for ci in critical_items if ci['type']=='Runtime')}</p>
<p><em><span style="color:#e94560">Red border</span> = needs action.</em></p>
{build_events_html(eval_events or [], sensor_events or [], xdr_results, v1_container_inventory, API_BASES.get(region, API_BASES['us-east-1']))}
  </div>
</div>

<h2>5. V1 API Reference</h2>
<div class="section" data-section="api-ref">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p>Raw API calls used to generate this report. Replace <code>YOUR_API_KEY</code> with your V1 API key from <strong>Administration &gt; API Keys</strong>.</p>
<table>
  <tr><th>Data</th><th>API Call</th></tr>
  <tr><td>Clusters</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "{API_BASES.get(region, API_BASES['us-east-1'])}/v3.0/containerSecurity/kubernetesClusters"</code></td></tr>
  <tr><td>Vulnerabilities</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "{API_BASES.get(region, API_BASES['us-east-1'])}/v3.0/containerSecurity/vulnerabilities?limit=200"</code></td></tr>
  <tr><td>Image Occurrences</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "{API_BASES.get(region, API_BASES['us-east-1'])}/v3.0/containerSecurity/kubernetesImageOccurrences"</code></td></tr>
  <tr><td>Eval Events</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "{API_BASES.get(region, API_BASES['us-east-1'])}/v3.0/containerSecurity/kubernetesEvaluationEventLogs"</code></td></tr>
  <tr><td>Sensor Events</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "{API_BASES.get(region, API_BASES['us-east-1'])}/v3.0/containerSecurity/kubernetesSensorEventLogs"</code></td></tr>
  <tr><td>Container Activity (XDR)</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" -H 'TMV1-Query: clusterName:YOUR_CLUSTER' "{API_BASES.get(region, API_BASES['us-east-1'])}/v3.0/search/containerActivities?top=50"</code></td></tr>
</table>
<p>See <a href="https://automation.trendmicro.com/xdr/api-v3" target="_blank">V1 API Documentation</a> for full reference.</p>
  </div>
</div>

<div class="meta">
  <p>Generated by v1-helper | Vision One API + Claude Analysis | {now.strftime('%Y-%m-%d %H:%M')}</p>
</div>

<script>
function toggleSection(bar) {{
  const sec = bar.parentElement;
  if (sec.classList.contains('collapsed')) {{
    sec.classList.remove('collapsed');
  }} else {{
    sec.classList.add('collapsed');
    let el = sec.nextElementSibling;
    while (el && el.tagName !== 'H2') el = el.nextElementSibling;
    if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
  }}
}}
// Flash yellow border when jumping to target from critical findings
function flashTarget(){{
  const id=location.hash.slice(1);if(!id)return;
  const el=document.getElementById(id);if(!el)return;
  document.querySelectorAll('.flash-target').forEach(e=>e.classList.remove('flash-target'));
  el.classList.add('flash-target');
  setTimeout(()=>el.classList.remove('flash-target'),2200);
}}
window.addEventListener('hashchange',flashTarget);
if(location.hash)setTimeout(flashTarget,400);
// Environment context inline editor
// Show expected save path based on where the HTML was opened from
(function(){{
  const hint=document.getElementById('env-path-hint');
  if(location.protocol==='file:'){{
    const dir=decodeURIComponent(location.pathname).replace(/\\\\/g,'/').split('/').slice(0,-1).join('/');
    hint.textContent='Save to: '+dir+'/customer-context.md';
  }}
}})();
function startEditEnv(){{
  document.getElementById('env-display').style.display='none';
  document.getElementById('env-editor').style.display='block';
  document.getElementById('env-edit-btn').style.display='none';
  document.getElementById('env-save-btn').style.display='inline-block';
  document.getElementById('env-cancel-btn').style.display='inline-block';
  document.getElementById('env-status').textContent='';
}}
function cancelEditEnv(){{
  document.getElementById('env-display').style.display='block';
  document.getElementById('env-editor').style.display='none';
  document.getElementById('env-edit-btn').style.display='inline-block';
  document.getElementById('env-save-btn').style.display='none';
  document.getElementById('env-cancel-btn').style.display='none';
  document.getElementById('env-editor').value=document.getElementById('env-display').textContent;
  document.getElementById('env-status').textContent='';
}}
async function saveEnv(){{
  const content=document.getElementById('env-editor').value;
  const status=document.getElementById('env-status');
  try{{
    if(window.showSaveFilePicker){{
      const handle=await window.showSaveFilePicker({{suggestedName:'customer-context.md',types:[{{description:'Markdown',accept:{{'text/markdown':['.md']}}}}]}});
      const w=await handle.createWritable();await w.write(content);await w.close();
      status.textContent='Saved!';status.style.color='#155724';
      setTimeout(()=>{{status.textContent='Re-run report generator to update analysis.';}},1500);
    }}else{{
      const blob=new Blob([content],{{type:'text/markdown'}});
      const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='customer-context.md';a.click();
      status.textContent='Downloaded. Move to reports/customer-context.md and re-run.';status.style.color='var(--meta)';
    }}
    document.getElementById('env-display').textContent=content;
    cancelEditEnv();
  }}catch(e){{
    if(e.name!=='AbortError'){{status.textContent='Error: '+e.message;status.style.color='#721c24';}}
  }}
}}
// CSV export
function exportCSV(){{
  const NL='\\n';
  const table=document.querySelector('[data-section="vulns"] table');
  if(!table)return;
  let csv='';
  table.querySelectorAll('tr:not(.analysis-row)').forEach(r=>{{
    const cells=[];
    r.querySelectorAll('th,td').forEach(c=>cells.push('"'+c.textContent.trim().replace(/"/g,'""')+'"'));
    if(cells.length)csv+=cells.join(',')+NL;
  }});
  const rows=csv.split(NL);
  let out=rows[0]+',Analysis,Relevant,Owner'+NL;
  let ri=1;
  table.querySelectorAll('tr:not(.analysis-row)').forEach((r,i)=>{{
    if(i===0)return;
    const next=r.nextElementSibling;
    let analysis='',relevant='',owner='';
    if(next&&next.classList.contains('analysis-row')){{
      const d=next.querySelector('.analysis-detail');
      if(d){{analysis=d.querySelector('strong')?.textContent||'';relevant=d.querySelector('.tag')?.textContent||'';owner=d.querySelector('.owner-tag')?.textContent||'';}}
    }}
    out+=(rows[ri]||'')+','+[analysis,relevant,owner].map(s=>'"'+s.replace(/"/g,'""')+'"').join(',')+NL;
    ri++;
  }});
  const blob=new Blob([out],{{type:'text/csv'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='container-security-report.csv';a.click();
}}
// PDF export via html2canvas approach - works cross-platform without print dialog
function exportPDF(){{
  window.print();
}}
</script>

</body></html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path


# ============================================================
# Main
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default=None, help="Override V1 region (default: from customer config)")
    parser.add_argument("--skip-llm", action="store_true", help="Skip Claude analysis")
    parser.add_argument("--batch-size", type=int, default=15)
    parser.add_argument("--output", help="Output HTML path")
    parser.add_argument("--customer", default="demo", help="Customer name (loads customers/<name>.json + .md)")
    parser.add_argument("--cached", help="Use cached V1 data JSON instead of live API")
    parser.add_argument("--prev", help="Previous raw-data JSON to compare against (for diff section)")
    parser.add_argument("--analysis", help="Pre-computed analysis JSON file")
    args = parser.parse_args()

    # Load customer config (API key, region)
    cust_config = load_customer_config(args.customer)
    region = args.region or cust_config.get("region", "us-east-1")
    api_key_name = cust_config.get("api_key_name", "v1-api/V1_API_KEY")
    print(f"Customer: {args.customer} | Region: {region} | API key: {api_key_name}")

    eval_events = []
    sensor_events = []
    prev_data = None

    if args.cached and os.path.exists(args.cached):
        print(f"Loading cached V1 data from {args.cached}...")
        cached = json.load(open(args.cached))
        clusters = cached["clusters"]
        vulns = cached["vulns"]
        occurrences = cached["occurrences"]
        eval_events = cached.get("eval_events", [])
        sensor_events = cached.get("sensor_events", [])
    else:
        print("Pulling V1 data...")
        # Load previous data for diff comparison before overwriting
        cache_path = REPORTS_DIR / f"{args.customer}-raw-data.json"
        prev_data = None
        if cache_path.exists():
            try:
                prev_data = json.load(open(str(cache_path)))
                print(f"  Loaded previous data for diff comparison")
            except Exception:
                pass
        api = V1(region, api_key_name)
        # Kubernetes
        clusters = api.clusters()
        vulns = api.vulns()
        occurrences = api.image_occ()
        eval_events = api.eval_events()
        sensor_events = api.sensor_events()
        # Amazon ECS
        ecs_clusters = api.ecs_clusters()
        ecs_occurrences = api.ecs_image_occ()
        ecs_sensor = api.ecs_sensor_events()
        # Merge ECS into main lists (tag ECS clusters with orchestrator)
        for c in ecs_clusters:
            c.setdefault("orchestrator", "Amazon ECS")
        clusters.extend(ecs_clusters)
        occurrences.extend(ecs_occurrences)
        sensor_events.extend(ecs_sensor)
        # Cache per customer
        json.dump({"clusters": clusters, "vulns": vulns, "occurrences": occurrences,
                   "eval_events": eval_events, "sensor_events": sensor_events},
                  open(str(cache_path), "w"))
        print(f"  Cached to {cache_path}")
    print(f"  {len(clusters)} clusters, {len(vulns)} vulns, {len(occurrences)} image occurrences")

    print("Enriching with K8s context...")
    findings = enrich(vulns, clusters, occurrences)
    print(f"  {len(findings)} findings enriched")

    # Compute diff against previous run
    diff_data = None
    prev_data_ref = prev_data if 'prev_data' in dir() else None
    if args.prev:
        try:
            prev_data_ref = json.load(open(args.prev))
        except Exception as e:
            print(f"  Warning: Could not load --prev file: {e}")
    if prev_data_ref:
        old_findings = enrich(prev_data_ref["vulns"], prev_data_ref["clusters"], prev_data_ref["occurrences"])
        diff_data = compute_diff(old_findings, findings)
        print(f"  Diff: {len(diff_data['added'])} new, {len(diff_data['resolved'])} resolved, {len(diff_data['changed'])} changed")

    analyses = None
    # Per-customer analysis cache, with fallback to shared analysis.json
    if args.analysis:
        analysis_file = args.analysis
    else:
        per_customer = REPORTS_DIR / f"{args.customer}-analysis.json"
        shared = REPORTS_DIR / "analysis.json"
        if per_customer.exists():
            analysis_file = str(per_customer)
        elif shared.exists():
            # Migrate: copy shared to per-customer on first use
            print(f"  Migrating shared analysis.json to {per_customer.name}...")
            import shutil
            shutil.copy2(str(shared), str(per_customer))
            analysis_file = str(per_customer)
        else:
            analysis_file = str(per_customer)
    if os.path.exists(analysis_file):
        print(f"Loading analysis from {analysis_file}...")
        raw = json.load(open(analysis_file))
        # Convert list format to dict keyed by CVE
        if isinstance(raw, list):
            analyses = {}
            for a in raw:
                cve_id = a.get("cve", "")
                if cve_id:
                    analyses[cve_id] = a
            print(f"  {len(analyses)} analyses loaded (converted from list)")
        else:
            analyses = raw
            print(f"  {len(analyses)} analyses loaded")
    # Detect and auto-analyze unanalyzed CVEs
    if analyses:
        finding_cves = set(f["cve"] for f in findings)
        analyzed_cves = set(analyses.keys())
        new_cves = sorted(finding_cves - analyzed_cves)
        if new_cves:
            print(f"\n  {len(new_cves)} new CVEs not in analysis.json:")
            for cve in new_cves[:20]:
                sev = next((f.get("severity", "?") for f in findings if f["cve"] == cve), "?")
                print(f"    {cve} ({sev})")
            if len(new_cves) > 20:
                print(f"    ... and {len(new_cves) - 20} more")

            if args.skip_llm:
                print("  Skipping analysis (--skip-llm). These will show as UNANALYZED in the report.\n")
            else:
                print(f"  Auto-analyzing {len(new_cves)} new CVEs...")
                new_findings = [f for f in findings if f["cve"] in set(new_cves)]
                customer_ctx = load_customer_context(args.customer, clusters, vulns, occurrences)
                new_analyses = run_analysis(new_findings, customer_ctx, args.batch_size)
                if new_analyses:
                    analyses.update(new_analyses)
                    json.dump(analyses, open(analysis_file, "w"), indent=2)
                    print(f"  Merged {len(new_analyses)} new analyses into {analysis_file} (total: {len(analyses)})")

    elif not args.skip_llm:
        print("Running Claude analysis...")
        customer_ctx = load_customer_context(args.customer, clusters, vulns, occurrences)
        analyses = run_analysis(findings, customer_ctx, args.batch_size)
        if analyses:
            json.dump(analyses, open(analysis_file, "w"), indent=2)
            print(f"  Saved {len(analyses)} analyses to {analysis_file}")

    # Run XDR queries for each unique violation type + cluster + namespace
    xdr_results = {}
    if not args.cached:
        print("Running XDR queries for runtime events...")
        api_for_xdr = V1(region, api_key_name)
        seen_queries = set()
        for e in eval_events:
            cluster = e.get("clusterName", "")
            namespace = e.get("namespace", "")
            for v in e.get("violationReasons", []):
                vtype = v.get("type", "")
                key = f"{vtype}:{cluster}:{namespace}"
                if key in seen_queries:
                    continue
                seen_queries.add(key)
                ctx = VIOLATION_CONTEXT.get(vtype, {})
                if isinstance(ctx, dict) and ctx.get("xdr_query"):
                    xdr_api_q = f"clusterName:{cluster} and k8sNamespace:{namespace}"
                    print(f"  XDR search: {key}")
                    hits = api_for_xdr.xdr_container_search(xdr_api_q, top=20)
                    if hits:
                        xdr_results[key] = hits
                        print(f"    {len(hits)} events found")
                    else:
                        print(f"    No events (data may not be indexed yet)")
    else:
        print("Skipping XDR queries (using cached data)")

    date = datetime.datetime.now().strftime('%Y-%m-%d')
    out = args.output or str(REPORTS_DIR / f"{args.customer}_Container_Security_{date}.html")
    customer_ctx = load_customer_context(args.customer, clusters, vulns, occurrences)
    if analyses:
        print("Generating relevance reasoning from customer context...")
        generate_relevance(analyses, customer_ctx)
    write_html(findings, analyses, clusters, out, eval_events, sensor_events, xdr_results, customer_ctx, region, diff_data)
    print(f"\nReport: {out}")

    # Auto-open
    if sys.platform == "win32":
        os.startfile(out)


if __name__ == "__main__":
    main()
