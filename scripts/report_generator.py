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

class V1:
    def __init__(self, region="us-east-1"):
        self.key = cred_resolve("v1-api/V1_API_KEY")
        if not self.key:
            raise RuntimeError("No v1-api/V1_API_KEY in credential store")
        bases = {
            "us-east-1": "https://api.xdr.trendmicro.com",
            "eu-central-1": "https://api.eu.xdr.trendmicro.com",
            "ap-southeast-1": "https://api.sg.xdr.trendmicro.com",
            "ap-northeast-1": "https://api.jp.xdr.trendmicro.com",
            "ap-southeast-2": "https://api.au.xdr.trendmicro.com",
        }
        self.base = bases.get(region, bases["us-east-1"])
        self.h = {"Authorization": f"Bearer {self.key}"}

    def _pages(self, path, params=None, max_pages=20):
        items, url = [], f"{self.base}{path}"
        for _ in range(max_pages):
            r = requests.get(url, headers=self.h, params=params, timeout=30)
            r.raise_for_status()
            d = r.json()
            items.extend(d.get("items", []))
            nxt = d.get("nextLink")
            if not nxt: break
            url, params = nxt, None
        return items

    def clusters(self): return self._pages("/v3.0/containerSecurity/kubernetesClusters")
    def vulns(self): return self._pages("/v3.0/containerSecurity/vulnerabilities", {"limit": 200})
    def image_occ(self): return self._pages("/v3.0/containerSecurity/kubernetesImageOccurrences")
    def eval_events(self): return self._pages("/v3.0/containerSecurity/kubernetesEvaluationEventLogs")
    def sensor_events(self): return self._pages("/v3.0/containerSecurity/kubernetesSensorEventLogs")
    def audit_events(self): return self._pages("/v3.0/containerSecurity/kubernetesAuditEventLogs")

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


# ============================================================
# Claude analysis
# ============================================================

def load_customer_context():
    p = REPORTS_DIR / "customer-context.md"
    if p.exists():
        return p.read_text()
    return "No customer context file found. Analyze based on general container security best practices."


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

    prompt = f"""You are a container security analyst reviewing vulnerabilities found in container images.
For EACH finding, determine if it's relevant to this customer's environment and what action to take.

CUSTOMER CONTEXT:
{customer_context}

CRITICAL ANALYSIS RULES:
1. KERNEL vs USERSPACE distinction:
   - Kernel CVEs (Linux kernel privilege escalation, memory management, namespace escape) are NOT exploitable from inside a container — containers share the HOST kernel (EKS runs Amazon Linux, ECS runs Amazon Linux 2). The container's base image kernel packages are never loaded.
   - HOWEVER: userspace vulnerabilities in kernel-related packages (e.g. glibc ASLR info leak, libc string overflow) ARE relevant because the container links against its own libc.so/libpthread.so at runtime.
   - Key test: does the CVE affect code that runs in userspace (libc functions, regex engine, DNS resolver) or kernel space (syscalls, memory layout, namespace isolation)?

2. For EACH CVE you must:
   - State the SPECIFIC vulnerability (not just "check if you use this package")
   - Explain WHY it is or isn't relevant to THIS container (nginx on EKS/ECS)
   - If disputed/theoretical, cite that explicitly (e.g. "marked DISPUTED on NVD")
   - Reference the actual CVE being analyzed, not a different one

3. Package relevance for nginx container:
   - nginx uses: openssl/gnutls (TLS), zlib (compression), pcre (regex), libc (everything)
   - nginx does NOT typically use: libxml2, libxslt, sqlite, perl, apt, systemd, ldap, libheif, libtiff at runtime
   - But libraries linked transitively still matter if the vulnerable function is reachable

4. Be specific about exploitability:
   - "Requires local access" + container = only via kubectl exec or RCE
   - "Requires crafted input" = depends on what input the container processes
   - "DoS only" vs "code execution" = very different risk levels

FINDINGS:
{findings_text}

Respond with a JSON array. Each element MUST have:
- "cve": the exact CVE ID from the finding (e.g. "CVE-2019-1010022")
- "relevant": "yes" | "no" | "low"
- "action": one-sentence specific action item
- "reasoning": 2-4 sentences explaining the specific vulnerability and why it does/doesn't matter here
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
                "title": f"User creation detected: <code>{cmd}</code>",
                "analysis": f"A new user account <code>{user}</code> was created inside a running container. In production, containers should be immutable — user creation suggests either: (1) an attacker establishing persistence after initial access (MITRE T1136.001), (2) a misconfigured entrypoint script, or (3) debugging activity. On EKS/ECS, container user changes are ephemeral (lost on restart), but an attacker could use the new account to escalate privileges or evade detection during the current container lifetime.",
                "action": f"Verify who ran <code>kubectl exec</code> — check RBAC audit logs for exec permissions on namespace <code>{namespace}</code>. If unauthorized, investigate the source IP and user identity. Consider switching from LogOnlyPolicy to an enforcement policy that blocks podExec in production namespaces.",
            }
        elif "shadow" in cmd or "/etc/passwd" in cmd:
            return {
                "title": f"Sensitive file access: <code>{cmd}</code>",
                "analysis": f"Reading <code>/etc/shadow</code> is a credential harvesting technique (MITRE T1003.008). In containers, /etc/shadow contains hashed passwords for system accounts in the base image. While these are typically non-functional service accounts, an attacker may attempt to crack them or use the access pattern to test what other sensitive files are readable. This is a common post-exploitation reconnaissance step.",
                "action": f"Check if the container runs as root (it shouldn't). Implement read-only root filesystem (<code>readOnlyRootFilesystem: true</code>) in the pod security context. Monitor for follow-up activity: if shadow read is followed by network connections or data exfiltration, treat as active compromise.",
            }
        elif "apt" in cmd or "yum" in cmd or "apk" in cmd:
            return {
                "title": f"Package manager execution: <code>{cmd}</code>",
                "analysis": f"Running a package manager inside a container at runtime indicates either: (1) an attacker installing tools for lateral movement, exfiltration, or persistence (MITRE T1059.004), (2) a developer debugging, or (3) a poorly built image that installs packages at startup. In production containers on EKS/ECS, packages should be baked into the image at build time. Runtime package installation bypasses vulnerability scanning (TMAS) and introduces unvetted code.",
                "action": f"Block package manager execution via Container Security runtime rules (or OPA/Gatekeeper policies). Ensure images are built with all dependencies and package managers are removed or disabled in the final image layer. If this was debugging, use ephemeral debug containers (<code>kubectl debug</code>) instead.",
            }
        elif "curl" in cmd or "wget" in cmd:
            target = cmd.split()[-1] if cmd.split() else "unknown"
            return {
                "title": f"Outbound HTTP request: <code>{cmd}</code>",
                "analysis": f"An outbound HTTP connection to <code>{target}</code> was initiated from inside the container. This could be: (1) legitimate application behavior, (2) C2 callback to an attacker-controlled server (MITRE T1071.001), (3) data exfiltration, or (4) downloading additional tools. On EKS/ECS, outbound traffic should be restricted via Network Policies or security groups. The target <code>{target}</code> should be verified against expected application dependencies.",
                "action": f"Review whether <code>{target}</code> is an expected dependency. Implement Kubernetes NetworkPolicy to restrict egress to known-good destinations. If unexpected, capture full network context: DNS resolution, response size, timing pattern. Check for data in the request body.",
            }
        else:
            return {
                "title": f"Command executed in pod: <code>{cmd}</code>",
                "analysis": f"A command was executed inside a running container via kubectl exec or equivalent. Any interactive access to production containers should be audited. The command <code>{cmd}</code> should be reviewed in the context of normal operational procedures for this workload.",
                "action": f"Review RBAC audit logs to identify who executed this command. If this is routine debugging, consider implementing break-glass procedures with time-limited access and mandatory logging.",
            }
    elif vtype == "unscannedImage" and images:
        img = images[0]
        obj = objects[0] if objects else "?"
        return {
            "title": f"Unscanned image deployed: <code>{img}</code>",
            "analysis": f"Container image <code>{img}</code> was deployed to pod <code>{obj}</code> without passing through vulnerability scanning. This means the image bypassed the CI/CD security pipeline — it could contain known CVEs, malware, embedded secrets, or supply-chain compromises. On EKS/ECS, images should be scanned by TMAS (Trend Micro Artifact Scanner) in the CI/CD pipeline before deployment, and admission control should block unscanned images.",
            "action": f"Configure Container Security admission control to <b>block</b> unscanned images (currently set to log-only). Integrate TMAS scanning into your CI/CD pipeline: <code>tmas scan docker:{img}</code>. For existing deployments, trigger a manual scan from the V1 console. Consider using a private registry with mandatory scan policies.",
        }
    elif vtype == "unscannedImage":
        return {
            "title": "Unscanned image deployed",
            "analysis": "A container image was deployed without being scanned for vulnerabilities. This bypasses the security scanning pipeline and introduces unknown risk.",
            "action": "Enable admission control to block unscanned images. Integrate TMAS scanning into CI/CD.",
        }
    else:
        ctx = VIOLATION_CONTEXT.get(vtype, {})
        if isinstance(ctx, dict):
            return {"title": ctx.get("analysis", f"Policy violation: {vtype}"), "analysis": ctx.get("action", ""), "action": ""}
        return {"title": str(ctx), "analysis": "", "action": ""}


def build_events_html(eval_events, sensor_events, xdr_results=None):
    """Build HTML section for non-CVE runtime detections with analysis and XDR queries."""
    if not eval_events and not sensor_events:
        return ""
    xdr_results = xdr_results or {}

    rows = ""
    copy_id = 0
    for e in eval_events:
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

        decision_color = "#44ff44" if e.get("decision") == "allow" else "#ff4444"
        rows += f"""<tr>
<td>{e.get("createdDateTime","")[:19]}</td>
<td>{cluster}</td>
<td>{namespace}</td>
<td>{e.get("kind","?")}</td>
<td>{", ".join(violations)}</td>
<td style="color:{decision_color};font-weight:700">{e.get("decision","?")}</td>
<td>{e.get("action","?")}</td>
<td>{"; ".join(resources) or "-"}</td>
<td>{e.get("policyName","?")}</td>
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
            analysis_html += f"<strong>{specific['title']}</strong>"
            analysis_html += f"<div class='reasoning'>{specific['analysis']}</div>"
            if specific.get("action"):
                analysis_html += f"<div class='note' style='margin-top:6px'><strong>Recommended:</strong> {specific['action']}</div>"

            xdr_q = ctx.get("xdr_query", "").format(cluster=cluster, namespace=namespace)
            if xdr_q:
                copy_id += 1
                analysis_html += f"""<div class="xdr-query-box">
<span class="xdr-label">XDR Query:</span>
<code id="xdr-{copy_id}">{xdr_q}</code>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('xdr-{copy_id}').textContent);this.textContent='Copied';setTimeout(()=>this.textContent='&#x2398;',1200)" title="Copy to clipboard">&#x2398;</button>
</div>"""
                # Show XDR results if available
                xdr_key = f"{vtype}:{cluster}:{namespace}"
                hits = xdr_results.get(xdr_key, [])
                if hits:
                    analysis_html += f'<div class="xdr-results"><span class="xdr-label">XDR Results ({len(hits)} events):</span><table class="xdr-table">'
                    analysis_html += '<tr><th>Time</th><th>Container</th><th>Process</th><th>Command</th><th>Parent</th><th>User</th></tr>'
                    for h in hits[:10]:
                        analysis_html += f"""<tr>
<td>{h.get("eventTimeDT","")[:19]}</td>
<td>{h.get("containerName","?")}</td>
<td>{h.get("processName","?")}</td>
<td><code>{h.get("processCmd","?")[:80]}</code></td>
<td>{h.get("parentName","?")}</td>
<td>{h.get("objectUser","?")}</td>
</tr>"""
                    if len(hits) > 10:
                        analysis_html += f'<tr><td colspan="6" style="text-align:center;font-style:italic">...and {len(hits)-10} more events. Run the query in V1 to see all.</td></tr>'
                    analysis_html += '</table></div>'
                elif xdr_results:
                    analysis_html += '<div class="xdr-results"><span class="xdr-label">XDR Results: No container activity telemetry indexed yet. Eval events come through the admission controller pipeline, not the XDR data lake. Runtime sensor telemetry typically takes 15-60 minutes to appear in XDR search after the event.</span></div>'

        if analysis_html:
            rows += f"""<tr class="analysis-row">
<td colspan="9"><div class="analysis-detail">{analysis_html}</div></td>
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
<td colspan="9"><div class="analysis-detail">
<strong>Runtime sensor detection.</strong> Investigate the process and context that triggered this rule.
<div class="xdr-query-box">
<span class="xdr-label">XDR Query:</span>
<code id="xdr-{copy_id}">{sensor_query}</code>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('xdr-{copy_id}').textContent);this.textContent='Copied';setTimeout(()=>this.textContent='&#x2398;',1200)" title="Copy to clipboard">&#x2398;</button>
</div>
</div></td>
</tr>"""

    return f"""<table>
<tr><th>Time</th><th>Cluster</th><th>Namespace</th><th>Kind</th><th>Violation</th><th>Decision</th><th>Action</th><th>Details</th><th>Policy</th></tr>
{rows}
</table>"""


def write_html(findings, analyses, clusters, output_path, eval_events=None, sensor_events=None, xdr_results=None):
    now = datetime.datetime.now()
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
        key = (f["repository"], f["namespace"], f["resourceName"], f.get("labels", ""))
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

    # Build image group sections
    groups_html = ""
    for (repo, ns, res_name, labels), group_findings in groups.items():
        sev_counts = defaultdict(int)
        for f in group_findings:
            sev_counts[f["severity"]] += 1
        sev_summary = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items(), key=lambda x: ["critical","high","medium","low"].index(x[0]) if x[0] in ["critical","high","medium","low"] else 9))

        # K8s location info from first finding in group
        f0 = group_findings[0]
        res_type = f0.get("resourceType", "-")
        container = f0.get("containerName", "-")
        lbl = f0.get("labels", "")

        groups_html += f"""
<div class="status-box">
  <h3><span class="tag medium">{len(group_findings)} CVEs</span> {repo}</h3>
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

        rows_html += f"""<tr>
<td><a href="{f['cveLink']}" target="_blank">{cve}</a></td>
<td><span class="tag" style="background:{sc};color:{st}">{f["severity"].upper()}</span></td>
<td>{f.get('score','')}</td>
<td>{f["package"]}</td>
<td><code>{f["packageVersion"]}</code></td>
<td><code>{f["namespace"]}</code></td>
<td><code>{f["resourceName"]}</code></td>
<td>{f.get("containerName","-")}</td>
<td>{f["repository"]}</td>
</tr>"""

        # Full-width analysis row under CVE
        if analysis:
            relevant = analysis.get("relevant", "?")
            rel_colors = {"yes": "#f8d7da", "no": "#d4edda", "low": "#fff3cd", "maybe": "#fff3cd"}
            rel_text = {"yes": "#721c24", "no": "#155724", "low": "#856404", "maybe": "#856404"}
            rel_bg = rel_colors.get(relevant, "#eee")
            rel_fg = rel_text.get(relevant, "#333")
            action = analysis.get("action", "")
            reasoning = analysis.get("reasoning", "")
            owner = analysis.get("owner", "")

            rows_html += f"""<tr class="analysis-row">
<td colspan="9">
  <div class="analysis-detail">
    <span class="tag" style="background:{rel_bg};color:{rel_fg}">Relevant: {relevant.upper()}</span>
    <span class="owner-tag">{owner}</span>
    <strong>{action}</strong>
    <div class="reasoning">{reasoning}</div>
  </div>
</td>
</tr>"""

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
  * {{ transition: background-color 0.2s, color 0.2s, border-color 0.2s; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; background: var(--bg); color: var(--fg); font-size: var(--base-font, 18px); }}
  h1 {{ border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: var(--heading); margin-top: 30px; border-bottom: 1px solid var(--border); padding-bottom: 5px; scroll-margin-top: 50px; }}
  h3 {{ color: var(--heading2); margin-top: 20px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid var(--border); padding: 8px 12px; text-align: left; font-size: 0.9em; }}
  th {{ background: var(--th-bg); color: var(--th-fg); position: sticky; top: 0; z-index: 10; }}
  tr:nth-child(even):not(.analysis-row) {{ background: var(--even-row); }}
  code {{ background: var(--code-bg); padding: 2px 6px; border-radius: 3px; font-size: 0.85em; color: var(--fg); }}
  a {{ color: var(--link); }}
  .meta {{ color: var(--meta); font-size: 0.85em; margin-top: 30px; border-top: 1px solid var(--border); padding-top: 10px; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; margin: 0 2px; }}
  .tag.healthy {{ background: #d4edda; color: #155724; }}
  .tag.medium {{ background: #fff3cd; color: #856404; }}
  .status-box {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 12px 0; box-shadow: 0 1px 3px var(--shadow); }}
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
  .owner-tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; background: var(--owner-bg); color: var(--owner-fg); margin-left: 4px; }}
  .xdr-query-box {{ margin-top: 8px; padding: 6px 10px; background: var(--code-bg); border-radius: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .xdr-query-box code {{ background: none; padding: 0; font-size: 0.82em; flex: 1; word-break: break-all; color: var(--fg); }}
  .xdr-label {{ font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: var(--meta); white-space: nowrap; }}
  .copy-btn {{ background: var(--th-bg); color: var(--th-fg); border: none; border-radius: 4px; padding: 3px 8px; font-size: 0.8em; cursor: pointer; white-space: nowrap; transition: background 0.15s; }}
  .copy-btn:hover {{ opacity: 0.85; }}
  .xdr-results {{ margin-top: 8px; }}
  .xdr-results .xdr-label {{ display: block; margin-bottom: 4px; }}
  .xdr-table {{ font-size: 0.82em; margin: 4px 0; }}
  .xdr-table th {{ background: var(--code-bg); color: var(--fg); font-size: 0.85em; padding: 4px 8px; }}
  .xdr-table td {{ padding: 3px 8px; font-size: 0.85em; }}
  ul {{ margin: 6px 0; }}
  li {{ margin: 4px 0; }}
  /* Collapsible sections */
  .section {{ display: flex; align-items: stretch; margin: 0 0 4px; }}
  .section-bar {{ width: 18px; min-width: 18px; background: var(--border); border-radius: 4px 0 0 4px; cursor: pointer; display: flex; flex-direction: column; align-items: center; padding-top: 10px; gap: 6px; transition: background 0.15s, width 0.2s, min-width 0.2s; flex-shrink: 0; user-select: none; }}
  .section-bar:hover {{ background: var(--heading); }}
  .section-bar:hover .chev {{ stroke: var(--th-fg); }}
  .section-bar:hover .expand-label {{ color: var(--th-fg); }}
  .section-bar .chev {{ width: 10px; height: 10px; stroke: var(--meta); fill: none; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; transition: transform 0.2s, stroke 0.15s; transform: rotate(90deg); }}
  .section.collapsed .section-bar .chev {{ transform: rotate(0deg); }}
  .section-bar .expand-label {{ font-size: 0.65em; font-weight: 700; color: var(--meta); writing-mode: vertical-lr; text-orientation: mixed; letter-spacing: 1px; text-transform: uppercase; opacity: 0; transition: opacity 0.2s; pointer-events: none; }}
  .section.collapsed .section-bar {{ width: 28px; min-width: 28px; }}
  .section.collapsed .section-bar .expand-label {{ opacity: 1; }}
  .section-body {{ flex: 1; min-width: 0; overflow: hidden; transition: max-height 0.3s ease, opacity 0.2s ease; }}
  .section.collapsed .section-body {{ max-height: 0 !important; opacity: 0; padding: 0; }}
  .section:not(.collapsed) .section-body {{ opacity: 1; }}
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
  .toolbar {{ position: sticky; top: 0; z-index: 200; display: flex; align-items: center; justify-content: flex-end; gap: 12px; padding: 8px 12px; background: var(--toolbar-bg); border-bottom: 1px solid var(--border); margin: -20px -20px 20px; box-shadow: 0 1px 4px var(--shadow); }}
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
<p>Maps each vulnerable container image to its exact K8s location so SRE knows where to patch.</p>
{groups_html}
  </div>
</div>

<h2>3. Vulnerability Detail with Analysis</h2>
<div class="section" data-section="vulns">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p><strong>Total:</strong> {total} | <strong>Critical:</strong> {sev_totals.get('critical',0)} | <strong>High:</strong> {sev_totals.get('high',0)} | <strong>Medium:</strong> {sev_totals.get('medium',0)} | <strong>Low:</strong> {sev_totals.get('low',0)}</p>
<p><em>Each CVE has an analysis row below it explaining relevance to your EKS/ECS environment.</em></p>
<table>
  <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Version</th><th>Namespace</th><th>Deployment</th><th>Container</th><th>Image</th></tr>
{rows_html}
</table>
  </div>
</div>

<h2>4. Runtime &amp; Policy Events</h2>
<div class="section" data-section="events">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
{build_events_html(eval_events or [], sensor_events or [], xdr_results)}
  </div>
</div>

<h2>5. V1 API Reference</h2>
<div class="section" data-section="api-ref">
  <div class="section-bar" onclick="toggleSection(this)"><svg class="chev" viewBox="0 0 12 12"><polyline points="3,2 9,6 3,10"/></svg><span class="expand-label">Expand</span></div>
  <div class="section-body">
<p>Raw API calls used to generate this report. Replace <code>YOUR_API_KEY</code> with your V1 API key from <strong>Administration &gt; API Keys</strong>.</p>
<table>
  <tr><th>Data</th><th>API Call</th></tr>
  <tr><td>Clusters</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "https://api.xdr.trendmicro.com/v3.0/containerSecurity/kubernetesClusters"</code></td></tr>
  <tr><td>Vulnerabilities</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "https://api.xdr.trendmicro.com/v3.0/containerSecurity/vulnerabilities?limit=200"</code></td></tr>
  <tr><td>Image Occurrences</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "https://api.xdr.trendmicro.com/v3.0/containerSecurity/kubernetesImageOccurrences"</code></td></tr>
  <tr><td>Eval Events</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "https://api.xdr.trendmicro.com/v3.0/containerSecurity/kubernetesEvaluationEventLogs"</code></td></tr>
  <tr><td>Sensor Events</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" "https://api.xdr.trendmicro.com/v3.0/containerSecurity/kubernetesSensorEventLogs"</code></td></tr>
  <tr><td>Container Activity (XDR)</td><td><code>curl -H "Authorization: Bearer YOUR_API_KEY" -H 'TMV1-Query: clusterName:YOUR_CLUSTER' "https://api.xdr.trendmicro.com/v3.0/search/containerActivities?top=50"</code></td></tr>
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
  const body = sec.querySelector('.section-body');
  if (sec.classList.contains('collapsed')) {{
    body.style.maxHeight = body.scrollHeight + 'px';
    sec.classList.remove('collapsed');
    setTimeout(() => body.style.maxHeight = 'none', 300);
  }} else {{
    body.style.maxHeight = body.scrollHeight + 'px';
    body.offsetHeight;
    body.style.maxHeight = '0';
    sec.classList.add('collapsed');
    // Scroll to the next section's h2 heading after collapse animation
    setTimeout(() => {{
      // Walk siblings after this .section to find the next h2
      let el = sec.nextElementSibling;
      while (el && el.tagName !== 'H2') el = el.nextElementSibling;
      if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}, 310);
  }}
}}
// Init: set max-height to none for all expanded sections
document.querySelectorAll('.section-body').forEach(b => b.style.maxHeight = 'none');
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
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--skip-llm", action="store_true", help="Skip Claude analysis")
    parser.add_argument("--batch-size", type=int, default=15)
    parser.add_argument("--output", help="Output HTML path")
    parser.add_argument("--cached", help="Use cached V1 data JSON instead of live API")
    parser.add_argument("--analysis", help="Pre-computed analysis JSON file")
    args = parser.parse_args()

    eval_events = []
    sensor_events = []

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
        api = V1(args.region)
        clusters = api.clusters()
        vulns = api.vulns()
        occurrences = api.image_occ()
        eval_events = api.eval_events()
        sensor_events = api.sensor_events()
        # Cache for next time
        json.dump({"clusters": clusters, "vulns": vulns, "occurrences": occurrences,
                   "eval_events": eval_events, "sensor_events": sensor_events},
                  open(str(REPORTS_DIR / "v1-raw-data.json"), "w"))
    print(f"  {len(clusters)} clusters, {len(vulns)} vulns, {len(occurrences)} image occurrences")

    print("Enriching with K8s context...")
    findings = enrich(vulns, clusters, occurrences)
    print(f"  {len(findings)} findings enriched")

    analyses = None
    analysis_file = args.analysis or str(REPORTS_DIR / "analysis.json")
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
    elif not args.skip_llm:
        print("Running Claude analysis...")
        customer_ctx = load_customer_context()
        analyses = run_analysis(findings, customer_ctx, args.batch_size)
        if analyses:
            json.dump(analyses, open(analysis_file, "w"), indent=2)
            print(f"  Saved {len(analyses)} analyses to {analysis_file}")

    # Run XDR queries for each unique violation type + cluster + namespace
    xdr_results = {}
    if not args.cached:
        print("Running XDR queries for runtime events...")
        api_for_xdr = V1(args.region)
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
    out = args.output or str(REPORTS_DIR / f"EP_Container_Security_{date}.html")
    write_html(findings, analyses, clusters, out, eval_events, sensor_events, xdr_results)
    print(f"\nReport: {out}")

    # Auto-open
    if sys.platform == "win32":
        os.startfile(out)


if __name__ == "__main__":
    main()
