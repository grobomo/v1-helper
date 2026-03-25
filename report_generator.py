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

PROJECT_ROOT = Path(__file__).resolve().parent
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
                # K8s context from image occurrences (the missing data EP wants)
                "namespace": ", ".join(sorted({o["namespace"] for o in occs if o.get("namespace")})) or "(not deployed)",
                "resourceType": ", ".join(sorted({o["resourceType"] for o in occs if o.get("resourceType")})) or "-",
                "resourceName": ", ".join(sorted({o["resourceName"] for o in occs if o.get("resourceName")})) or "-",
                "containerName": ", ".join(sorted({o["containerName"] for o in occs if o.get("containerName")})) or "-",
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
Description: {f['description'][:300]}
Running on: cluster={f['clusterName']}, namespace={f['namespace']}, resourceType={f['resourceType']}, resourceName={f['resourceName']}, container={f['containerName']}
Image: {f['repository']}
"""

    prompt = f"""You are a container security analyst. Review each vulnerability finding below and determine:
1. Is this relevant in this customer's environment? (yes/no/maybe)
2. What should the customer do? (one sentence action)
3. Brief reasoning (2-3 sentences explaining your logic)

CUSTOMER CONTEXT:
{customer_context}

IMPORTANT RULES:
- Kernel CVEs (Linux kernel flaws) on container images are NOT relevant — containers share the host kernel
- If a fix version exists for an app dependency (npm, pip, maven, etc), the action is to update
- If a CVE affects an OS base image package with no fix, it's low priority unless critical severity
- Secrets flagged in npm internal files (corepack, arborist, sigstore) are false positives
- Be specific about WHO should act: "dev team", "SRE/infra team", "security team", or "no action needed"
- If the vulnerability is disputed or theoretical, say so

FINDINGS:
{findings_text}

Respond with a JSON array. Each element must have:
- "index": finding number (1-based)
- "relevant": "yes" | "no" | "low"
- "action": one-sentence action item
- "reasoning": 2-3 sentence explanation
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
            "max_tokens": 4096,
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
    """Run Claude analysis on all findings in batches."""
    raw = cred_resolve("NEURAL_PIPELINE/CLAUDE_TOKEN") or os.environ.get("ANTHROPIC_API_KEY") or ""
    anthropic_key = raw.replace("\n", "").replace("\r", "").strip()
    if not anthropic_key:
        print("  WARNING: No Anthropic API key found (NEURAL_PIPELINE/API_KEY), skipping LLM analysis")
        return None

    all_results = []
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i+batch_size]
        print(f"  Analyzing findings {i+1}-{i+len(batch)} of {len(findings)}...")
        try:
            results = analyze_batch(batch, customer_context, anthropic_key)
            all_results.extend(results)
        except Exception as e:
            print(f"  ERROR on batch: {e}")
            # Fill with defaults for failed batch
            for j in range(len(batch)):
                all_results.append({
                    "index": j+1, "relevant": "maybe",
                    "action": "Analysis failed — review manually",
                    "reasoning": f"LLM analysis error: {str(e)[:80]}",
                    "owner": "security"
                })
    return all_results


# ============================================================
# HTML Output
# ============================================================

VIOLATION_CONTEXT = {
    "podexec": "Someone ran a command inside a running pod (kubectl exec or equivalent). In production this may indicate debugging activity or unauthorized access. Check who ran the command and whether it was authorized.",
    "unscannedImage": "A container image was deployed without being scanned for vulnerabilities first. This bypasses the security scanning pipeline. Ensure all images go through TMAS scanning in CI/CD before deployment.",
    "unscannedImageRegistry": "Image pulled from a registry that hasn't been scanned. Configure admission control to block unscanned images.",
    "privilegedContainer": "Container running in privileged mode, which gives it full host access. This is a security risk — review if privileged mode is actually needed.",
    "hostNetwork": "Container using host network namespace. This bypasses network isolation. Review if host networking is required.",
    "hostPID": "Container sharing host PID namespace. Can see and interact with host processes. Review if needed.",
    "readOnlyRootFilesystem": "Container does not have a read-only root filesystem. Writable root increases attack surface.",
}


def build_events_html(eval_events, sensor_events):
    """Build HTML section for non-CVE runtime detections with analysis."""
    if not eval_events and not sensor_events:
        return ""

    rows = ""
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

        # Add analysis context for each violation type
        analysis_parts = []
        for vtype in violations:
            ctx = VIOLATION_CONTEXT.get(vtype, f"Policy violation: {vtype}")
            analysis_parts.append(ctx)

        decision_color = "#44ff44" if e.get("decision") == "allow" else "#ff4444"
        rows += f"""<tr>
<td>{e.get("createdDateTime","")[:19]}</td>
<td>{e.get("clusterName","?")}</td>
<td>{e.get("namespace","?")}</td>
<td>{e.get("kind","?")}</td>
<td>{", ".join(violations)}</td>
<td style="color:{decision_color};font-weight:700">{e.get("decision","?")}</td>
<td>{e.get("action","?")}</td>
<td>{"; ".join(resources) or "-"}</td>
<td>{e.get("policyName","?")}</td>
<td class="analysis-cell">{" ".join(analysis_parts)}</td>
</tr>"""

    for e in sensor_events:
        rows += f"""<tr>
<td>{e.get("createdDateTime","")[:19]}</td>
<td>{e.get("clusterName","?")}</td>
<td>{e.get("namespace","?")}</td>
<td>Sensor</td>
<td>{e.get("ruleName","?")}</td>
<td style="color:#f59e0b;font-weight:700">{e.get("mitigation","?")}</td>
<td>-</td>
<td>{e.get("k8s",{}).get("pod",{}).get("name","?")}</td>
<td>-</td>
</tr>"""

    return f"""
<h2 style="margin-top:24px;">Runtime & Policy Events</h2>
<table>
<tr><th>Time</th><th>Cluster</th><th>Namespace</th><th>Kind</th><th>Violation</th><th>Decision</th><th>Action</th><th>Details</th><th>Policy</th><th>Analysis</th></tr>
{rows}
</table>
"""


def write_html(findings, analyses, clusters, output_path, eval_events=None, sensor_events=None):
    now = datetime.datetime.now()
    sev_colors = {"critical": "#ff4444", "high": "#ff6666", "medium": "yellow", "low": "#44ff44"}

    # Merge analysis into findings
    if analyses:
        for i, f in enumerate(findings):
            if i < len(analyses):
                a = analyses[i]
                f["_action"] = a.get("action", "")
                f["_steps"] = a.get("steps", a.get("where_to_look", ""))

    # Build rows
    rows_html = ""
    for f in findings:
        sc = sev_colors.get(f["severity"], "white")
        action = f.get("_action", "")
        where = f.get("_where", "")
        fix = f["fixedVersion"]

        # V1 console link — goes to vulnerability overview page (containers tab)
        v1_cve_url = "https://portal.xdr.trendmicro.com/index.html#/app/sase"

        # Where it's running
        running = f"Cluster: <b>{f['clusterName']}</b>"
        if f['namespace'] != '-':
            running += f"<br>Namespace: <b>{f['namespace']}</b>"
        if f['resourceName'] != '-':
            running += f"<br>{f['resourceType']}: <b>{f['resourceName']}</b>"
        if f['containerName'] != '-':
            running += f"<br>Container: <b>{f['containerName']}</b>"
        running += f"<br>Image: {f.get('image') or f.get('image_repo') or f.get('repository','')}"

        # Analysis section
        analysis_html = ""
        if action:
            analysis_html += f"<div class='analysis-block'><b>{action}</b></div>"
        steps = f.get("_steps", "")
        if steps:
            steps_formatted = steps.replace("\\n", "<br>")
            analysis_html += f"<div class='steps'>{steps_formatted}</div>"

        # Single action link — goes to V1 vulnerability page
        buttons_html = f'<a class="btn btn-v1" href="{v1_cve_url}" target="_blank">Open in V1</a>'

        rows_html += f"""<tr>
<td style="color:{sc};font-weight:700">{f["severity"].title()}</td>
<td><a href="{f['cveLink']}" target="_blank">{f["cve"]}</a></td>
<td class="pkg-cell"><span class="pkg">{f["package"]}</span><br><span class="ver">{f["packageVersion"]}</span></td>
<td class="context-cell"><div class="where-running">{running}</div></td>
<td class="analysis-cell">{analysis_html}</td>
<td class="btn-cell">{buttons_html}</td>
</tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Container Security Analysis — {now.strftime('%Y-%m-%d')}</title>
<style>
* {{ box-sizing: border-box; color: white; }}
body {{ font-family: -apple-system, system-ui, sans-serif; background: black; color: white; margin: 0; padding: 16px; font-size: 14px; }}
h1 {{ font-size: 20px; margin: 0 0 4px; }}
h2 {{ font-size: 17px; margin: 24px 0 8px; }}
.sub {{ font-size: 13px; margin-bottom: 12px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th {{ background: #222; text-align: left; padding: 8px 10px; position: sticky; top: 0; z-index: 10; font-size: 12px; text-transform: uppercase; border-bottom: 2px solid #555; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #333; vertical-align: top; }}
tr:hover {{ background: #1a1a1a; }}
.context-cell {{ font-size: 12px; line-height: 1.6; white-space: nowrap; }}
.analysis-cell {{ font-size: 13px; line-height: 1.6; width: 100%; }}
.analysis-block {{ margin-bottom: 6px; }}
.where-running {{ font-size: 12px; }}
details summary {{ cursor: pointer; font-weight: 700; font-size: 13px; }}
a {{ color: cyan; text-decoration: underline; }}
code {{ background: #222; padding: 1px 5px; border-radius: 3px; font-size: 12px; }}
.pkg {{ font-size: 14px; font-weight: 700; color: white; }}
.pkg-cell {{ max-width: 120px; word-wrap: break-word; }}
.ver {{ font-size: 14px; color: white; font-family: monospace; }}
.btn-cell {{ vertical-align: middle; text-align: center; white-space: nowrap; }}
.btn {{ display: inline-block; padding: 5px 14px; border-radius: 4px; font-size: 12px; font-weight: 700; text-decoration: none; cursor: pointer; margin-top: 8px; }}
.btn-v1 {{ background: #0066cc; color: white; }}
.btn-v1:hover {{ background: #0088ff; }}
.v1-hint {{ font-size: 10px; color: #888; }}
</style>
</head><body>
<h1>Container Security — Vulnerability Analysis</h1>
<div class="sub">{now.strftime('%Y-%m-%d %H:%M')} | {len(findings)} findings | {len(clusters)} clusters | V1 API data enriched with exploitability context</div>

<table>
<tr><th>Sev</th><th>CVE</th><th>Affected Package</th><th>Location</th><th>Analysis</th><th></th></tr>
{rows_html}
</table>
{build_events_html(eval_events or [], sensor_events or [])}
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
        analyses = json.load(open(analysis_file))
        print(f"  {len(analyses)} analyses loaded")
    elif not args.skip_llm:
        print("Running Claude analysis...")
        customer_ctx = load_customer_context()
        analyses = run_analysis(findings, customer_ctx, args.batch_size)

    date = datetime.datetime.now().strftime('%Y-%m-%d')
    out = args.output or str(REPORTS_DIR / f"EP_Container_Security_{date}.html")
    write_html(findings, analyses, clusters, out, eval_events, sensor_events)
    print(f"\nReport: {out}")

    # Auto-open
    if sys.platform == "win32":
        os.startfile(out)


if __name__ == "__main__":
    main()
