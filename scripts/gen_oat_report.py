#!/usr/bin/env python3
"""Generate OAT HTML report from cached V1 API data.
Usage: python scripts/gen_oat_report.py [path/to/oat_data.json]
Default: ~/oat_medium.json (output of v1-api executor list_oat)
"""
import json, os, html, sys
from collections import defaultdict
from datetime import datetime, timezone

CSS = ("body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;"
       "max-width:900px;margin:40px auto;padding:0 20px;background:#f8f9fa;color:#1a1a2e}"
       "h1{border-bottom:3px solid #e94560;padding-bottom:10px}"
       "h2{color:#0f3460;margin-top:30px}h3{color:#16213e}h4{color:#0f3460;margin-top:20px}"
       ".chat{margin:20px 0}.msg{padding:14px 18px;margin:10px 0;border-radius:10px;line-height:1.6}"
       ".user{background:#e3f2fd;border-left:4px solid #1976d2}"
       '.user::before{content:"User";font-weight:700;color:#1976d2;display:block;'
       "margin-bottom:4px;font-size:.85em;text-transform:uppercase}"
       ".assistant{background:#fff;border-left:4px solid #e94560;box-shadow:0 1px 3px rgba(0,0,0,.08)}"
       '.assistant::before{content:"Claude";font-weight:700;color:#e94560;display:block;'
       "margin-bottom:4px;font-size:.85em;text-transform:uppercase}"
       "table{border-collapse:collapse;width:100%;margin:12px 0}"
       "th,td{border:1px solid #ddd;padding:8px 12px;text-align:left}"
       "th{background:#0f3460;color:#fff}tr:nth-child(even){background:#f2f2f2}"
       "code{background:#e8e8e8;padding:2px 6px;border-radius:3px;font-size:.9em;word-break:break-all}"
       ".meta{color:#666;font-size:.85em;margin-top:30px;border-top:1px solid #ddd;padding-top:10px}"
       ".tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8em;font-weight:600;margin:0 2px}"
       ".tag.critical{background:#f8d7da;color:#721c24}"
       ".tag.high{background:#f5c6cb;color:#721c24}"
       ".tag.medium{background:#fff3cd;color:#856404}"
       ".tag.low{background:#d4edda;color:#155724}"
       "ul{margin:6px 0}")


def parse_oat_data(data):
    items = data.get("items", [])
    mk = lambda: dict(count=0, risk="", tactics=set(), techniques=set(), desc="",
        latest="", users=set(), urls=set(), actions=set(), products=set(),
        policies=set(), apps=set(), src_ips=set(), policy_templates=set(),
        entity_names=set())
    summary = defaultdict(mk)
    for item in items:
        for f in item.get("filters", []):
            s = summary[f["name"]]
            s["count"] += 1
            s["risk"] = f.get("riskLevel", "")
            s["desc"] = f.get("description", "")
            s["tactics"].update(f.get("mitreTacticIds", []))
            s["techniques"].update(f.get("mitreTechniqueIds", []))
            ep = item.get("entityName", "")
            if ep:
                s["entity_names"].add(ep)
            dt = item.get("detectedDateTime", "")
            if dt > s["latest"]:
                s["latest"] = dt
            d = item.get("detail", {})
            user = d.get("suid") or d.get("principalName") or ""
            if isinstance(user, str) and user:
                s["users"].add(user)
            act = d.get("act", "")
            if act:
                if isinstance(act, list):
                    act = ", ".join(act)
                s["actions"].add(act)
            for k, t in [("pname", "products"), ("profile", "policies"), ("application", "apps")]:
                v = d.get(k, "")
                if v:
                    s[t].add(v)
            src = d.get("src", [])
            if isinstance(src, list):
                for ip in src:
                    if len(str(ip)) > 3:
                        s["src_ips"].add(str(ip))
            elif isinstance(src, str) and len(src) > 3:
                s["src_ips"].add(src)
            for pt in d.get("policyTemplate", []):
                s["policy_templates"].add(pt)
            for h in f.get("highlightedObjects", []):
                val = h.get("value", "")
                if isinstance(val, list):
                    val = ", ".join(val)
                if val and h.get("type") == "url":
                    s["urls"].add(val)
    return items, summary


def build_rows(sf):
    rows = ""
    for name, s in sf:
        mitre = ", ".join(sorted(s["tactics"])) + " / " + ", ".join(sorted(s["techniques"]))
        eps = ", ".join(sorted(s["entity_names"]))[:60]
        rows += (f'<tr><td>{html.escape(name)}</td>'
                 f'<td><span class="tag {s["risk"]}">{s["risk"].upper()}</span></td>'
                 f'<td>{s["count"]}</td><td><code>{html.escape(mitre)}</code></td>'
                 f'<td>{html.escape(eps)}</td></tr>\n')
    return rows


def build_details(sf):
    out = ""
    for name, s in sf:
        out += f'<h4>{html.escape(name)}</h4>\n<ul>\n'
        out += f'<li><strong>Description:</strong> {html.escape(s["desc"])}</li>\n'
        fields = [
            ("entity_names", "Source"), ("src_ips", "Source IPs"), ("actions", "Action"),
            ("policies", "Policy"), ("policy_templates", "Template"),
            ("products", "Product"), ("apps", "Application"),
        ]
        for fld, label in fields:
            if s[fld]:
                out += f'<li><strong>{label}:</strong> {", ".join(sorted(s[fld]))}</li>\n'
        if s["urls"]:
            out += "<li><strong>URLs:</strong><ul>\n"
            for u in sorted(s["urls"])[:3]:
                t = u[:100] + "..." if len(u) > 100 else u
                out += f"<li><code>{html.escape(t)}</code></li>\n"
            out += "</ul></li>\n"
        out += f'<li><strong>Latest:</strong> {s["latest"]}</li>\n</ul>\n'
    return out


def assess(items, sf):
    ips, pols, acts = set(), set(), set()
    for _, s in sf:
        ips.update(s["src_ips"])
        pols.update(s["policies"])
        acts.update(s["actions"])
    ip_s = ", ".join(sorted(ips))
    pol_s = ", ".join(sorted(pols))
    n = len(items)
    if acts == {"Monitor"} and len(ips) <= 2:
        return (f'<p>All {n} detections are <strong>expected lab/test activity</strong>. '
                f'Single source ({ip_s}), "{pol_s}" policy in Monitor mode.</p>\n'
                f'<p><strong>Verdict:</strong> No action required.</p>')
    return (f'<p>{n} detections need <strong>review</strong>. '
            f'IPs: {ip_s}. Policies: {pol_s}. Actions: {", ".join(sorted(acts))}.</p>\n'
            f'<p><strong>Verdict:</strong> Review recommended.</p>')


def main():
    dp = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/oat_medium.json")
    if not os.path.exists(dp):
        print(f"ERROR: {dp} not found")
        sys.exit(1)
    data = json.load(open(dp))
    items, summary = parse_oat_data(data)
    if not items:
        print("No OAT items.")
        sys.exit(1)
    ro = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sf = sorted(summary.items(), key=lambda x: (ro.get(x[1]["risk"], 9), -x[1]["count"]))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dates = [i.get("detectedDateTime", "")[:10] for i in items if i.get("detectedDateTime")]
    dr = f"{min(dates)} to {max(dates)}" if dates else f"14d ending {today}"

    report = (f'<!DOCTYPE html>\n<html lang="en"><head><meta charset="UTF-8">\n'
              f'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
              f'<title>V1 OAT Detections - {dr}</title>\n'
              f'<style>{CSS}</style></head><body>\n'
              f'<h1>V1 OAT Detections Report</h1>\n'
              f'<p>Query: Noteworthy Observed Attack Techniques, {dr}</p>\n'
              f'<div class="chat">\n'
              f'<div class="msg user">Show me noteworthy OAT detections, medium risk and above.</div>\n'
              f'<div class="msg assistant">\n'
              f'<h2>V1 OAT Detections ({dr})</h2>\n'
              f'<p><strong>Medium+ risk:</strong> {len(items)} across {len(sf)} filter types</p>\n'
              f'<h3>Detections</h3>\n'
              f'<table><tr><th>Filter</th><th>Risk</th><th>Hits</th><th>MITRE</th><th>Endpoint</th></tr>\n'
              f'{build_rows(sf)}</table>\n'
              f'<h3>Details</h3>\n{build_details(sf)}\n'
              f'<h3>Assessment</h3>\n{assess(items, sf)}\n'
              f'</div></div>\n'
              f'<div class="meta">Generated by Claude Code | {today} | Vision One API (list_oat)</div>\n'
              f'</body></html>')

    os.makedirs("reports", exist_ok=True)
    path = f"reports/oat-detections-{today}.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Written: {path} ({len(report)} bytes)")
    print(f"\n=== OAT Summary ({dr}) ===")
    print(f"Medium+ detections: {len(items)} | Filters: {len(sf)}")
    for name, s in sf:
        mitre = ", ".join(sorted(s["tactics"])) + "/" + ", ".join(sorted(s["techniques"]))
        print(f'  {s["risk"].upper():8s} x{s["count"]:3d}  {name}  [{mitre}]')


if __name__ == "__main__":
    main()
