"""
actions.py — High-level action plan builders for V1 console automation.

Plans are structured JSON sequences that Claude Code executes via Blueprint MCP.
Each step maps to a Blueprint MCP tool call (navigate, evaluate, snapshot).
"""

import json
from pathlib import Path
from . import js as v1js

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

V1_PAGES = {
    "vuln_mgmt": "#/app/sase",
    "container_inventory": "#/app/server-cloud/container-inventory",
    "container_protection": "#/app/server-cloud/container-protection",
    "workbench": "#/app/workbench",
    "xdr_search": "#/app/search",
    "risk_insights": "#/app/risk-insights/risk-index",
}


# ============================================================
# Plan step builders
# ============================================================

def _step(action, description, **kwargs):
    """Create a plan step."""
    return {"action": action, "description": description, **kwargs}


def step_navigate(page_key):
    route = V1_PAGES.get(page_key, page_key)
    return _step("navigate", f"Navigate to V1 {page_key}", url_fragment=route)


def step_evaluate(description, js_code, expect_key=None):
    s = _step("evaluate", description, js=js_code)
    if expect_key:
        s["expect"] = f"result.{expect_key} should be true"
    return s


def step_snapshot(description="Verify page state"):
    return _step("snapshot", description)


def step_wait(description, seconds=2):
    return _step("wait", description, seconds=seconds)


def build_plan(steps, metadata=None):
    return {"version": 1, "metadata": metadata or {}, "steps": steps}


# ============================================================
# High-level automation plans
# ============================================================

def plan_dismiss_cves(cve_ids, reason="Not relevant per analysis"):
    """Dismiss multiple CVEs in V1 vulnerability management."""
    steps = [
        step_navigate("vuln_mgmt"),
        step_snapshot("Confirm vulnerability management page loaded"),
        step_evaluate("Read page state", v1js.get_page_state()),
    ]

    for cve in cve_ids:
        steps.extend([
            step_evaluate(f"Search for {cve}", v1js.search_cve(cve)),
            step_wait(f"Wait for filter to apply for {cve}"),
            step_evaluate(f"Find {cve} row", v1js.find_cve_row(cve), expect_key="found"),
            step_evaluate(f"Check {cve} checkbox", v1js.check_cve(cve), expect_key="success"),
            step_evaluate("Clear search", v1js.clear_search()),
        ])

    steps.extend([
        step_evaluate("Open status dropdown", v1js.click_status_dropdown(), expect_key="success"),
        step_wait("Wait for dropdown to render"),
        step_evaluate("Select 'Dismissed'", v1js.select_status("dismissed"), expect_key="success"),
        step_wait("Wait for confirmation dialog"),
        step_evaluate("Click confirm", v1js.click_confirm(), expect_key="success"),
        step_snapshot("Verify CVEs were dismissed"),
    ])

    return build_plan(steps, {
        "action": "dismiss_cves",
        "cve_count": len(cve_ids),
        "cve_ids": cve_ids,
        "reason": reason,
    })


def plan_change_cve_status(cve_ids, status):
    """Change status of CVEs. Status: dismissed, accepted, inProgress, remediated."""
    steps = [
        step_navigate("vuln_mgmt"),
        step_snapshot("Confirm vulnerability management page loaded"),
    ]

    for cve in cve_ids:
        steps.extend([
            step_evaluate(f"Search for {cve}", v1js.search_cve(cve)),
            step_wait(f"Wait for filter for {cve}"),
            step_evaluate(f"Check {cve}", v1js.check_cve(cve), expect_key="success"),
            step_evaluate("Clear search", v1js.clear_search()),
        ])

    steps.extend([
        step_evaluate("Open status dropdown", v1js.click_status_dropdown(), expect_key="success"),
        step_wait("Wait for dropdown"),
        step_evaluate(f"Select '{status}'", v1js.select_status(status), expect_key="success"),
        step_wait("Wait for confirmation"),
        step_evaluate("Confirm", v1js.click_confirm(), expect_key="success"),
        step_snapshot("Verify status changed"),
    ])

    return build_plan(steps, {"action": "change_status", "status": status, "cve_ids": cve_ids})


def plan_inject_overlays(analysis_file=None):
    """Inject analysis overlays into the V1 vulnerability page."""
    import sys, os
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from v1_overlay import build_overlay_js

    analysis_file = analysis_file or str(PROJECT_ROOT / "reports" / "analysis.json")
    p = Path(analysis_file)
    analyses = json.loads(p.read_text()) if p.exists() else []
    if isinstance(analyses, dict):
        analyses = [{"cve": k, **v} for k, v in analyses.items()]

    overlay_js = build_overlay_js(analyses)
    return build_plan([
        step_navigate("vuln_mgmt"),
        step_snapshot("Confirm on vulnerability page"),
        step_evaluate(f"Inject {len(analyses)} analysis overlays", overlay_js),
        step_snapshot("Verify overlays injected"),
    ], {"action": "inject_overlays", "analysis_count": len(analyses)})


def plan_read_page(page_key="vuln_mgmt"):
    """Navigate to a V1 page and scrape its data."""
    import sys
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from v1_reader import get_scrape_js

    page_type_map = {
        "vuln_mgmt": "vulnerability_management",
        "container_inventory": "container_inventory",
    }
    scrape_js = get_scrape_js(page_type_map.get(page_key, "vulnerability_management"))

    return build_plan([
        step_navigate(page_key),
        step_snapshot("Confirm page loaded"),
        step_evaluate("Read page state", v1js.get_page_state()),
        step_evaluate("Scrape page data", scrape_js),
    ], {"action": "read_page", "page": page_key})


def plan_from_report(action="dismiss"):
    """Build a plan from report analysis — dismiss/accept all non-relevant CVEs."""
    analysis_path = PROJECT_ROOT / "reports" / "analysis.json"
    if not analysis_path.exists():
        return build_plan([], {"error": "No analysis.json found. Run report first."})

    analyses = json.loads(analysis_path.read_text())
    if isinstance(analyses, list):
        analyses = {a["cve"]: a for a in analyses if "cve" in a}

    non_relevant = [cve for cve, a in analyses.items() if a.get("relevant") == "no"]

    if not non_relevant:
        return build_plan([], {"info": "No non-relevant CVEs found in analysis."})

    if action == "dismiss":
        return plan_dismiss_cves(non_relevant, "Marked non-relevant by Claude analysis")
    elif action == "accept":
        return plan_change_cve_status(non_relevant, "accepted")
    else:
        return build_plan([], {"error": f"Unknown action: {action}"})


def plan_triage(customer=None, dry_run=False):
    """Full bulk triage: dismiss non-relevant, accept low-risk, flag critical.

    Returns dict with:
      - summary: counts per category
      - plans: list of action plans to execute (dismiss + accept)
      - critical: CVEs flagged for manual review
      - dry_run: if True, plans are preview-only
    """
    # Find analysis file — per-customer first, then shared
    if customer:
        analysis_path = PROJECT_ROOT / "reports" / f"{customer}-analysis.json"
    else:
        analysis_path = PROJECT_ROOT / "reports" / "analysis.json"

    if not analysis_path.exists():
        analysis_path = PROJECT_ROOT / "reports" / "analysis.json"

    if not analysis_path.exists():
        return {"error": "No analysis file found. Run report first.", "plans": [], "critical": []}

    analyses = json.loads(analysis_path.read_text())
    if isinstance(analyses, list):
        analyses = {a["cve"]: a for a in analyses if "cve" in a}

    # Categorize
    dismiss = []  # relevant == "no"
    accept = []   # relevant == "low"
    critical = [] # severity critical/high AND relevant == "yes"
    review = []   # relevant == "yes" but not critical severity

    for cve, a in analyses.items():
        rel = a.get("relevant", "").lower()
        action_text = a.get("action", a.get("what", ""))
        owner = a.get("owner", "")

        if rel == "no":
            dismiss.append(cve)
        elif rel == "low":
            accept.append(cve)
        elif rel == "yes":
            item = {"cve": cve, "owner": owner, "action": action_text}
            if owner.lower() in ("sre", "dev", "security"):
                critical.append(item)
            else:
                review.append(item)

    summary = {
        "total": len(analyses),
        "dismiss": len(dismiss),
        "accept": len(accept),
        "critical": len(critical),
        "review": len(review),
        "unanalyzed": len(analyses) - len(dismiss) - len(accept) - len(critical) - len(review),
    }

    plans = []
    if not dry_run:
        if dismiss:
            plans.append(plan_dismiss_cves(dismiss, "Bulk triage: not relevant per analysis"))
        if accept:
            plans.append(plan_change_cve_status(accept, "accepted"))

    return {
        "summary": summary,
        "plans": plans,
        "critical": critical,
        "review": review,
        "dismiss_cves": dismiss,
        "accept_cves": accept,
        "analysis_file": str(analysis_path),
        "dry_run": dry_run,
    }


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys as _sys
    if len(_sys.argv) < 2:
        print("Usage: python -m automate.actions <command> [args]")
        print("  dismiss CVE-2024-1234 ...   Generate dismiss plan")
        print("  accept CVE-2024-1234 ...    Generate accept plan")
        print("  overlay                     Generate overlay injection plan")
        print("  read [page_key]             Generate page read plan")
        print("  auto-dismiss                Dismiss all non-relevant from analysis")
        _sys.exit(0)

    cmd = _sys.argv[1]
    if cmd == "dismiss":
        plan = plan_dismiss_cves(_sys.argv[2:])
    elif cmd == "accept":
        plan = plan_change_cve_status(_sys.argv[2:], "accepted")
    elif cmd == "overlay":
        plan = plan_inject_overlays()
    elif cmd == "read":
        plan = plan_read_page(_sys.argv[2] if len(_sys.argv) > 2 else "vuln_mgmt")
    elif cmd == "auto-dismiss":
        plan = plan_from_report("dismiss")
    else:
        print(f"Unknown command: {cmd}")
        _sys.exit(1)

    print(json.dumps(plan, indent=2))
