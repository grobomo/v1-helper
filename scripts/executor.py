"""
executor.py — Main CLI entry point for v1-helper.

Sub-modules:
  report    — HTML report generation (container security, OAT)
  automate  — V1 console automation via Blueprint MCP action plans
  read      — V1 page scraping
  overlay   — Analysis badge injection

Usage:
  python executor.py report --customer ep          # Generate container security report
  python executor.py report --customer ep --cached  # Use cached V1 data
  python executor.py automate dismiss CVE-2024-1234 CVE-2024-5678
  python executor.py automate auto-dismiss          # Dismiss all non-relevant from analysis
  python executor.py automate overlay               # Inject analysis overlays
  python executor.py automate read [page_key]       # Scrape V1 page
  python executor.py automate plan <plan.json>      # Show a saved plan
"""

import os
import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CUSTOMERS_DIR = PROJECT_ROOT / "customers"

sys.path.insert(0, os.path.expanduser("~/.claude/skills/credential-manager"))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def load_customer_config(customer="demo"):
    p = CUSTOMERS_DIR / f"{customer}.json"
    if p.exists():
        return json.load(open(p))
    return {"api_key_name": "v1-api/V1_API_KEY", "region": "us-east-1"}


# ============================================================
# Report commands
# ============================================================

def cmd_report(args):
    """Generate HTML report from V1 API data."""
    from v1_api import V1API
    config = load_customer_config(args.customer)
    region = args.region or config.get("region", "us-east-1")
    api_key = config.get("api_key_name", "v1-api/V1_API_KEY")
    cache_path = PROJECT_ROOT / "reports" / f"{args.customer}-raw-data.json"

    if args.cached and cache_path.exists():
        print(f"Loading cached V1 data from {cache_path}...")
        data = json.load(open(cache_path))
    else:
        print(f"Pulling V1 API data (customer: {args.customer}, key: {api_key})...")
        api = V1API(region, api_key)
        data = api.pull_all()

    for k, v in data.items():
        print(f"  {k}: {len(v)}")

    print(f"\nTo generate report: python scripts/report_generator.py --customer {args.customer}" +
          (f" --cached reports/{args.customer}-raw-data.json" if args.cached else ""))


# ============================================================
# Automation commands
# ============================================================

def cmd_automate(args):
    """Generate and optionally save automation action plans."""
    from automate.actions import (
        plan_dismiss_cves, plan_change_cve_status,
        plan_inject_overlays, plan_read_page, plan_from_report,
        plan_triage,
    )

    sub = args.auto_command
    if sub == "triage":
        customer = getattr(args, 'customer', None)
        dry_run = getattr(args, 'dry_run', False)
        result = plan_triage(customer=customer, dry_run=dry_run)

        if result.get("error"):
            print(f"Error: {result['error']}", file=sys.stderr)
            return

        s = result["summary"]
        print(f"\n=== Bulk CVE Triage {'(DRY RUN)' if dry_run else ''} ===")
        print(f"Analysis: {result['analysis_file']}")
        print(f"Total CVEs: {s['total']}")
        print(f"  Dismiss (not relevant): {s['dismiss']}")
        print(f"  Accept (low risk):      {s['accept']}")
        print(f"  Critical (needs review):{s['critical']}")
        print(f"  Other relevant:         {s['review']}")
        if s['unanalyzed'] > 0:
            print(f"  Unanalyzed:             {s['unanalyzed']}")

        if result["critical"]:
            print(f"\n--- ACTION REQUIRED (assigned owner) ---")
            for item in result["critical"]:
                print(f"  [{item['owner']}] {item['cve']}: {item['action'][:80]}")

        if result["review"]:
            print(f"\n--- Relevant (unassigned) ---")
            for item in result["review"]:
                print(f"  {item['cve']}: {item['action'][:80]}")

        if dry_run:
            print(f"\nDry run — no plans generated. Remove --dry-run to generate action plans.")
            return

        if result["plans"]:
            for i, plan in enumerate(result["plans"]):
                meta = plan.get("metadata", {})
                steps = len(plan.get("steps", []))
                print(f"\n--- Plan {i+1}: {meta.get('action', '?')} | {steps} steps ---")
                if args.save:
                    out = PROJECT_ROOT / "reports" / f"plan-triage-{i+1}.json"
                    out.write_text(json.dumps(plan, indent=2))
                    print(f"Saved: {out}")
                else:
                    print(json.dumps(plan, indent=2))
        else:
            print("\nNo actions needed — all CVEs already triaged or relevant.")
        return

    elif sub == "dismiss":
        if not args.cve_ids:
            print("Usage: executor.py automate dismiss CVE-2024-1234 [CVE-2024-5678 ...]")
            return
        plan = plan_dismiss_cves(args.cve_ids)

    elif sub == "accept":
        if not args.cve_ids:
            print("Usage: executor.py automate accept CVE-2024-1234 [CVE-2024-5678 ...]")
            return
        plan = plan_change_cve_status(args.cve_ids, "accepted")

    elif sub == "status":
        if not args.cve_ids or not args.status_value:
            print("Usage: executor.py automate status --status dismissed CVE-2024-1234 ...")
            return
        plan = plan_change_cve_status(args.cve_ids, args.status_value)

    elif sub == "auto-dismiss":
        plan = plan_from_report("dismiss")

    elif sub == "auto-accept":
        plan = plan_from_report("accept")

    elif sub == "overlay":
        plan = plan_inject_overlays(args.analysis_file)

    elif sub == "read":
        plan = plan_read_page(args.page_key if hasattr(args, 'page_key') and args.page_key else "vuln_mgmt")

    elif sub == "plan":
        if not args.plan_file:
            print("Usage: executor.py automate plan <plan.json>")
            return
        plan = json.loads(Path(args.plan_file).read_text())

    else:
        print(f"Unknown automate command: {sub}")
        return

    # Output the plan
    plan_json = json.dumps(plan, indent=2)

    if args.save:
        out_path = PROJECT_ROOT / "reports" / f"plan-{sub}.json"
        out_path.write_text(plan_json)
        print(f"Plan saved to {out_path}")
    else:
        print(plan_json)

    meta = plan.get("metadata", {})
    if meta.get("error"):
        print(f"\nError: {meta['error']}", file=sys.stderr)
    elif meta.get("info"):
        print(f"\nInfo: {meta['info']}")
    else:
        step_count = len(plan.get("steps", []))
        print(f"\n--- Plan: {meta.get('action', sub)} | {step_count} steps ---")
        print("Claude Code executes this plan via Blueprint MCP tools.")
        print("Each 'evaluate' step -> browser_evaluate, 'navigate' -> browser_navigate, 'snapshot' -> browser_snapshot")


# ============================================================
# Legacy commands (kept for backward compatibility)
# ============================================================

def cmd_analyze(args):
    from automate.actions import plan_inject_overlays, plan_read_page
    print("Full analysis pipeline:")
    print("  1. python scripts/report_generator.py --customer <name>")
    print("  2. python scripts/executor.py automate overlay")
    print("  3. Claude Code executes the plan via Blueprint MCP")


def cmd_read(args):
    from automate.actions import plan_read_page
    plan = plan_read_page()
    print(json.dumps(plan, indent=2))


def cmd_overlay(args):
    from automate.actions import plan_inject_overlays
    plan = plan_inject_overlays(args.analysis_file if hasattr(args, 'analysis_file') else None)
    print(json.dumps(plan, indent=2))


def cmd_dismiss(args):
    from automate.actions import plan_dismiss_cves
    if not args.cve_id:
        print("Usage: python executor.py dismiss CVE-XXXX-XXXXX")
        return
    plan = plan_dismiss_cves([args.cve_id])
    print(json.dumps(plan, indent=2))


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="v1-helper — Vision One container security toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Sub-modules:
  report     Generate HTML container security reports
  automate   V1 console automation via Blueprint MCP action plans

Examples:
  python executor.py report --customer ep --cached
  python executor.py automate dismiss CVE-2024-1234
  python executor.py automate auto-dismiss
  python executor.py automate overlay
""")
    parser.add_argument("--region", default=None)
    parser.add_argument("--customer", default="demo")
    sub = parser.add_subparsers(dest="command")

    # Report
    p_report = sub.add_parser("report", help="Generate HTML report")
    p_report.add_argument("--cached", action="store_true")

    # Automate
    p_auto = sub.add_parser("automate", help="V1 console automation")
    p_auto.add_argument("auto_command", choices=[
        "dismiss", "accept", "status", "auto-dismiss", "auto-accept",
        "overlay", "read", "plan", "triage"
    ])
    p_auto.add_argument("cve_ids", nargs="*", default=[])
    p_auto.add_argument("--status", dest="status_value", default="dismissed")
    p_auto.add_argument("--save", action="store_true", help="Save plan to reports/")
    p_auto.add_argument("--analysis-file", default=None)
    p_auto.add_argument("--page-key", default="vuln_mgmt")
    p_auto.add_argument("--plan-file", default=None)
    p_auto.add_argument("--dry-run", action="store_true", help="Preview triage without generating plans")

    # Legacy commands
    sub.add_parser("analyze", help="(legacy) Full analysis pipeline")
    p_read = sub.add_parser("read", help="(legacy) Read V1 page")
    p_overlay = sub.add_parser("overlay", help="(legacy) Inject overlays")
    p_overlay.add_argument("analysis_file", nargs="?")
    p_dismiss = sub.add_parser("dismiss", help="(legacy) Dismiss a CVE")
    p_dismiss.add_argument("cve_id", nargs="?")

    args = parser.parse_args()

    commands = {
        "report": cmd_report,
        "automate": cmd_automate,
        "analyze": cmd_analyze,
        "read": cmd_read,
        "overlay": cmd_overlay,
        "dismiss": cmd_dismiss,
    }
    fn = commands.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
