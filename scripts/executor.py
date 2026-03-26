"""
executor.py — Main entry point for v1-helper skill.

Dependencies (bundled/expected):
  - Blueprint Extra MCP (browser automation) — via mcp-manager
  - mcp-manager — manages MCP server lifecycle
  - credential-manager — stores V1 API key
  - v1-api skill — V1 REST API operations (also used directly in v1_api.py)

Usage:
  python executor.py analyze              # Read V1 tab, enrich via API, analyze, inject overlays
  python executor.py report               # Generate HTML report from V1 API data
  python executor.py report --cached      # Use cached V1 data
  python executor.py read                 # Just read current V1 page, print data
  python executor.py overlay <analysis>   # Inject analysis overlays from JSON file
  python executor.py dismiss <CVE-ID>     # Dismiss a CVE in V1
  python executor.py track-start          # Start interaction tracking
  python executor.py track-export         # Export tracked interactions
"""

import os
import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CUSTOMERS_DIR = PROJECT_ROOT / "customers"

# Add credential-manager to path
sys.path.insert(0, os.path.expanduser("~/.claude/skills/credential-manager"))


def load_customer_config(customer="demo"):
    """Load customer config from customers/<name>.json."""
    p = CUSTOMERS_DIR / f"{customer}.json"
    if p.exists():
        return json.load(open(p))
    return {"api_key_name": "v1-api/V1_API_KEY", "region": "us-east-1"}

from v1_api import V1API
from v1_reader import detect_v1_page, get_scrape_js
from v1_overlay import build_overlay_js, build_remove_overlay_js
from v1_actions import build_dismiss_cve_js, build_change_status_js, build_bulk_action_sequence


def ensure_blueprint():
    """Verify Blueprint Extra MCP is available via mcp-manager."""
    # In practice, Claude Code calls mcp-manager tools directly.
    # This is for standalone CLI usage.
    print("Checking Blueprint Extra MCP...")
    # Would call: mcp-manager search blueprint
    print("  Blueprint Extra MCP required — ensure it is running via mcp-manager")


def load_customer_context():
    ctx_file = PROJECT_ROOT / "customer-context.md"
    if ctx_file.exists():
        return ctx_file.read_text()
    return "No customer context file. Analyze based on general container security best practices."


def cmd_analyze(args):
    """Full pipeline: read V1 tab + API enrichment + analysis + overlay injection."""
    ensure_blueprint()

    # Step 1: Pull V1 API data
    print("Pulling V1 API data...")
    api = V1API(args.region)
    data = api.pull_all()
    for k, v in data.items():
        print(f"  {k}: {len(v)}")

    # Cache for report generation
    cache_path = PROJECT_ROOT / "v1-data-cache.json"
    with open(cache_path, "w") as f:
        json.dump(data, f)
    print(f"  Cached to {cache_path}")

    # Step 2: Read V1 browser tab via Blueprint MCP
    # (In Claude Code session, this would be:
    #   mcp-manager call blueprint-extra browser_snapshot
    #   mcp-manager call blueprint-extra browser_evaluate {js}
    # )
    print("\nTo read V1 browser tab, run these in Claude Code:")
    print("  1. mcp-manager call blueprint-extra browser_tabs action=list")
    print("  2. mcp-manager call blueprint-extra browser_tabs action=attach index=<V1_TAB>")
    print("  3. mcp-manager call blueprint-extra browser_evaluate expression=<SCRAPE_JS>")

    # Step 3: Analysis happens in Claude Code session (Claude IS the analysis engine)
    print("\nAnalysis: Claude Code session analyzes each finding with customer context.")
    print(f"  Customer context: {PROJECT_ROOT / 'customer-context.md'}")

    # Step 4: Overlay injection
    print("\nTo inject overlays, run in Claude Code:")
    print("  mcp-manager call blueprint-extra browser_evaluate expression=<OVERLAY_JS>")


def cmd_report(args):
    """Generate HTML report from V1 API data."""
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

    # Import report generator (from recording-analyzer or local copy)
    report_gen = PROJECT_ROOT.parent / "recording-analyzer" / "tools" / "generate-report.py"
    if report_gen.exists():
        print(f"\nReport generator: {report_gen}")
        print(f"Run: python {report_gen} --cached {PROJECT_ROOT / 'v1-data-cache.json'}")
    else:
        print("Report generator not found. Copy from recording-analyzer/tools/generate-report.py")


def cmd_read(args):
    """Read current V1 page data via Blueprint MCP."""
    ensure_blueprint()
    print("JS to scrape V1 vulnerability table:")
    print(get_scrape_js("vulnerability_management"))
    print("\nRun via: mcp-manager call blueprint-extra browser_evaluate expression=<above JS>")


def cmd_overlay(args):
    """Inject analysis overlays from JSON file."""
    if not args.analysis_file:
        print("Usage: python executor.py overlay <analysis.json>")
        return
    analyses = json.load(open(args.analysis_file))
    js = build_overlay_js(analyses)
    print("JS to inject overlays:")
    print(js[:500] + "...")
    print("\nRun via: mcp-manager call blueprint-extra browser_evaluate expression=<above JS>")


def cmd_dismiss(args):
    """Dismiss a CVE in V1 via Blueprint MCP automation."""
    if not args.cve_id:
        print("Usage: python executor.py dismiss CVE-XXXX-XXXXX")
        return
    steps = [
        ("Select CVE", build_dismiss_cve_js(args.cve_id)),
        ("Change status", build_change_status_js("dismissed")),
    ]
    print(f"Dismiss {args.cve_id} — {len(steps)} steps:")
    for desc, js in steps:
        print(f"\n--- {desc} ---")
        print(js[:300] + "...")
    print("\nRun each step via: mcp-manager call blueprint-extra browser_evaluate expression=<JS>")
    print("Wait 1-2 seconds between steps for V1 UI to update.")


def main():
    parser = argparse.ArgumentParser(description="V1 Helper — Vision One analysis skill")
    parser.add_argument("--region", default=None, help="Override V1 region (default: from customer config)")
    parser.add_argument("--customer", default="demo", help="Customer name (loads customers/<name>.json)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("analyze", help="Full pipeline: read + enrich + analyze + overlay")
    p_report = sub.add_parser("report", help="Generate HTML report")
    p_report.add_argument("--cached", action="store_true")
    sub.add_parser("read", help="Read current V1 page")
    p_overlay = sub.add_parser("overlay", help="Inject analysis overlays")
    p_overlay.add_argument("analysis_file", nargs="?")
    p_dismiss = sub.add_parser("dismiss", help="Dismiss a CVE")
    p_dismiss.add_argument("cve_id", nargs="?")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "read":
        cmd_read(args)
    elif args.command == "overlay":
        cmd_overlay(args)
    elif args.command == "dismiss":
        cmd_dismiss(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
