#!/usr/bin/env python3
"""
Verify DoD SIEM Event ID coverage against V1 XDR endpoint activity search.

Reference: CISA/NSA/ASD "Priority Logs for SIEM Ingestion" (May 2025)

Usage:
    python scripts/verify_dod_events.py --customer ep
    python scripts/verify_dod_events.py --customer ep --hours 720
    python scripts/verify_dod_events.py --customer ep --cached reports/dod_event_verification.json
"""

import os, sys, json, argparse, time, requests
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/.claude/skills/credential-manager"))
from claude_cred import resolve as cred_resolve

# V1 region base URLs
REGION_URLS = {
    "us-east-1": "https://api.xdr.trendmicro.com",
    "eu-central-1": "https://api.eu.xdr.trendmicro.com",
    "ap-southeast-1": "https://api.sg.xdr.trendmicro.com",
    "ap-northeast-1": "https://api.jp.xdr.trendmicro.com",
    "ap-southeast-2": "https://api.au.xdr.trendmicro.com",
}

# All DoD/CISA recommended Windows Event IDs
# Format: event_id -> (description, doc_coverage_status, dod_priority)
DOD_EVENTS = {
    # 3.1 Process & Execution
    4688: ("Process Creation", "Standard", "High"),
    4689: ("Process Termination", "PENDING", "Medium"),
    # 3.2 Logon / Logoff
    4624: ("Successful Logon", "Standard", "High"),
    4625: ("Failed Logon", "Standard", "High"),
    4634: ("Account Logoff", "3P-Log-Collector", "High"),
    4647: ("User Initiated Logoff", "3P-Log-Collector", "High"),
    4648: ("Logon Using Explicit Credentials", "3P-Log-Collector", "High"),
    4672: ("Special Privileges Assigned", "3P-Log-Collector", "High"),
    4673: ("Privileged Service Called", "3P-Log-Collector", "Medium"),
    4674: ("Operation on Privileged Object", "3P-Log-Collector", "Medium"),
    # 3.3 Account Management
    4720: ("User Account Created", "Standard", "High"),
    4722: ("User Account Enabled", "Standard", "High"),
    4723: ("Password Change Attempt", "3P-Log-Collector", "High"),
    4724: ("Password Reset Attempt", "3P-Log-Collector", "High"),
    4725: ("User Account Disabled", "Standard", "High"),
    4726: ("User Account Deleted", "Standard", "High"),
    4738: ("User Account Changed", "3P-Log-Collector", "High"),
    4740: ("User Account Locked Out", "3P-Log-Collector", "High"),
    4767: ("User Account Unlocked", "3P-Log-Collector", "Medium"),
    # 3.4 Security Group Management
    4728: ("Member Added Global Group", "3P-Log-Collector", "High"),
    4729: ("Member Removed Global Group", "3P-Log-Collector", "High"),
    4732: ("Member Added Local Group", "3P-Log-Collector", "High"),
    4733: ("Member Removed Local Group", "3P-Log-Collector", "High"),
    4756: ("Member Added Universal Group", "3P-Log-Collector", "High"),
    4757: ("Member Removed Universal Group", "3P-Log-Collector", "High"),
    # 3.5 Scheduled Tasks
    4698: ("Scheduled Task Created", "Hypersensitive", "High"),
    4699: ("Scheduled Task Deleted", "Hypersensitive", "High"),
    4700: ("Scheduled Task Enabled", "Hypersensitive", "High"),
    4701: ("Scheduled Task Disabled", "Hypersensitive", "High"),
    4702: ("Scheduled Task Modified", "Hypersensitive", "High"),
    # 3.6 Service Installation
    7045: ("New Service Installed", "Hypersensitive", "High"),
    4697: ("Service Installed (Security)", "Hypersensitive", "High"),
    7040: ("Service Start Type Changed", "Hypersensitive", "Medium"),
    # 3.7 PowerShell
    4104: ("Script Block Logging", "Standard", "High"),
    4103: ("Module Logging", "3P-Log-Collector", "High"),
    # 3.8 WMI
    5857: ("WMI Provider Loaded", "Standard", "High"),
    5858: ("WMI Provider Error", "Standard", "Medium"),
    5859: ("WMI Subscription Event", "Standard", "High"),
    5860: ("WMI Subscription Binding", "Standard", "High"),
    5861: ("WMI ESS Event Filter", "Standard", "High"),
    # 3.9 Object / File Access
    4656: ("Handle to Object Requested", "Standard", "High"),
    4657: ("Registry Value Modified", "Standard", "High"),
    4660: ("Object Deleted", "PENDING", "Medium"),
    4663: ("Object Access Attempt", "Standard", "High"),
    # 3.11 Group Policy
    4719: ("System Audit Policy Changed", "3P-Log-Collector", "High"),
    # 3.12 Audit Log
    1100: ("Event Logging Service Shut Down", "3P-Log-Collector", "High"),
    1102: ("Audit Log Cleared", "3P-Log-Collector", "High"),
    # 3.13 AppLocker
    8004: ("AppLocker EXE/DLL Blocked", "3P-Log-Collector", "High"),
    8007: ("AppLocker Script Blocked", "3P-Log-Collector", "High"),
    8022: ("AppLocker Packaged App Allowed", "3P-Log-Collector", "Medium"),
    8025: ("AppLocker Packaged App Blocked", "3P-Log-Collector", "Medium"),
    # 3.14 Network / WFP
    5156: ("WFP Connection Permitted", "3P-Log-Collector", "High"),
    5157: ("WFP Connection Blocked", "3P-Log-Collector", "High"),
    5158: ("WFP Bind Permitted", "3P-Log-Collector", "Medium"),
    # 3.15 Kerberos / Auth (DC)
    4768: ("Kerberos TGT Requested", "3P-Log-Collector", "High"),
    4769: ("Kerberos Service Ticket", "3P-Log-Collector", "High"),
    4770: ("Kerberos Ticket Renewed", "3P-Log-Collector", "Medium"),
    4771: ("Kerberos Pre-Auth Failed", "3P-Log-Collector", "High"),
    4776: ("NTLM Credential Validation", "3P-Log-Collector", "High"),
    # 3.16 Directory Services (DC)
    4661: ("Handle to AD Object", "3P-Log-Collector", "High"),
    4662: ("Operation on AD Object", "3P-Log-Collector", "High"),
    4670: ("Object Permissions Changed", "Standard", "High"),
    5136: ("DS Object Modified", "3P-Log-Collector", "High"),
    5137: ("DS Object Created", "3P-Log-Collector", "High"),
    5141: ("DS Object Deleted", "3P-Log-Collector", "High"),
    # 3.17 Certificate Services (DC)
    4876: ("Cert Services Backup Started", "3P-Log-Collector", "Medium"),
    4886: ("Certificate Requested", "3P-Log-Collector", "High"),
    4887: ("Certificate Issued", "3P-Log-Collector", "High"),
    # 3.18 System Time
    4608: ("Windows Starting Up", "3P-Log-Collector", "Medium"),
    4609: ("Windows Shutting Down", "3P-Log-Collector", "Medium"),
    4616: ("System Time Changed", "3P-Log-Collector", "High"),
}


def load_customer_config(customer):
    config_path = Path(__file__).parent.parent / "customers" / f"{customer}.json"
    if not config_path.exists():
        print(f"Customer config not found: {config_path}")
        sys.exit(1)
    return json.loads(config_path.read_text())


def search_event_id(base_url, headers, event_id, hours=168):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    url = f"{base_url}/v3.0/search/endpointActivities"
    params = {
        "top": 5,
        "startDateTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endDateTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    req_headers = {**headers, "TMV1-Query": f"winEventId:{event_id}"}

    try:
        r = requests.get(url, headers=req_headers, params=params, timeout=30)
        if r.status_code == 200:
            data = r.json()
            return data.get("totalItems", data.get("totalCount", len(data.get("items", []))))
        elif r.status_code == 429:
            time.sleep(5)
            return search_event_id(base_url, headers, event_id, hours)
        else:
            return f"HTTP {r.status_code}"
    except Exception as e:
        return f"ERROR: {e}"


def main():
    parser = argparse.ArgumentParser(description="Verify DoD SIEM Event IDs against V1 XDR")
    parser.add_argument("--customer", required=True, help="Customer name (matches customers/<name>.json)")
    parser.add_argument("--hours", type=int, default=168, help="Lookback hours (default: 168 = 7 days)")
    parser.add_argument("--cached", help="Load results from cached JSON instead of querying API")
    parser.add_argument("--output", default="reports/dod_event_verification.json", help="Output JSON path")
    args = parser.parse_args()

    config = load_customer_config(args.customer)
    api_key = cred_resolve(config["api_key_name"]).strip()
    region = config.get("region", "us-east-1")
    base_url = REGION_URLS.get(region, REGION_URLS["us-east-1"])
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json;charset=utf-8",
    }

    results = {}

    if args.cached:
        print(f"Loading cached results from {args.cached}")
        cached = json.loads(Path(args.cached).read_text())
        for k, v in cached.items():
            results[int(k)] = v.get("hits", v) if isinstance(v, dict) else v
    else:
        print(f"Querying V1 XDR ({region}) for {len(DOD_EVENTS)} DoD event IDs ({args.hours}h lookback)...\n")
        for eid in sorted(DOD_EVENTS.keys()):
            time.sleep(1.5)
            desc, status, priority = DOD_EVENTS[eid]
            hits = search_event_id(base_url, headers, eid, args.hours)
            marker = "OK" if isinstance(hits, int) and hits > 0 else "MISS" if isinstance(hits, int) else "ERR"
            print(f"{eid:>5} | {str(hits):>8} | {status:<20} | {priority:<8} | {marker:>4} {desc}")
            results[eid] = hits

    # Categorize
    def by_status(status, found=True):
        return {k: v for k, v in results.items()
                if isinstance(v, int) and (v > 0 if found else v == 0) and DOD_EVENTS[k][1] == status}

    found_std, miss_std = by_status("Standard", True), by_status("Standard", False)
    found_hyp, miss_hyp = by_status("Hypersensitive", True), by_status("Hypersensitive", False)
    found_3p, miss_3p = by_status("3P-Log-Collector", True), by_status("3P-Log-Collector", False)
    found_pend, miss_pend = by_status("PENDING", True), by_status("PENDING", False)
    errs = {k: v for k, v in results.items() if isinstance(v, str)}

    print("\n" + "=" * 90)
    print(f"\nSTANDARD (doc says native):     {len(found_std)} found / {len(miss_std)} missing")
    for k in sorted(miss_std):
        print(f"  DISCREPANCY: {k} ({DOD_EVENTS[k][0]})")

    print(f"\nHYPERSENSITIVE:                 {len(found_hyp)} found / {len(miss_hyp)} missing")
    for k in sorted(found_hyp):
        print(f"  SURPRISE: {k} ({DOD_EVENTS[k][0]}) - found without Hypersensitive Mode")

    print(f"\n3P-LOG-COLLECTOR:               {len(found_3p)} found / {len(miss_3p)} missing")
    for k in sorted(found_3p):
        print(f"  SURPRISE: {k} ({DOD_EVENTS[k][0]}) - found without 3P collector")

    print(f"\nPENDING:                        {len(found_pend)} found / {len(miss_pend)} missing")
    for k in sorted(miss_pend):
        print(f"  STILL MISSING: {k} ({DOD_EVENTS[k][0]})")

    if errs:
        print(f"\nERRORS:                         {len(errs)}")
        for k in sorted(errs):
            print(f"  {k} ({DOD_EVENTS[k][0]}): {results[k]}")

    total_found = len(found_std) + len(found_hyp) + len(found_3p) + len(found_pend)
    total_miss = len(miss_std) + len(miss_hyp) + len(miss_3p) + len(miss_pend)
    print(f"\nTOTAL: {total_found} confirmed / {total_miss} not found / {len(errs)} errors")

    # Save
    output = {str(k): {
        "hits": v, "desc": DOD_EVENTS[k][0],
        "doc_status": DOD_EVENTS[k][1], "priority": DOD_EVENTS[k][2]
    } for k, v in results.items()}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
