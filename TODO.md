# v1-helper TODO

## v1.0 DONE
- [x] Report generator with Claude-powered CVE analysis
- [x] V1 API integration (clusters, vulns, image occurrences, eval/sensor events)
- [x] Per-CVE environment-aware analysis (kernel vs userspace, EKS/ECS context)
- [x] Sorted by relevance (YES/LOW/NO), grouped by image + K8s location
- [x] Runtime event analysis with MITRE ATT&CK references per command
- [x] XDR queries with copy-to-clipboard for each event
- [x] Collapsible sections with expand bar + auto-scroll
- [x] Dark/light mode, sticky toolbar, font controls, CSV/PDF export
- [x] Cluster overview with protection modules, node topology, troubleshooting
- [x] V1 API reference section with curl examples
- [x] Secret scan CI workflow
- [x] Multi-customer support (--customer flag, per-customer API keys + context)
- [x] Auto-generate customer context from V1 API (platform detection, workloads)
- [x] Amazon ECS support (clusters, image occurrences, sensor events)
- [x] Dynamic relevance reasoning from customer context at report time
- [x] Inline environment context editor with save-to-disk
- [x] Sticky table headers below toolbar
- [x] Critical findings section with clickable jump links
- [x] Red border on critical items, neutral border on all items
- [x] Copy CVE ID button per row
- [x] Runtime events sorted by severity
- [x] V1 API retry logic for transient errors (504, 500, 429)
- [x] Fault-tolerant ECS API calls (V1 pagination bugs)

## Current
- [x] T002: V1 API key with full permissions stored (2026-04-24)
- [x] T003: OAT HTML report generator (scripts/gen_oat_report.py, 2026-04-24)
- [x] T004: Fix v1-api executor.py credential path (delegated to v1-api skill TODO)
- [x] T005: Fix Anthropic API key newline (key itself expired — analysis done in-session by Claude, cached to analysis.json)
- [x] Archived expired v1-lite/V1_API_KEY
- [x] Added no-Playwright rule to CLAUDE.md
- [x] DoD SIEM event verification (scripts/verify_dod_events.py)
- [x] T006: Auto-detect new CVEs not in analysis.json and prompt for analysis (2026-04-24)
- [ ] T007: Per-cluster report sections (group findings by cluster instead of mixing)

### Working API keys
- `v1-api/V1_API_KEY` — full permissions, Alerts+Clusters+OAT verified 200
- `v1-api/EP_API_KEY` — customer key, Alerts verified 200

## v1.1: Analysis Automation
- [x] Anthropic API key: expired, not needed — analysis is done in-session by Claude and cached to analysis.json
- [ ] Auto-run analysis for new CVEs not in analysis.json (currently manual)
- [ ] Analysis cache per customer (currently shared analysis.json)
- [ ] Diff analysis between runs (what changed since last report)

## v1.1: Lab Infrastructure
- [x] Terminated orphaned v1-helper-lab EC2 instance (was costing money)
- [ ] Spin up dedicated EC2 spot instance (Debian) with microk8s
- [ ] Install V1 Container Security helm chart on new cluster
- [ ] Register cluster in V1 console
- [ ] Script to auto-provision lab: EC2 + microk8s + helm + V1 registration
- [ ] Continuous test event runner (varied attack simulations for XDR telemetry)

## v1.2: Report Enhancements
- [ ] Direct PDF export without print dialog (jsPDF or html2pdf.js)
- [ ] Kubernetes labels in image grouping
- [ ] Historic trend analysis: compare current vs past reports
- [ ] Per-cluster sections in report (currently all clusters mixed together)
- [ ] V1 console deep links per CVE (not just generic vuln management page)

## Future: Blueprint Browser Automation
- [ ] V1 overlay injection: analysis badges next to CVE rows in V1 console
- [ ] V1 action automation: dismiss/accept/remediate via Blueprint
- [ ] V1 SPA navigation handling (re-inject on page change)
