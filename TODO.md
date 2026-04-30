# v1-helper TODO

## Session Handoff
This session: V1 deep links (region-aware portal URLs, per-CVE buttons, fixed wrong links) + diff analysis (--prev flag, auto-compare on fresh runs, new/resolved/changed section in report). CLAUDE.md updated.
Next: Kubernetes labels in grouping, PDF export, or historic trend analysis.

## Priority 1: Chrome Extension
- [x] T013: MVP Chrome extension — ported from Blueprint Extra MCP, Trend-branded, MCP automation + CVE overlay
- [x] T014: CVE overlay injection — color-coded badges (relevant/low/not-relevant), detail panel, auto-inject on V1 SPA nav, toggle in popup
- [x] T015: CVE list view in popup — filter by relevance (All/Relevant/Low/None), copy CVE IDs to clipboard, 40-point test suite
- [x] T016: V1 settings — API key (masked + toggle), region selector (5 regions), test connection, customer context, 53-point test suite
- [x] T017: Extension verified — 53-point Playwright test (service worker, popup, V1 settings, content script, icons, overlay, CVE list)

## Priority 2: Reports
- [x] T007: Per-cluster report sections — images grouped under cluster headers with protection status, sorted by CVE count
- [x] Auto-run analysis for new CVEs — incremental Claude analysis, merge into analysis.json
- [x] Analysis cache per customer — `reports/<customer>-analysis.json`, auto-migrates from shared file
- [x] Diff analysis between runs — --prev flag, auto-loads previous cache, new/resolved/changed CVE section
- [ ] Direct PDF export without print dialog (jsPDF or html2pdf.js)
- [ ] Kubernetes labels in image grouping
- [ ] Historic trend analysis: compare current vs past reports
- [x] V1 console deep links per CVE — region-aware portal URLs, per-row V1 button, fixed wrong links, API ref URLs

## Priority 3: Automation Tooling
- [ ] T009: Live test automation against V1 console — BLOCKED: need V1 login password stored in credential-manager
- [x] T010: V1 SPA navigation handling — implemented in T014 content script (MutationObserver URL watcher)
- [ ] T011: Bulk CVE triage workflow (auto-dismiss non-relevant, accept low-risk, flag critical)
- [ ] T012: V1 page data scraper — extract data not available via API (policy details, etc)

## Priority 4: Lab Infrastructure
- [ ] Spin up dedicated EC2 spot instance (Debian) with microk8s
- [ ] Install V1 Container Security helm chart on new cluster
- [ ] Register cluster in V1 console
- [ ] Script to auto-provision lab: EC2 + microk8s + helm + V1 registration
- [ ] Continuous test event runner (varied attack simulations for XDR telemetry)

## Completed
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
- [x] T002: V1 API key with full permissions stored
- [x] T003: OAT HTML report generator
- [x] T004: Fix v1-api executor.py credential path
- [x] T005: Fix Anthropic API key newline
- [x] T006: Auto-detect new CVEs not in analysis.json
- [x] T008: Automate sub-module with plan-based architecture
- [x] T008a: JS payloads for V1 DOM interaction
- [x] T008b: Action plan builders — dismiss, accept, overlay, read
- [x] T008c: Unified CLI with automate sub-commands
- [x] DoD SIEM event verification
- [x] Terminated orphaned v1-helper-lab EC2 instance

### Working API keys
- `v1-api/V1_API_KEY` — full permissions, Alerts+Clusters+OAT verified 200
- `v1-api/EP_API_KEY` — customer key, Alerts verified 200
