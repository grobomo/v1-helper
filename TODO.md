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

## v1.1: Lab Infrastructure
- [ ] Spin up dedicated EC2 spot instance (Debian) with microk8s for persistent test lab
- [ ] Install V1 Container Security helm chart on new cluster
- [ ] Register cluster in V1 console (connect to Trend first)
- [ ] Re-spin PX_lab cluster (auto-shutdown after 4h, need Blueprint to recreate)
- [ ] Add SSH security group rule for lab access
- [ ] Script to auto-provision lab: EC2 + microk8s + helm + V1 registration

## v1.1: Test Event Generation
- [ ] Continuous test event runner script (run in background on lab cluster)
- [ ] Varied attack simulations for runtime telemetry:
  - User creation / credential harvesting (useradd, /etc/shadow)
  - Package manager in runtime (apt, pip install)
  - Outbound C2 callbacks (curl to external domains)
  - Reverse shell attempts (bash -i, nc listeners)
  - Container escape attempts (mount /proc, access host PID)
  - Cryptominer behavior (CPU-intensive process, mining pool connections)
  - Supply chain: pull unscanned image, deploy pod with malicious entrypoint
  - Lateral movement: curl to internal service IPs, K8s API discovery
  - Secret extraction: env var dump, mounted secret volume reads
  - AI-enabled attack vectors: LLM-generated payloads, prompt injection via env vars
- [ ] Run events continuously so XDR data lake has telemetry to query
- [ ] Cache raw V1 data after each run for historical comparison

## v1.1: XDR Data Pipeline Integration
- [ ] Understand two data paths: admission controller (eval logs) vs runtime telemetry (XDR search)
- [ ] Wait for runtime sensor telemetry to index in XDR (15-60 min after events)
- [ ] Add XDR container activity results to report (table under each event)
- [ ] Claude analysis of XDR search results (not just eval events)
- [ ] Include raw API queries with placeholder key for customer self-service
- [ ] Historical data: save raw V1 data per run, compare across reports

## v1.2: Report Enhancements
- [ ] Direct PDF export (without browser print dialog) — use jsPDF or html2pdf.js
- [ ] Kubernetes labels in image grouping (need labels from V1 API or kubectl)
- [ ] Claude analysis of XDR query results with insights/next steps
- [ ] Historic trend analysis: compare current vs past reports
- [ ] Auto-troubleshoot unexpected V1 values (UNKNOWN protection, missing data)
- [ ] Debian base image support for lab (user preference)

## Future: Blueprint Browser Automation
- [ ] Blueprint Extra MCP: browser_track_interactions (click/keypress recording)
- [ ] Blueprint Extra MCP: browser_inject_overlay (persistent HTML in V1 DOM)
- [ ] Blueprint Extra MCP: browser_click_sequence (multi-step V1 actions)
- [ ] V1 overlay injection: analysis badges next to CVE rows in V1 console
- [ ] V1 action automation: dismiss/accept/remediate via Blueprint click sequences
- [ ] V1 SPA navigation handling (re-inject on page change)
