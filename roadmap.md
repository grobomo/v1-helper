# V1 Helper — Roadmap

## Phase 1: Clean Architecture (current)
Strip the extension back to its core purpose. Remove the Playwright dependency.

- [ ] Remove MCP bridge code from extension (WebSocket, tab handlers, network tracker, dialog handler, console handler)
- [ ] Remove `launch-extension.js` and `load-analysis.js` (Playwright-dependent)
- [ ] Remove duplicate icon sets (`extension/icons/` vs `extension/chrome/icons/`)
- [ ] Remove `v1_actions.py` (deprecated)
- [ ] Remove MCP status display from popup (no longer relevant)
- [ ] Update popup to focus on: import analysis, view CVEs, toggle overlays, settings
- [ ] Write install instructions for Chrome developer mode
- [ ] Rewrite tests without Playwright (use Chrome extension testing patterns or manual checklist)
- [ ] Verify extension loads in Chrome, import works, overlays appear on V1 pages

## Phase 2: Extension Verified on V1
Prove the extension works end-to-end on real V1 Container Security pages.

- [ ] Store V1 login password in credential-manager
- [ ] Load extension in Chrome, navigate to V1 Container Security
- [ ] Import analysis.json, verify overlays appear on CVE rows
- [ ] Test SPA navigation watcher (navigate between V1 pages, overlays re-inject)
- [ ] Test detail panel (click badge, see full analysis)
- [ ] Fix any DOM selector issues (V1 uses Ant Design, selectors may break)
- [ ] Document known V1 DOM patterns for overlay injection
- [ ] Screenshot the working overlay for docs/demo

## Phase 3: Automation via Blueprint MCP
Use Blueprint MCP (not the extension) for browser automation.

- [ ] Log into V1 via Blueprint MCP
- [ ] Navigate to Container Security > Vulnerabilities
- [ ] Execute a dismiss plan (from `automate triage --save`)
- [ ] Execute an accept plan
- [ ] Verify status changes in V1 console
- [ ] End-to-end test: generate plan > execute via Blueprint > verify in V1

## Phase 4: Lab Infrastructure
A real K8s cluster registered in V1 for generating test data.

- [ ] EC2 spot instance with microk8s (scripts exist in scripts/aws/)
- [ ] Fix cloud-init user data encoding (base64 issue on Windows)
- [ ] Install V1 Container Security helm chart
- [ ] Register cluster in V1 console
- [ ] Deploy test workloads to generate CVEs and sensor events
- [ ] Continuous event generation for XDR telemetry

## Phase 5: Reports Polish
Make reports production-ready for customer delivery.

- [ ] Direct PDF export (html2pdf.js, WIP in worktree-pdf-export)
- [ ] Executive summary page (counts + critical items only)
- [ ] Historic trend analysis (compare multiple report runs)
- [ ] Kubernetes labels in image grouping (blocked by V1 API)

## Phase 6: Distribution
Make it easy for others to use.

- [ ] README with screenshots and quick start
- [ ] Chrome Web Store listing (unlisted) for easy extension install
- [ ] Package as a Claude Code skill for the CLI workflows
- [ ] Demo video: full workflow from API key to report to triage

## Deferred / Maybe Later

- Extension-native analysis (Claude API key in extension, fully standalone)
- Cross-customer CVE rollup
- V1 exception policy sync
- Slack/Teams report delivery
- Scheduled report generation
