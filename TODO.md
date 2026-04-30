# v1-helper TODO

## Session Handoff
Architecture reset. Created VISION.md, brainstorming.md, roadmap.md.
Key insight: extension has wrong architecture — it's a fork of Blueprint MCP with CVE overlays bolted on.
Must strip MCP bridge code, remove Playwright dependency, make it a pure Chrome extension.
Lab EC2 instance running (i-04cc9b51b45291988, 3.144.209.155) but cloud-init failed (base64 encoding issue). Needs manual fix or teardown.
PDF export WIP in worktree-pdf-export branch.

## Phase 1: Clean Architecture (ACTIVE)
Strip the extension to its core purpose. Remove Playwright.

- [ ] T019: Remove MCP bridge code from extension (WebSocket, tab handlers, network tracker, dialog handler, console handler, install handler)
- [ ] T020: Remove Playwright-dependent scripts (launch-extension.js, load-analysis.js)
- [ ] T021: Clean up popup — remove MCP status display, focus on: import analysis, view CVEs, toggle overlays, settings
- [ ] T022: Remove duplicate icon sets (extension/icons/ vs extension/chrome/icons/)
- [ ] T023: Remove deprecated v1_actions.py
- [ ] T024: Write Chrome developer mode install instructions
- [ ] T025: Rewrite tests without Playwright dependency

## Phase 2: Verify on V1 (needs V1 login)
- [ ] T009: Store V1 login password in credential-manager
- [ ] T026: Load extension in Chrome, navigate to V1, verify overlays appear on CVE rows
- [ ] T027: Test SPA navigation (overlays re-inject on V1 route changes)
- [ ] T028: Fix any DOM selector issues (V1 uses Ant Design)
- [ ] T029: Screenshot working overlay for docs

## Phase 3: Automation via Blueprint MCP
- [ ] T030: Log into V1 via Blueprint MCP (not Playwright)
- [ ] T031: Execute dismiss/accept plans via Blueprint MCP
- [ ] T012: V1 page data scraper via Blueprint

## Phase 4: Lab Infrastructure
- [ ] T032: Fix cloud-init user data encoding (base64 on Windows)
- [ ] T033: Install V1 Container Security on lab cluster
- [ ] T034: Deploy test workloads, generate CVEs and sensor events

## Phase 5: Reports Polish (lowest priority)
- [ ] PDF export (WIP in worktree-pdf-export)
- [ ] Executive summary
- [ ] Historic trend analysis
- [ ] K8s labels in image grouping (blocked by V1 API)

## Completed
- [x] T013: MVP Chrome extension (ported from Blueprint Extra MCP)
- [x] T014: CVE overlay injection (color-coded badges, detail panel, SPA nav watcher)
- [x] T015: CVE list view in popup (filter, copy IDs)
- [x] T016: V1 settings (API key, region, test connection, customer context)
- [x] T017: Extension verified (54-point test via Playwright)
- [x] T018: Extension launch fix (Playwright Chromium workaround)
- [x] T007: Per-cluster report sections
- [x] T010: V1 SPA navigation handling
- [x] T011: Bulk CVE triage workflow
- [x] Report generator, V1 API integration, analysis, relevance, diff, XDR, runtime events
- [x] Multi-customer support, ECS support, secret scan CI, deep links
- [x] T002-T008: API keys, OAT report, automate sub-module, JS payloads, action plans, CLI

### Working API keys
- `v1-api/V1_API_KEY` — full permissions, Alerts+Clusters+OAT verified 200
- `v1-api/EP_API_KEY` — customer key, Alerts verified 200

### Active infrastructure
- EC2: i-04cc9b51b45291988 (t3.medium spot, 3.144.209.155) — needs cloud-init fix or teardown
- SG: sg-0a21cd8d514293389 (v1-lab-sg)
- Key: v1-lab-key (config/v1-lab-key.pem)
