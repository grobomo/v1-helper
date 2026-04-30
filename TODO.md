# v1-helper TODO

## Session Handoff
T035 (PDF export), T032 (cloud-init fix), T036 (exec summary) done. 94/94 tests via `npm test`.
Unified test runner, auto-archiving of raw data for future trends.
Phase 2 blocked on V1 login password (T009). T037 needs accumulated snapshots (auto-archive now in place).
Remaining unblocked: T033/T034 (lab cluster), T037 (needs data), T038 (blocked by V1 API).

## Phase 1: Clean Architecture (DONE)
- [x] T019: Remove MCP bridge code (1932-line background script -> 67 lines)
- [x] T020: Archive Playwright scripts (launch-extension.js, load-analysis.js, tests)
- [x] T021: Clean popup (remove MCP status, port, stealth mode)
- [x] T022: Archive duplicate icon sets + MCP status icons
- [x] T023: Archive deprecated v1_actions.py
- [x] T024: Chrome developer mode install instructions (extension/INSTALL.md)
- [x] T025: 48-point validation tests without Playwright (tests/extension-validate.js)

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
- [x] T032: Fix cloud-init user data encoding — file:// instead of base64 pipe (12-point test)
- [ ] T033: Install V1 Container Security on lab cluster
- [ ] T034: Deploy test workloads, generate CVEs and sensor events

## Phase 5: Reports Polish (lowest priority)
- [x] T035: PDF export — html2pdf.js with CDN on-demand load, print fallback (20-point test)
- [x] T036: Executive summary — stat grid + relevance table at top of report (10-point test)
- [ ] T037: Historic trend analysis (auto-archive in place, needs accumulated snapshots)
- [ ] T038: K8s labels in image grouping (blocked by V1 API)

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

### AWS resources (no instances running)
- SG: sg-0a21cd8d514293389 (v1-lab-sg) — kept for next provision
- Key: v1-lab-key — kept in AWS, local .pem in config/
