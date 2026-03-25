# v1-helper TODO

## Phase 1: Blueprint Extra MCP — Add Generic Tracking
These go into Blueprint Extra, not v1-helper. Reusable across all projects.
- [ ] `browser_track_interactions` tool — start/stop click+keypress recording
  - DOM path capture per event
  - Element attributes (tag, id, classes, text, aria, data-*)
  - Screenshot on each click (captureVisibleTab)
  - Network requests triggered within 2s window
  - Store in extension IndexedDB with daily rotation
- [ ] `browser_get_interactions` tool — retrieve recorded interactions
- [ ] `browser_inject_overlay` tool — insert HTML at specific DOM location, persist across SPA nav
- [ ] `browser_click_sequence` tool — multi-step click+wait automation

## Phase 2: V1 Reader (v1_reader.py)
- [ ] Detect current V1 page from URL hash via Blueprint snapshot
- [ ] Scrape vulnerability table rows via browser_evaluate
- [ ] Scrape container inventory tree
- [ ] Scrape code security CI/CD artifacts
- [ ] Pull enrichment data from V1 API (image occurrences, cluster details)

## Phase 3: Analysis + Overlay (v1_overlay.py)
- [ ] Claude analyzes each finding with customer context (this session does analysis)
- [ ] Inject analysis tooltips next to CVE rows in V1 DOM via browser_evaluate
- [ ] Expandable reasoning on hover/click
- [ ] customer-context.md for per-customer notes

## Phase 4: V1 Action Automation (v1_actions.py)
- [ ] Dismiss CVE — browser_click_sequence: checkbox > status dropdown > dismiss > confirm
- [ ] Accept CVE — same flow with accept
- [ ] Remediate — same flow
- [ ] Bulk actions
- [ ] Report HTML with buttons that trigger automation via Blueprint MCP

## Phase 5: Report Generator (report_generator.py)
- [ ] Move generate-report.py from recording-analyzer to v1-helper
- [ ] HTML report with V1 action buttons that call Blueprint MCP
- [ ] Customer context integration
