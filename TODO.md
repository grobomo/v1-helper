# v1-helper TODO

## Phase 0: Blueprint Stability — PARTIALLY DONE
- [x] Relay auto-reconnect with exponential backoff (relayClient.js)
- [x] Keepalive ping on both relay client and primary server side
- [x] Command retry in RelayTransport (3 retries with reconnect wait)
- [x] Relay-first as default mode in statefulBackend.js
- [ ] V1 session expires during automation (incognito lab) — need non-incognito session for stable testing
- [ ] Screenshot operation detaches extension on heavy V1 pages — investigate Chrome extension service worker lifecycle
- [ ] Test relay stability across two concurrent Claude sessions

## Phase 0.5: Overlay Injection — PROVEN
- [x] Successfully injected 20 "AI" badges next to CVE IDs in V1 iframe DOM
- [x] Confirmed V1 CVE data lives in iframe[0].contentDocument (same origin, accessible)
- [x] JS injection via browser_evaluate works for reading AND writing V1 DOM
- [ ] Add real analysis text to badges (not just "AI" placeholder)
- [ ] Add click handler for full analysis popup
- [ ] Handle V1 SPA navigation (re-inject when page changes)

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
