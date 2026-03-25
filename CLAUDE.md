# v1-helper

Claude Code skill that adds intelligent analysis to TrendAI Vision One console. NOT a standalone extension — uses Blueprint Extra MCP for all browser automation.

## What It Does

Runs inside V1 console pages. Reads vulnerability/detection data from the DOM and V1 API, sends it through Claude for environment-aware analysis, and presents results directly in the V1 UI — no separate report tab needed (but can open one for full detail).

## Architecture

v1-helper is a **Claude Code skill** that orchestrates:
- **Blueprint Extra MCP** for browser automation (click tracking, DOM reading, overlay injection, action automation)
- **V1 API** for data enrichment (vulnerabilities, clusters, image occurrences)
- **Claude analysis** (this session) for environment-aware CVE assessment

```
v1-helper/
├── CLAUDE.md                  # This file
├── SKILL.md                   # Skill definition for Claude Code
├── TODO.md                    # Task tracking
├── executor.py                # Main entry point — orchestrates everything
├── v1_reader.py               # Reads V1 page data via Blueprint MCP snapshot/evaluate
├── v1_overlay.py              # Injects analysis overlays via Blueprint MCP evaluate
├── v1_actions.py              # Automates V1 actions via Blueprint MCP interact/evaluate
├── v1_api.py                  # V1 REST API wrapper (uses credential store)
├── report_generator.py        # Generates HTML report (moved from recording-analyzer)
├── customer-context.md        # Customer-specific notes for analysis
└── .github/
    └── publish.json
```

### How It Works (no custom extension needed)

1. **Blueprint Extra MCP** is already installed as a Chrome extension with full DOM access
2. v1-helper calls Blueprint MCP tools via mcp-manager:
   - `browser_snapshot` — read V1 page DOM to find CVE rows
   - `browser_evaluate` — inject JS to read table data, add overlays/tooltips
   - `browser_interact` — click V1 UI elements for actions (dismiss, accept)
   - `browser_take_screenshot` — capture state
3. New Blueprint Extra tools needed (to be built):
   - `browser_track_interactions` — start/stop click+keypress recording with DOM path, screenshot, network capture
   - `browser_inject_overlay` — insert HTML elements into specific DOM locations on a page
   - `browser_click_sequence` — execute a series of clicks/waits for multi-step V1 actions

## How It Works

### Flow

1. User says "analyze V1 container security" or runs `python executor.py`
2. executor.py attaches to V1 tab via Blueprint MCP (`browser_tabs attach`)
3. v1_reader.py uses `browser_snapshot` + `browser_evaluate` to scrape CVE table data from V1 DOM
4. v1_api.py calls V1 REST API for enrichment data (image occurrences, cluster details)
5. Claude (this session) analyzes each finding with customer context
6. v1_overlay.py uses `browser_evaluate` to inject analysis tooltips directly into V1 page DOM
7. OR report_generator.py creates HTML report with "Take Action" buttons
8. v1_actions.py uses `browser_interact` + `browser_evaluate` to automate V1 actions (dismiss, accept)

### Blueprint Extra MCP Tools Used (existing)

- `browser_tabs` — list/attach to V1 tab
- `browser_snapshot` — read DOM tree
- `browser_evaluate` — execute JS in V1 page (read data, inject overlays)
- `browser_interact` — click elements
- `browser_take_screenshot` — capture state
- `browser_lookup` — find elements by text

### Blueprint Extra MCP Tools Needed (to build)

- `browser_track_interactions` — start/stop click+keypress recording. Each event captures: DOM path, element attributes, screenshot, network requests triggered. Generic feature useful across all projects.
- `browser_inject_overlay` — insert persistent HTML overlay at a specific DOM location. Survives SPA navigation. Generic.
- `browser_click_sequence` — execute multi-step click sequences with waits between steps. Generic.

## V1 Pages to Support

| Page | URL Pattern | What to Read | What to Overlay |
|------|-------------|-------------|-----------------|
| Vulnerability Management | `#/app/sase` | CVE table rows | Analysis per CVE |
| Container Inventory | `#/app/server-cloud/container-inventory` | Cluster/pod tree | Protection status notes |
| Code Security | `#/app/server-cloud/code-security` (or via nav) | CI/CD artifact scans | Scan result analysis |
| Cyber Risk Overview | `#/dashboard` | Risk index, risk factors | Prioritized actions |

## V1 API Endpoints Used

From background script (using session cookies):
- `/v3.0/containerSecurity/vulnerabilities` — CVE list with cluster/image context
- `/v3.0/containerSecurity/kubernetesClusters` — cluster metadata, nodes, pods
- `/v3.0/containerSecurity/kubernetesImageOccurrences` — namespace, resourceType, resourceName, containerName
- `/v3.0/containerSecurity/kubernetesEvaluationEventLogs` — policy violation events
- `/v3.0/containerSecurity/kubernetesSensorEventLogs` — runtime detections

## Customer Context

The extension loads `customer-context.json` which contains customer-specific notes that affect analysis:
- What runtime environment (containers on EKS, VMs, etc.)
- What packages are actually used vs transitive dependencies
- Known accepted risks
- Team structure (who handles what: dev team, SRE, security)

This file can be updated per-customer when switching between accounts in the XDR Support Portal.

## User Interaction Tracking

The extension records all clicks and keypresses in V1 to:
1. Identify repetitive workflows (e.g., 15 clicks to dismiss one CVE)
2. Surface automation opportunities (if user does X > Y > Z every time, offer a one-click shortcut)
3. Track time spent per V1 section for prioritization
4. Build a click heatmap showing where users spend most effort

### How It Works

- `content/v1-tracker.js` — listens for all click and keypress events on V1 pages
- Each event captures:
  - Timestamp
  - Full DOM path to clicked element (e.g., `body > div#App > section > div.ant-table > tbody > tr:nth-child(3) > td.cve-col > a`)
  - Element attributes: tag, id, classes, text content, aria-label, data-* attributes
  - Page URL hash (which V1 section)
  - Click coordinates
  - Screenshot of the visible viewport at moment of click (via `chrome.tabs.captureVisibleTab`)
  - Network requests triggered by the click (via `chrome.webRequest` listener — captures URL, method, status for requests fired within 2s after click)
- Background.js correlates: click event + screenshot + network requests into a single interaction record
- Stored in IndexedDB (chrome.storage.local is too small for screenshots) with daily rotation
- Extension popup shows: recent interactions with thumbnail screenshots, repetitive sequences, network-heavy clicks

### Privacy

- Only tracks on portal.xdr.trendmicro.com (V1 console)
- Does NOT capture form input values, passwords, or sensitive text content
- Captures element identifiers (button text, menu item names) for workflow analysis
- Data stays local in extension storage, never sent externally
- User can clear tracking data from popup

## Key Design Decisions

- **Overlays in V1 UI** — users stay in V1, analysis appears where they need it
- **Report tab as fallback** — for full detail and bulk actions
- **Report tab CAN automate V1** — because chrome.tabs.executeScript works from extension pages to content script tabs
- **Session cookies for API** — no separate API key management, uses existing V1 login
- **Claude analysis cached** — same CVE + same package + same context = same result, don't re-analyze

## Relationship to Blueprint Extra MCP

Click/keypress tracking and browser automation are **generic capabilities that belong in Blueprint Extra**, not in this project. v1-helper depends on Blueprint Extra and adds V1-specific wrappers.

### What lives in Blueprint Extra (generic, reusable across projects):
- Click/keypress event capture with full DOM path
- Screenshot on interaction
- Network request correlation
- IndexedDB storage with rotation
- Interaction replay/export
- DOM element targeting and clicking
- Page scraping utilities

### What lives in v1-helper (V1-specific):
- V1 page detection (which console section is active)
- V1 DOM selectors for CVE tables, container inventory, etc.
- V1 API wrappers using session cookies
- Claude analysis integration for V1 vulnerability data
- V1 action automation (dismiss/accept/remediate button sequences)
- Customer context management
- V1 overlay injection (tooltips, badges in V1 UI)

### Architecture change needed:
- Move `v1-tracker.js` generic tracking logic into Blueprint Extra extension
- Blueprint Extra exposes tracking data via MCP tools (e.g., `browser_get_interactions`, `browser_replay_click`)
- v1-helper content scripts call Blueprint Extra's tracking API instead of implementing their own
- v1-helper's background.js orchestrates V1-specific workflows using Blueprint Extra's generic browser automation

### TODO: Coordinate with Blueprint Extra
- [ ] Add interaction tracking to Blueprint Extra (click, keypress, DOM path, screenshot, network)
- [ ] Add MCP tools: `browser_get_interactions`, `browser_interaction_export`, `browser_replay_sequence`
- [ ] v1-helper depends on Blueprint Extra being installed
- [ ] v1-helper content scripts detect Blueprint Extra and use its tracking instead of own implementation

## Relationship to recording-analyzer

The `recording-analyzer` project handles meeting transcript analysis and the initial POC report generation. The `v1-helper` extension is the productized version of the container security report — instead of a standalone HTML file, it lives inside V1 itself.

The analysis logic (classifier.js, customer-context.json) is shared between both projects.

## Git / GitHub

- Account: grobomo (public, generic tool)
- No customer data, no PII, no internal infra details in the repo
- Customer context files are gitignored
