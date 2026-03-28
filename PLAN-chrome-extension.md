# V1-Helper Chrome Extension — Consolidation Plan

## Goal
Combine Blueprint Extra MCP extension + V1EGO click tracking + V1-Helper analysis into a single Chrome extension called **V1-Helper**.

## Source Projects

| Source | What We Take | What We Drop |
|--------|-------------|-------------|
| **Blueprint Extra MCP** (`extensions/`) | Extension architecture, popup UI, content script, background module, connection handling, MCP relay | "Upgrade to Pro" banner, Blueprint branding/logos, Firefox support |
| **V1EGO** (`src/`) | Click event interception, DOM path capture, hover overlay, keyboard shortcuts | Email alert overlay (not needed for booth demo) |
| **V1-Helper** (`scripts/`) | Analysis/summary generation, V1 API integration, report templates | Python CLI (keep as separate tool, not in extension) |

## What V1-Helper Extension Does

1. **Blueprint MCP relay** — same browser automation capabilities as Blueprint Extra (all 30 tools work)
2. **Click tracking** — silently intercepts every click, logs DOM path + timestamp + element info
3. **Silent screenshots** — `chrome.tabs.captureVisibleTab()` on every click, no visual indication
4. **Session management** — start/stop recording tied to booth demo session (S3 polling)
5. **Periodic screenshots** — every N seconds as fallback (configurable)
6. **Batch upload** — collect click data + screenshots locally, upload to S3 when session ends
7. **Session banner** — small bar at top of page: "Session tracked — you'll receive a summary"

## Visual Changes

- **Logo:** Replace Blueprint logo with TrendAI logo (Trend spark icon)
- **Name:** "V1-Helper" in manifest and popup
- **Popup UI:** Same layout as Blueprint, remove "Upgrade to Pro" banner
- **Colors:** Keep dark theme, add Trend red accent (#D32F2F)

## Extension Structure (after merge)

```
extensions/
├── manifest.json                # MV3, name: "V1-Helper"
├── icons/                       # TrendAI logos (16, 32, 48, 128)
├── chrome/src/
│   ├── background-module.js     # Blueprint MCP relay (unchanged)
│   └── content-script.js        # Blueprint content script + click tracker + screenshot
├── shared/
│   ├── adapters/                # Blueprint adapters (unchanged)
│   ├── connection/              # Blueprint connection (unchanged)
│   ├── handlers/                # Blueprint handlers (unchanged)
│   ├── popup/                   # Blueprint popup (remove Pro banner, rebrand)
│   └── utils/                   # Blueprint utils (unchanged)
├── booth/                       # NEW: booth demo features
│   ├── click-tracker.js         # Click interception + DOM path logging
│   ├── screenshot.js            # Silent captureVisibleTab on click
│   ├── session-poller.js        # Poll S3 for session start/stop
│   ├── uploader.js              # Batch upload to S3
│   └── banner.js                # "Session tracked" banner injection
```

## Implementation Steps

### Phase 1: Fork Blueprint extension into v1-helper
- [ ] Copy `blueprint-extra-mcp/extensions/` to `v1-helper/extension/`
- [ ] Update manifest.json: name, description, icons
- [ ] Remove "Upgrade to Pro" banner from popup
- [ ] Replace logos with TrendAI icons
- [ ] Verify Blueprint MCP relay still works after rename

### Phase 2: Add click tracking (from V1EGO)
- [ ] Extract click event listener from v1ego/src
- [ ] Adapt for general click tracking (not just V1 email alerts)
- [ ] Log: timestamp, DOM path, element tag/id/class, innerText preview, coordinates
- [ ] Store in memory buffer, flush periodically

### Phase 3: Add silent screenshots
- [ ] Add `chrome.tabs.captureVisibleTab()` call on each click event
- [ ] Compress to JPEG (quality 60) to save space
- [ ] Tag with timestamp + click index
- [ ] Store in IndexedDB or memory (batch, not per-click network calls)

### Phase 4: Add session management
- [ ] Session poller: check S3 for start/stop commands
- [ ] On session start: begin click tracking + screenshots
- [ ] On session end: batch upload everything to S3 session folder
- [ ] Inject "Session tracked" banner at top of page

### Phase 5: Integration test
- [ ] Blueprint MCP tools still work (all 30)
- [ ] Click tracking captures during normal V1 browsing
- [ ] Screenshots are silent (no flash, no delay, no UI artifacts)
- [ ] Session start/stop works via S3 polling
- [ ] Batch upload completes within 30s of session end
