# V1 Helper — Brainstorming

## Architecture Decisions Needed

### Extension: Strip the MCP bridge code
The extension was forked from Blueprint Extra MCP. It still has WebSocket connection code, tab handlers, network tracking, dialog handling, console forwarding — all duplicating what Blueprint already does.

**Decision:** Remove all MCP bridge code from the extension. Keep only:
- CVE overlay injection (content script)
- Popup UI (import analysis, view CVEs, settings)
- Storage management (chrome.storage.local)
- SPA navigation watcher (re-inject overlays on V1 route changes)

This makes the extension ~80% smaller, easier to maintain, and eliminates the Playwright dependency entirely.

### Extension: How to load analysis data
Current options:
1. **Manual import** — click "Import analysis.json" in popup, select file (works now)
2. **Auto-sync from reports/** — extension watches a local file path (File System Access API, requires user permission)
3. **V1 API direct** — extension has its own API key, pulls CVE data and runs analysis locally (complex, needs Claude API key)
4. **Clipboard paste** — paste JSON into popup textarea (simple, no file access)

**Recommendation:** Keep manual import as primary. Add clipboard paste as convenience. Auto-sync is fragile. Direct API is over-engineering the extension.

### Blueprint MCP: How automation works with the extension
When Claude Code runs `automate triage`, the flow is:
1. Python generates action plan (which CVEs to dismiss/accept)
2. Claude Code opens Blueprint MCP browser
3. Blueprint navigates to V1, logs in, goes to Container Security
4. Blueprint clicks through CVEs, changes status
5. Extension overlays appear automatically (if loaded in same Chrome)

**Key insight:** The extension and Blueprint MCP don't need to communicate. They coexist in Chrome. Blueprint controls the page, extension decorates it.

But: Blueprint MCP launches its own browser (Playwright-backed). If the user has the extension in their Chrome but Blueprint launches a separate instance, the extension won't be there.

**Options:**
- a) Blueprint connects to user's running Chrome via CDP (--remote-debugging-port)
- b) Blueprint launches Chrome with extension pre-loaded (configure launch args)
- c) Accept the split: automation runs in Blueprint's browser (no overlays), manual browsing uses Chrome (with overlays)

Option (c) is simplest and probably correct. Automation doesn't need overlays — it reads analysis.json directly.

## Feature Ideas

### Extension
- [ ] **Inline dismiss/accept** — right-click CVE badge > "Dismiss in V1" (would need V1 API key in extension)
- [ ] **Badge summary bar** — fixed bar at top showing "47 relevant / 102 dismissed / 18 pending"
- [ ] **Export filtered CVEs** — "Copy 47 relevant CVE IDs" from the overlay view
- [ ] **Context editor in extension** — edit customer context directly, re-score relevance
- [ ] **Diff view** — show which badges changed since last import (new CVEs, resolved)
- [ ] **Extension-native analysis** — use V1 API key to pull CVEs, call Claude API for analysis, no CLI needed

### Reports
- [ ] **PDF export** — direct download without print dialog (WIP in worktree-pdf-export)
- [ ] **Executive summary** — one-page view for management (just counts + critical items)
- [ ] **Multi-cluster comparison** — side-by-side view of two clusters
- [ ] **Trend lines** — CVE count over time from historical reports
- [ ] **Slack/Teams integration** — post report summary to channel
- [ ] **Scheduled reports** — cron job that generates and emails weekly report

### Automation
- [ ] **Accept with reason** — when accepting CVEs, attach analysis as justification
- [ ] **Undo triage** — revert a batch dismiss/accept
- [ ] **Policy sync** — auto-create V1 exception policies for dismissed CVEs
- [ ] **Cross-customer rollup** — "CVE-2024-1234 affects 3 of your 5 customers"

### Lab / Testing
- [ ] **Lab cluster** — EC2 + microk8s + V1 Container Security for generating real CVE data
- [ ] **Synthetic events** — deploy intentionally vulnerable pods, generate XDR telemetry
- [ ] **Extension E2E test** — load extension in Chrome, navigate to V1, verify overlays appear

## Technical Debt

- [ ] Extension still has Blueprint MCP code (WebSocket, tab handlers, etc.) — needs cleanup
- [ ] `launch-extension.js` and `load-analysis.js` use Playwright — should be removed or rewritten
- [ ] `extension-load.spec.js` tests use Playwright — need an alternative test strategy
- [ ] Duplicate icon sets in `extension/icons/` and `extension/chrome/icons/`
- [ ] `v1_actions.py` is deprecated but still exists
- [ ] MCP status display in popup is meaningless without MCP bridge code

## Open Questions

1. Should the extension be published to Chrome Web Store (unlisted) for easier installation?
2. Should the extension be able to run analysis itself (with Claude API key), making it fully standalone?
3. Is Blueprint MCP the right automation layer, or should we build custom automation using V1 API directly?
4. How do we handle enterprise Chrome policies that block developer mode extensions?
