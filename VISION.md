# V1 Helper — Vision

## The Problem

Vision One Container Security shows hundreds of CVEs per cluster. For a security engineer managing multiple customers, the daily workflow is:

1. Open V1 console, stare at a wall of CVEs
2. Manually research each one — is this kernel-level? Does this customer even use the affected library at runtime?
3. Dismiss/accept CVEs one at a time through the UI
4. Write up findings for the customer (copy-paste, screenshots, spreadsheets)

This is slow, error-prone, and doesn't scale. A single cluster can have 200+ CVEs. Multiply by customers and it's unmanageable.

## The Solution

**V1 Helper makes V1 Container Security actionable.** AI analyzes each CVE against the customer's real environment and delivers results through three surfaces:

### 1. Chrome Extension — See it while you browse
Load the extension in Chrome. Navigate to V1 Container Security. Every CVE gets a color-coded badge:
- **Red (RELEVANT)** — affects runtime packages, needs action
- **Yellow (LOW)** — transitive dependency, monitor only
- **Green (NOT RELEVANT)** — kernel-only, wrong platform, or unreachable code

Click a badge for full analysis: what it is, why it matters (or doesn't) in this customer's environment, and what to do about it.

The extension works independently — no Claude Code session needed. Import analysis.json once, browse V1 with overlays until the next report cycle.

### 2. CLI Automation — Act on it in bulk
```bash
# Preview: what would be dismissed vs accepted vs flagged?
python scripts/executor.py --customer ep automate triage --dry-run

# Generate action plans for Blueprint MCP to execute
python scripts/executor.py --customer ep automate triage --save
```

Triage 200 CVEs in one command. Non-relevant CVEs get dismissed, low-risk get accepted, critical ones get flagged for human review.

### 3. HTML Reports — Share it with the customer
```bash
python scripts/report_generator.py --customer ep
```

Self-contained HTML report with:
- Per-CVE analysis and relevance reasoning
- Diff against last run (new, resolved, changed)
- Runtime event analysis with MITRE ATT&CK mapping
- V1 console deep links
- Dark/light mode, search, export

One file, no dependencies, shareable via email.

## Architecture Principles

### The extension is NOT a browser automation tool
The extension's job is **overlays and UX enhancement**. It shows analysis badges on V1 pages and provides a popup for managing analysis data.

Browser automation (navigating, clicking, dismissing CVEs) is handled by **Blueprint MCP**, which already exists and works. Claude Code talks to Blueprint MCP. Blueprint MCP controls the browser. The extension adds visual intelligence on top.

```
Claude Code ──> Blueprint MCP ──> Chrome (with V1 Helper extension loaded)
                                    │
                                    ├── Blueprint controls navigation, clicks, DOM
                                    └── Extension adds overlays, badges, detail panels
```

### The extension works without Claude Code
A user can:
1. Load extension in Chrome (developer mode)
2. Import analysis.json via the popup
3. Browse V1 with overlays — no automation, no WebSocket, no MCP

This is the primary use case for customers or colleagues who just want to see the analysis while browsing.

### Playwright is not part of the architecture
Playwright was used as a crutch to bypass enterprise Chrome extension policies. The extension is a standard Chrome extension that loads via `chrome://extensions` > Developer Mode > Load Unpacked. If enterprise policies block this, the fix is policy exceptions or enterprise deployment — not bundling a separate browser runtime.

### Analysis is the core value
The two-pass analysis system is the engine:
- **Pass 1 (CVE Analysis):** What is this vulnerability? Generic, cached, reusable across customers.
- **Pass 2 (Relevance):** Does it matter HERE? Fresh per customer, tied to their environment context.

Everything else — extension, reports, automation — is a delivery mechanism for this analysis.

## Who uses this

- **Security engineers** reviewing V1 Container Security for customers
- **Customer-facing teams** sharing findings via HTML reports
- **Anyone browsing V1** who wants CVEs color-coded by relevance

## What success looks like

- Open V1 Container Security → instantly see which CVEs matter
- Generate a customer report in 60 seconds, not 60 minutes
- Triage 200 CVEs in one command, not 200 clicks
- New customer onboarded with one API key and one report run
