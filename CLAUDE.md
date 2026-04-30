# v1-helper

Vision One container security toolkit. Two sub-modules:
- **Reports** — Pull V1 API data, analyze CVEs with Claude, generate interactive HTML reports
- **Automate** — V1 console automation via Blueprint MCP action plans (dismiss CVEs, inject overlays, scrape pages)

## Quick Start

```bash
# --- Reports ---
# Run report for a customer (first run auto-creates config + context)
python scripts/report_generator.py --customer ep

# Use cached V1 data (skip API calls, faster iteration)
python scripts/report_generator.py --customer ep --cached reports/ep-raw-data.json

# Skip Claude LLM analysis (use existing analysis.json)
python scripts/report_generator.py --customer ep --cached reports/ep-raw-data.json --skip-llm

# Compare against previous run (diff section in report)
python scripts/report_generator.py --customer ep --cached reports/ep-raw-data.json --prev reports/ep-prev-data.json --skip-llm

# --- Automation ---
# Generate a plan to dismiss specific CVEs in V1 console
python scripts/executor.py automate dismiss CVE-2024-1234 CVE-2024-5678

# Auto-dismiss all non-relevant CVEs from analysis
python scripts/executor.py automate auto-dismiss

# Inject analysis overlays into V1 vulnerability page
python scripts/executor.py automate overlay

# Scrape V1 page data
python scripts/executor.py automate read vuln_mgmt
```

## How It Works

### Report Generation Flow

```
1. Load customer config        customers/<name>.json (API key name, region)
2. Load previous raw data      For diff comparison (auto on fresh runs, --prev on cached)
3. Pull V1 data                Clusters, vulns, image occurrences, eval/sensor events
4. Cache raw data              reports/<customer>-raw-data.json
5. Enrich with K8s context     Map CVEs to namespaces, deployments, containers, labels
6. Compute diff                New/resolved/changed CVEs vs previous run
7. Load/run CVE analysis       reports/<customer>-analysis.json (cached) or Claude API
8. Generate relevance          Compare analysis against customers/<name>.md context
9. Run XDR queries             Container activity search for runtime events
10. Write HTML report          reports/<customer>_Container_Security_<date>.html
11. Auto-open in browser
```

### Analysis Flow (two-pass)

**Pass 1 — CVE Analysis** (cached in `reports/analysis.json`):
- What is this vulnerability? Technical details, affected function, impact type.
- Generic and factual — same analysis works across customers.
- Done by Claude (this session or API) once, reused across runs.

**Pass 2 — Relevance** (generated fresh every run from `customers/<name>.md`):
- Does this CVE matter in THIS customer's environment?
- Reads customer context: runtime packages, managed K8s type, workload descriptions.
- Updates automatically when customer context changes — no re-analysis needed.

### Customer Setup

Each customer gets two files in `customers/`:

**`<name>.json`** — API config (auto-created on first run):
```json
{
  "api_key_name": "v1-api/EP_API_KEY",
  "region": "us-east-1"
}
```

**`<name>.md`** — Environment context (auto-generated from V1 API, then edited):
- Clusters, orchestrator, nodes, registries, images, namespaces, workloads
- What packages are used at runtime vs transitive deps
- TODO prompts for what only the customer knows

### Adding a New Customer

```bash
# 1. Store their V1 API key
python ~/.claude/skills/credential-manager/store_gui.py "v1-api/ACME_API_KEY"

# 2. Run the report (auto-creates customers/acme.json + customers/acme.md)
python scripts/report_generator.py --customer acme

# 3. Review and edit customers/acme.md with customer-specific context

# 4. Re-run for updated relevance analysis
python scripts/report_generator.py --customer acme --cached reports/acme-raw-data.json --skip-llm
```

## Report Features

- **Critical Findings** — clickable jump links to high-severity, high-relevance items
- **CVE Analysis** — per-CVE reasoning with relevance section tied to customer context
- **Runtime Event Analysis** — MITRE ATT&CK mapping, command-specific analysis
- **XDR Queries** — copy-pasteable curl commands with proper headers
- **Raw Event Data** — collapsible JSON + API reference per event
- **Collapsible Sections** — sidebar bar with Expand label, auto-scroll on collapse
- **Dark/Light Mode** — toggle with smooth transitions, persists in localStorage
- **Sticky Toolbar** — font size controls, CSV/PDF export, theme toggle
- **Sticky Table Headers** — column headers follow you while scrolling
- **Red Border** — highlights critical items needing action
- **Environment Context Editor** — inline edit + save to disk via File System Access API
- **Self-Contained HTML** — single file, no dependencies, shareable via email

## Project Structure

```
v1-helper/
├── CLAUDE.md                     # This file
├── TODO.md                       # Roadmap
├── .gitignore
├── .github/
│   ├── publish.json              # grobomo account config
│   └── workflows/
│       └── secret-scan.yml       # CI secret scanning
├── scripts/
│   ├── report_generator.py       # Container security HTML report generator
│   ├── gen_oat_report.py         # OAT detection HTML report generator
│   ├── executor.py               # Unified CLI (report + automate sub-commands)
│   ├── v1_api.py                 # V1 REST API wrapper
│   ├── v1_reader.py              # V1 DOM reader via Blueprint
│   ├── v1_overlay.py             # V1 DOM overlay injection
│   ├── v1_actions.py             # (deprecated, redirects to automate/)
│   ├── verify_dod_events.py      # DoD SIEM event verification
│   └── automate/                 # V1 console automation sub-module
│       ├── __init__.py           # Package exports
│       ├── actions.py            # Action plan builders (dismiss, accept, overlay)
│       └── js.py                 # JavaScript payloads for V1 DOM interaction
├── customers/                    # Per-customer config + context (gitignored)
│   ├── demo.json                 # API key name + region
│   ├── demo.md                   # Environment context
│   ├── ep.json
│   └── ep.md
└── reports/                      # Generated reports + cached data (gitignored)
    ├── analysis.json             # Cached CVE analysis (shared across customers)
    ├── demo-raw-data.json        # Cached V1 API responses
    ├── ep-raw-data.json
    └── ep_Container_Security_2026-03-25.html
```

## V1 API Endpoints Used

| Data | Endpoint |
|------|----------|
| Clusters | `/v3.0/containerSecurity/kubernetesClusters` |
| Vulnerabilities | `/v3.0/containerSecurity/vulnerabilities` |
| Image Occurrences | `/v3.0/containerSecurity/kubernetesImageOccurrences` |
| Eval Events | `/v3.0/containerSecurity/kubernetesEvaluationEventLogs` |
| Sensor Events | `/v3.0/containerSecurity/kubernetesSensorEventLogs` |
| XDR Search | `/v3.0/search/containerActivities` (TMV1-Query header) |

## Browser Automation

- **NEVER use Playwright directly** (`mcp__playwright__*` tools). Always use Blueprint Extra MCP for browser automation.
- Playwright artifacts archived to `archive/.playwright-mcp/`

## V1 Console Automation (scripts/automate/)

Action plans are structured JSON sequences. Python generates the plan, Claude Code executes it step-by-step via Blueprint MCP.

### Architecture

```
Python (automate/actions.py)  -->  generates plan JSON (steps + JS payloads)
Claude Code                   -->  reads plan, calls Blueprint MCP per step
Blueprint MCP                 -->  controls browser (evaluate JS, click, snapshot)
```

### Plan step types

| Step | Blueprint MCP tool | Description |
|------|--------------------|-------------|
| `navigate` | `browser_navigate` | Go to a V1 SPA route |
| `evaluate` | `browser_evaluate` | Run JS in page, check result |
| `snapshot` | `browser_snapshot` | Verify page state visually |
| `wait` | (pause between calls) | Let V1 SPA update |

### How Claude Code executes a plan

1. `python scripts/executor.py automate auto-dismiss` generates plan JSON
2. Claude reads the plan steps
3. For each step, Claude calls the corresponding Blueprint MCP tool
4. If a step has `expect`, Claude checks the result and stops on failure
5. Final snapshot confirms the outcome

### Available automations

| Command | What it does |
|---------|-------------|
| `automate dismiss CVE-...` | Select CVEs, change status to dismissed |
| `automate accept CVE-...` | Select CVEs, change status to accepted |
| `automate auto-dismiss` | Dismiss all non-relevant CVEs from analysis.json |
| `automate overlay` | Inject analysis badges into V1 vulnerability page |
| `automate read [page]` | Navigate to V1 page and scrape data |

## Git / GitHub

- Account: grobomo (public, generic tool)
- No customer data, no PII, no API keys in the repo
- `customers/` and `reports/` are gitignored
