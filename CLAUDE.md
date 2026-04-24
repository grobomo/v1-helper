# v1-helper

Container security report generator for Trend Vision One. Pulls V1 API data, analyzes CVEs and runtime events with Claude, generates self-contained HTML reports with interactive features.

## Quick Start

```bash
# Run report for a customer (first run auto-creates config + context)
python scripts/report_generator.py --customer ep

# Use cached V1 data (skip API calls, faster iteration)
python scripts/report_generator.py --customer ep --cached reports/ep-raw-data.json

# Skip Claude LLM analysis (use existing analysis.json)
python scripts/report_generator.py --customer ep --cached reports/ep-raw-data.json --skip-llm
```

## How It Works

### Report Generation Flow

```
1. Load customer config        customers/<name>.json (API key name, region)
2. Pull V1 data                Clusters, vulns, image occurrences, eval/sensor events
3. Cache raw data              reports/<customer>-raw-data.json
4. Enrich with K8s context     Map CVEs to namespaces, deployments, containers, labels
5. Load/run CVE analysis       reports/analysis.json (cached) or Claude API (fresh)
6. Generate relevance          Compare analysis against customers/<name>.md context
7. Run XDR queries             Container activity search for runtime events
8. Write HTML report           reports/<customer>_Container_Security_<date>.html
9. Auto-open in browser
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
│   ├── report_generator.py       # Main report generator
│   ├── executor.py               # V1 page orchestrator (Blueprint MCP)
│   ├── v1_api.py                 # V1 REST API wrapper
│   ├── v1_reader.py              # V1 DOM reader via Blueprint
│   ├── v1_overlay.py             # V1 DOM overlay injection
│   └── v1_actions.py             # V1 action automation
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

## Git / GitHub

- Account: grobomo (public, generic tool)
- No customer data, no PII, no API keys in the repo
- `customers/` and `reports/` are gitignored
