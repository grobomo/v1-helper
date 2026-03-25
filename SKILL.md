# V1 Helper

Intelligent analysis overlay for TrendAI Vision One console. Reads V1 vulnerability data from API and browser DOM, analyzes with Claude, injects results into V1 UI or generates actionable HTML report.

## Usage

```
# Analyze current V1 tab — read CVEs, enrich, analyze, inject overlays
python executor.py analyze

# Generate HTML report from V1 API data
python executor.py report

# Start interaction tracking on V1 tab
python executor.py track-start

# Export tracked interactions
python executor.py track-export
```

## Requires
- Blueprint Extra MCP (browser automation)
- mcp-manager
- V1 API key in credential store (v1-api/V1_API_KEY)
- Active V1 console session in browser
