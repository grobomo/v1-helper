"""
v1_reader.py — Reads V1 console page data via Blueprint Extra MCP.
Detects which V1 page is active, scrapes relevant data from DOM.
"""

import json
import subprocess


def mcpm_call(server, tool, arguments=None):
    """Call a Blueprint Extra MCP tool via mcp-manager CLI."""
    # This would normally go through the MCP protocol.
    # For now, we use browser_evaluate to run JS in the V1 tab.
    # In practice, Claude Code calls these tools directly.
    pass


def detect_v1_page(snapshot_text):
    """Detect which V1 page is active from snapshot or URL hash."""
    if "container-inventory" in snapshot_text:
        return "container_inventory"
    elif "code-security" in snapshot_text or "CI/CD Artifacts" in snapshot_text:
        return "code_security"
    elif "/app/sase" in snapshot_text or "Vulnerabilities" in snapshot_text:
        return "vulnerability_management"
    elif "/dashboard" in snapshot_text:
        return "dashboard"
    return "unknown"


# JavaScript to inject into V1 page to scrape vulnerability table
SCRAPE_VULN_TABLE_JS = """
(function() {
    // Find the vulnerability table in V1 DOM
    // V1 uses Ant Design tables — look for ant-table-tbody rows
    const rows = document.querySelectorAll('.ant-table-tbody tr.ant-table-row');
    if (!rows.length) return JSON.stringify({error: 'No table rows found', page: window.location.hash});

    const results = [];
    for (const row of rows) {
        const cells = row.querySelectorAll('td');
        if (cells.length < 3) continue;

        // Extract text from each cell
        const cellTexts = Array.from(cells).map(c => c.textContent.trim());

        // Try to identify CVE IDs
        const cveMatch = row.textContent.match(/CVE-\\d{4}-\\d+/);

        results.push({
            cellTexts: cellTexts.slice(0, 10),
            cve: cveMatch ? cveMatch[0] : null,
            innerHTML: row.innerHTML.substring(0, 500),
        });
    }
    return JSON.stringify({count: results.length, rows: results, page: window.location.hash});
})()
"""

# JavaScript to scrape container inventory
SCRAPE_CONTAINER_INVENTORY_JS = """
(function() {
    // Container inventory uses a tree view
    // Look for cluster names, protection status, policies
    const iframe = document.querySelector('iframe');
    const doc = iframe ? iframe.contentDocument : document;
    if (!doc) return JSON.stringify({error: 'No document access'});

    const rows = doc.querySelectorAll('tr');
    const results = [];
    for (const row of rows) {
        const cells = row.querySelectorAll('td');
        if (cells.length < 3) continue;
        results.push({
            cells: Array.from(cells).map(c => c.textContent.trim().substring(0, 100)),
        });
    }
    return JSON.stringify({count: results.length, rows: results, page: window.location.hash});
})()
"""

# JavaScript to scrape code security CI/CD artifacts
SCRAPE_CODE_SECURITY_JS = """
(function() {
    const iframe = document.querySelector('iframe');
    const doc = iframe ? iframe.contentDocument : document;
    if (!doc) return JSON.stringify({error: 'No document access'});

    const rows = doc.querySelectorAll('tr');
    const results = [];
    for (const row of rows) {
        const cells = row.querySelectorAll('td');
        if (cells.length < 3) continue;
        results.push({
            cells: Array.from(cells).map(c => c.textContent.trim().substring(0, 100)),
        });
    }
    return JSON.stringify({count: results.length, rows: results, page: window.location.hash});
})()
"""


def get_scrape_js(page_type):
    """Return the right JS scraper for the detected page type."""
    return {
        "vulnerability_management": SCRAPE_VULN_TABLE_JS,
        "container_inventory": SCRAPE_CONTAINER_INVENTORY_JS,
        "code_security": SCRAPE_CODE_SECURITY_JS,
    }.get(page_type, SCRAPE_VULN_TABLE_JS)
