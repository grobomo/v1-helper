"""
v1_actions.py — Automates V1 console actions via Blueprint MCP.
Dismiss, accept, remediate CVEs by clicking through the V1 UI.
"""


def build_dismiss_cve_js(cve_id):
    """JavaScript to dismiss a specific CVE in V1 vulnerability management.
    Clicks: find CVE row > checkbox > status dropdown > dismiss > confirm.
    """
    return f"""
(function() {{
    // Step 1: Find the CVE row
    const allElements = document.querySelectorAll('td, span, a');
    let cveRow = null;
    for (const el of allElements) {{
        if (el.textContent.trim() === '{cve_id}') {{
            cveRow = el.closest('tr');
            break;
        }}
    }}
    if (!cveRow) return 'CVE {cve_id} not found in current view';

    // Step 2: Click checkbox
    const checkbox = cveRow.querySelector('input[type="checkbox"], .ant-checkbox-input, label.ant-checkbox-wrapper');
    if (checkbox) {{
        checkbox.click();
        return 'checked_' + '{cve_id}';
    }}
    return 'checkbox not found for {cve_id}';
}})()
"""


def build_change_status_js(status):
    """JavaScript to change status of checked CVEs.
    status: 'dismissed', 'accepted', 'inProgress', 'remediated'
    Call after build_dismiss_cve_js has checked the checkbox.
    """
    return f"""
(function() {{
    // Find and click the status change button/dropdown
    const buttons = document.querySelectorAll('button, .ant-btn');
    for (const btn of buttons) {{
        const text = btn.textContent.trim().toLowerCase();
        if (text.includes('status') || text.includes('change')) {{
            btn.click();
            // Wait for dropdown, then find the right option
            setTimeout(() => {{
                const options = document.querySelectorAll('.ant-dropdown-menu-item, .ant-select-item, li[role="option"]');
                for (const opt of options) {{
                    if (opt.textContent.trim().toLowerCase().includes('{status}')) {{
                        opt.click();
                        return;
                    }}
                }}
            }}, 500);
            return 'clicked status dropdown, selecting {status}';
        }}
    }}
    return 'status button not found';
}})()
"""


def build_bulk_action_sequence(cve_ids, status):
    """Build a sequence of JS snippets to bulk-change status for multiple CVEs.
    Returns list of (description, js_code) tuples to execute in order with waits.
    """
    steps = []
    for cve in cve_ids:
        steps.append((f"Select {cve}", build_dismiss_cve_js(cve)))

    steps.append((f"Change status to {status}", build_change_status_js(status)))
    return steps
