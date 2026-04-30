"""
js.py — JavaScript payloads for V1 DOM interaction.

Each function returns a self-executing JS snippet that can be passed to
Blueprint MCP's browser_evaluate. All return JSON-serializable results.
"""


def find_cve_row(cve_id):
    """Find a CVE row in V1 vulnerability table. Returns {found, cve, rowIndex}."""
    return f"""
(function() {{
    const cells = document.querySelectorAll('td, span, a');
    for (const el of cells) {{
        if (el.textContent.trim() === '{cve_id}') {{
            const row = el.closest('tr');
            if (row) return {{ found: true, cve: '{cve_id}', rowIndex: row.rowIndex }};
        }}
    }}
    return {{ found: false, cve: '{cve_id}' }};
}})()
"""


def check_cve(cve_id):
    """Click checkbox on a CVE row. Returns {success, cve, error?}."""
    return f"""
(function() {{
    const cells = document.querySelectorAll('td, span, a');
    for (const el of cells) {{
        if (el.textContent.trim() === '{cve_id}') {{
            const row = el.closest('tr');
            if (!row) return {{ success: false, error: 'no row', cve: '{cve_id}' }};
            const cb = row.querySelector('input[type="checkbox"], .ant-checkbox-input, label.ant-checkbox-wrapper');
            if (!cb) return {{ success: false, error: 'no checkbox', cve: '{cve_id}' }};
            cb.click();
            return {{ success: true, cve: '{cve_id}' }};
        }}
    }}
    return {{ success: false, error: 'cve not found', cve: '{cve_id}' }};
}})()
"""


def click_status_dropdown():
    """Open the status change dropdown. Returns {success, action?, error?}."""
    return """
(function() {
    const buttons = document.querySelectorAll('button, .ant-btn');
    for (const btn of buttons) {
        const text = btn.textContent.trim().toLowerCase();
        if (text.includes('status') || text.includes('change status')) {
            btn.click();
            return { success: true, action: 'opened status dropdown' };
        }
    }
    return { success: false, error: 'status button not found' };
})()
"""


def select_status(status):
    """Select a status option from opened dropdown. Returns {success, selected?, error?}."""
    return f"""
(function() {{
    const options = document.querySelectorAll(
        '.ant-dropdown-menu-item, .ant-select-item, li[role="option"], .ant-menu-item'
    );
    for (const opt of options) {{
        if (opt.textContent.trim().toLowerCase().includes('{status.lower()}')) {{
            opt.click();
            return {{ success: true, selected: '{status}' }};
        }}
    }}
    return {{ success: false, error: 'option {status} not found', optionCount: options.length }};
}})()
"""


def click_confirm():
    """Click confirm/OK button in a modal dialog. Returns {success, clicked?, error?}."""
    return """
(function() {
    const btns = document.querySelectorAll('.ant-modal-footer button, .ant-btn-primary, button');
    for (const btn of btns) {
        const text = btn.textContent.trim().toLowerCase();
        if (text === 'ok' || text === 'confirm' || text === 'yes' || text === 'apply') {
            btn.click();
            return { success: true, clicked: text };
        }
    }
    return { success: false, error: 'no confirm button found' };
})()
"""


def get_page_state():
    """Read current V1 page state. Returns {page, selectedCount, visibleCVEs, rowCount}."""
    return """
(function() {
    const hash = window.location.hash;
    const selectedCount = document.querySelectorAll(
        'input[type="checkbox"]:checked, .ant-checkbox-checked'
    ).length;
    const rows = document.querySelectorAll('.ant-table-tbody tr.ant-table-row');
    const cves = [];
    rows.forEach(r => {
        const m = r.textContent.match(/CVE-\\d{4}-\\d+/);
        if (m) cves.push(m[0]);
    });
    return {
        page: hash,
        selectedCount: selectedCount,
        visibleCVEs: cves,
        rowCount: rows.length
    };
})()
"""


def search_cve(cve_id):
    """Type CVE ID into the V1 search/filter box. Returns {success, searched?, error?}."""
    return f"""
(function() {{
    const inputs = document.querySelectorAll(
        'input[type="text"], input[type="search"], .ant-input, input[placeholder*="search" i], input[placeholder*="filter" i]'
    );
    for (const inp of inputs) {{
        inp.focus();
        inp.value = '{cve_id}';
        inp.dispatchEvent(new Event('input', {{ bubbles: true }}));
        inp.dispatchEvent(new Event('change', {{ bubbles: true }}));
        inp.dispatchEvent(new KeyboardEvent('keydown', {{ key: 'Enter', code: 'Enter', bubbles: true }}));
        return {{ success: true, searched: '{cve_id}' }};
    }}
    return {{ success: false, error: 'no search input found' }};
}})()
"""


def clear_search():
    """Clear the search/filter box. Returns {success}."""
    return """
(function() {
    const inputs = document.querySelectorAll(
        'input[type="text"], input[type="search"], .ant-input, input[placeholder*="search" i], input[placeholder*="filter" i]'
    );
    for (const inp of inputs) {
        inp.focus();
        inp.value = '';
        inp.dispatchEvent(new Event('input', { bubbles: true }));
        inp.dispatchEvent(new Event('change', { bubbles: true }));
        return { success: true };
    }
    return { success: false, error: 'no search input found' };
})()
"""


def scroll_to_bottom():
    """Scroll the vulnerability table to load more rows (virtual scroll). Returns {scrolled, rowCount}."""
    return """
(function() {
    const container = document.querySelector('.ant-table-body') || document.querySelector('.ant-table-content');
    if (container) {
        container.scrollTop = container.scrollHeight;
        const rows = document.querySelectorAll('.ant-table-tbody tr.ant-table-row');
        return { scrolled: true, rowCount: rows.length };
    }
    return { scrolled: false, error: 'no table container found' };
})()
"""
