"""
v1_overlay.py — Injects analysis results into V1 console DOM via Blueprint MCP.
Adds tooltips/badges next to CVE rows with exploitability assessment and resolution steps.
"""


def build_overlay_js(cve_analyses):
    """Build JavaScript that injects analysis overlays into V1 vulnerability table.

    cve_analyses: list of {cve, action, steps} dicts from Claude analysis.
    """
    # Escape for JS string embedding
    analysis_map = {}
    for a in cve_analyses:
        analysis_map[a["cve"]] = {
            "action": a.get("action", ""),
            "steps": a.get("steps", ""),
        }

    import json as _json
    analysis_json = _json.dumps(analysis_map).replace("'", "\\'").replace("\\n", "\\\\n")

    js_template = """
(function() {
    const analyses = JSON.parse('ANALYSIS_PLACEHOLDER');

    // Find all CVE links/text in the page
    const allElements = document.querySelectorAll('a, td, span');
    let injected = 0;

    for (const el of allElements) {
        const text = el.textContent.trim();
        const cveMatch = text.match(/^CVE-\\d{4}-\\d+$/);
        if (!cveMatch) continue;

        const cve = cveMatch[0];
        const analysis = analyses[cve];
        if (!analysis) continue;

        // Skip if already injected
        if (el.dataset.v1helper) continue;
        el.dataset.v1helper = 'true';

        // Create overlay badge
        const badge = document.createElement('span');
        badge.style.cssText = 'display:inline-block;margin-left:8px;padding:2px 6px;background:#1a1a2e;border:1px solid #333;border-radius:4px;font-size:11px;color:#e0e0e0;cursor:pointer;max-width:300px;';
        badge.textContent = '[analysis] ' + analysis.action.substring(0, 60);
        badge.title = analysis.action + '\\n\\n' + analysis.steps;

        // Click to show full analysis
        badge.addEventListener('click', function(e) {
            e.stopPropagation();
            const existing = document.getElementById('v1helper-detail-' + cve);
            if (existing) { existing.remove(); return; }

            const detail = document.createElement('div');
            detail.id = 'v1helper-detail-' + cve;
            detail.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#0a0a0a;border:1px solid #444;border-radius:8px;padding:16px;max-width:600px;max-height:80vh;overflow-y:auto;z-index:99999;color:white;font-size:13px;line-height:1.6;box-shadow:0 4px 20px rgba(0,0,0,0.8);';

            detail.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:8px;"><b>' + cve + '</b><span style="cursor:pointer;color:#888;" onclick="this.parentElement.parentElement.remove()">\\u2715</span></div>'
                + '<div style="margin-bottom:8px;"><b>' + analysis.action.replace(/</g,'&lt;') + '</b></div>'
                + '<div style="white-space:pre-wrap;color:#ccc;">' + analysis.steps.replace(/</g,'&lt;').replace(/\\\\n/g,'\\n') + '</div>';

            document.body.appendChild(detail);
        });

        el.parentElement.insertBefore(badge, el.nextSibling);
        injected++;
    }
    return injected + ' overlays injected';
})()
"""
    return js_template.replace("ANALYSIS_PLACEHOLDER", analysis_json)


def build_remove_overlay_js():
    """JavaScript to remove all v1-helper overlays from the page."""
    return """
(function() {
    document.querySelectorAll('[data-v1helper]').forEach(el => {
        const badge = el.nextSibling;
        if (badge && badge.dataset && badge.textContent.startsWith('🔍')) {
            badge.remove();
        }
        delete el.dataset.v1helper;
    });
    document.querySelectorAll('[id^="v1helper-detail-"]').forEach(el => el.remove());
    return 'overlays removed';
})()
"""
