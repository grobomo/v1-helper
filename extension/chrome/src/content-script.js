/**
 * V1 Helper content script
 * - Forwards console messages from injected script to background
 * - Watches for focus requests from MCP server
 * - Detects tech stack
 * - Injects CVE analysis overlays on V1 console vulnerability pages
 */

// Guard against multiple content script executions
if (!window.__v1HelperContentScriptLoaded) {
  window.__v1HelperContentScriptLoaded = true;

  // Forward console messages from injected script to background
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data && event.data.__v1hConsole) {
      const message = event.data.__v1hConsole;
      chrome.runtime.sendMessage({
        type: 'console',
        level: message.level,
        text: message.text,
        timestamp: message.timestamp
      }).catch(() => {});
    }
  });

  // Watch for focus requests from MCP server
  const focusObserver = new MutationObserver(() => {
    const focusElement = document.querySelector('.mcp-extension-focus-tab');
    if (focusElement) {
      chrome.runtime.sendMessage({ type: 'focusTab' }).catch(() => {});
    }
  });
  focusObserver.observe(document.documentElement, { childList: true, subtree: true });

  // ─── Tech Stack Detection ───

  function detectTechStack() {
    const stack = {
      frameworks: [], libraries: [], css: [], devTools: [],
      spa: false, autoReload: false, obfuscatedCSS: false
    };
    try {
      if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
          document.getElementById('root') || document.getElementById('react-root')) {
        stack.frameworks.push('React'); stack.spa = true;
      }
      if (window.Vue || window.__VUE__ || window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {
        stack.frameworks.push('Vue'); stack.spa = true;
      }
      if (window.ng || typeof window.getAllAngularRootElements === 'function') {
        stack.frameworks.push('Angular'); stack.spa = true;
      }
      if (window.__NEXT_DATA__) { stack.frameworks.push('Next.js'); stack.spa = true; }
      if (document.querySelector('[class^="ant-"], [class*=" ant-"]')) stack.css.push('Ant Design');
      if (window.jQuery || window.$) stack.libraries.push('jQuery');
    } catch (e) {
      console.error('[V1 Helper] Tech stack detection error:', e);
    }
    return stack;
  }

  async function sendTechStackDetection() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'isStealthMode' });
      if (response?.isStealthMode) return;
    } catch { /* proceed */ }
    const stack = detectTechStack();
    chrome.runtime.sendMessage({
      type: 'techStackDetected', stack, url: window.location.href
    }).catch(() => {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(sendTechStackDetection, 100));
  } else {
    setTimeout(sendTechStackDetection, 100);
  }

  // ─── CVE Overlay Injection ───

  const V1_URL_PATTERNS = [
    /trendmicro\.com.*container.?security.*vulnerabilit/i,
    /trendmicro\.com.*#\/app\/container/i,
    /trendmicro\.com.*containerSecurity/i,
  ];

  function isV1VulnPage() {
    const url = window.location.href + window.location.hash;
    return V1_URL_PATTERNS.some(p => p.test(url));
  }

  const RELEVANCE_COLORS = {
    yes:  { bg: '#fef2f2', border: '#dc2626', text: '#991b1b', label: 'RELEVANT' },
    low:  { bg: '#fefce8', border: '#ca8a04', text: '#854d0e', label: 'LOW' },
    no:   { bg: '#f0fdf4', border: '#16a34a', text: '#166534', label: 'NOT RELEVANT' },
  };

  function getRelevanceStyle(relevant) {
    const key = (relevant || '').toLowerCase();
    return RELEVANCE_COLORS[key] || { bg: '#f3f4f6', border: '#9ca3af', text: '#4b5563', label: relevant || '?' };
  }

  let analysisCache = null;
  let overlayEnabled = true;
  let overlayObserver = null;

  async function loadAnalysisData() {
    try {
      const { v1h_analysis, v1h_overlay_enabled } = await chrome.storage.local.get([
        'v1h_analysis', 'v1h_overlay_enabled'
      ]);
      analysisCache = v1h_analysis || null;
      overlayEnabled = v1h_overlay_enabled !== false;
    } catch (e) {
      console.error('[V1 Helper] Failed to load analysis:', e);
    }
  }

  function createBadge(cve, analysis) {
    const style = getRelevanceStyle(analysis.relevant);
    const badge = document.createElement('span');
    badge.className = 'v1h-badge';
    badge.dataset.v1hCve = cve;
    badge.style.cssText = `
      display:inline-flex; align-items:center; gap:4px;
      margin-left:8px; padding:2px 8px;
      background:${style.bg}; border:1px solid ${style.border};
      border-radius:12px; font-size:11px; font-weight:600;
      color:${style.text}; cursor:pointer; white-space:nowrap;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      transition:opacity 0.15s;
    `;
    badge.textContent = style.label;
    badge.title = `${cve}: ${analysis.summary || analysis.action || ''}`;

    badge.addEventListener('mouseenter', () => { badge.style.opacity = '0.8'; });
    badge.addEventListener('mouseleave', () => { badge.style.opacity = '1'; });
    badge.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      showDetailPanel(cve, analysis);
    });

    return badge;
  }

  function showDetailPanel(cve, analysis) {
    // Remove existing panel
    const existing = document.getElementById('v1h-detail');
    if (existing) existing.remove();

    const style = getRelevanceStyle(analysis.relevant);
    const panel = document.createElement('div');
    panel.id = 'v1h-detail';
    panel.style.cssText = `
      position:fixed; top:50%; left:50%; transform:translate(-50%,-50%);
      background:white; border:2px solid ${style.border}; border-radius:12px;
      padding:0; max-width:640px; width:90vw; max-height:80vh;
      overflow:hidden; z-index:999999;
      box-shadow:0 20px 60px rgba(0,0,0,0.3);
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      font-size:14px; color:#1f2937; line-height:1.6;
    `;

    const header = `
      <div style="display:flex;justify-content:space-between;align-items:center;
        padding:16px 20px;background:${style.bg};border-bottom:1px solid ${style.border};">
        <div>
          <span style="font-weight:700;font-size:16px;color:${style.text};">${escHtml(cve)}</span>
          <span style="margin-left:10px;padding:2px 8px;background:${style.border};
            color:white;border-radius:10px;font-size:11px;font-weight:600;">
            ${escHtml(style.label)}
          </span>
        </div>
        <span id="v1h-detail-close" style="cursor:pointer;font-size:20px;color:#9ca3af;
          padding:4px 8px;border-radius:4px;">&times;</span>
      </div>
    `;

    const sections = [];

    if (analysis.summary || analysis.action) {
      sections.push(`
        <div style="margin-bottom:16px;">
          <div style="font-weight:600;color:#374151;margin-bottom:4px;">Summary</div>
          <div style="color:#4b5563;">${escHtml(analysis.summary || analysis.action)}</div>
        </div>
      `);
    }

    if (analysis.relevance_reasoning) {
      sections.push(`
        <div style="margin-bottom:16px;">
          <div style="font-weight:600;color:#374151;margin-bottom:4px;">Relevance</div>
          <div style="color:#4b5563;">${escHtml(analysis.relevance_reasoning)}</div>
        </div>
      `);
    }

    if (analysis.steps || analysis.remediation) {
      sections.push(`
        <div style="margin-bottom:16px;">
          <div style="font-weight:600;color:#374151;margin-bottom:4px;">Remediation</div>
          <div style="color:#4b5563;white-space:pre-wrap;">${escHtml(analysis.steps || analysis.remediation)}</div>
        </div>
      `);
    }

    if (analysis.cvss_score || analysis.severity) {
      sections.push(`
        <div style="margin-bottom:16px;">
          <div style="font-weight:600;color:#374151;margin-bottom:4px;">Severity</div>
          <div style="color:#4b5563;">
            ${analysis.cvss_score ? 'CVSS: ' + escHtml(String(analysis.cvss_score)) : ''}
            ${analysis.severity ? ' (' + escHtml(analysis.severity) + ')' : ''}
          </div>
        </div>
      `);
    }

    if (analysis.affected_component) {
      sections.push(`
        <div style="margin-bottom:16px;">
          <div style="font-weight:600;color:#374151;margin-bottom:4px;">Affected Component</div>
          <div style="color:#4b5563;">${escHtml(analysis.affected_component)}</div>
        </div>
      `);
    }

    panel.innerHTML = header + `
      <div style="padding:20px;overflow-y:auto;max-height:calc(80vh - 60px);">
        ${sections.join('')}
        ${sections.length === 0 ? '<div style="color:#9ca3af;">No analysis details available.</div>' : ''}
      </div>
    `;

    document.body.appendChild(panel);

    // Close handlers
    document.getElementById('v1h-detail-close').addEventListener('click', () => panel.remove());
    panel.addEventListener('keydown', (e) => { if (e.key === 'Escape') panel.remove(); });

    // Click outside to close
    const backdrop = document.createElement('div');
    backdrop.id = 'v1h-backdrop';
    backdrop.style.cssText = `
      position:fixed; top:0; left:0; right:0; bottom:0;
      background:rgba(0,0,0,0.3); z-index:999998;
    `;
    backdrop.addEventListener('click', () => {
      panel.remove();
      backdrop.remove();
    });
    document.body.insertBefore(backdrop, panel);
  }

  function escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function injectOverlays() {
    if (!analysisCache || !overlayEnabled) return 0;

    const analysisMap = analysisCache;
    const elements = document.querySelectorAll('td, span, a');
    let injected = 0;

    for (const el of elements) {
      const text = el.textContent.trim();
      const cveMatch = text.match(/^CVE-\d{4}-\d+$/);
      if (!cveMatch) continue;

      const cve = cveMatch[0];
      const analysis = analysisMap[cve];
      if (!analysis) continue;

      // Skip if already badged
      if (el.dataset.v1hOverlay) continue;
      el.dataset.v1hOverlay = 'true';

      const badge = createBadge(cve, analysis);
      el.parentElement.insertBefore(badge, el.nextSibling);
      injected++;
    }

    return injected;
  }

  function removeOverlays() {
    document.querySelectorAll('.v1h-badge').forEach(b => b.remove());
    document.querySelectorAll('[data-v1h-overlay]').forEach(el => {
      delete el.dataset.v1hOverlay;
    });
    const detail = document.getElementById('v1h-detail');
    if (detail) detail.remove();
    const backdrop = document.getElementById('v1h-backdrop');
    if (backdrop) backdrop.remove();
  }

  function startOverlayObserver() {
    if (overlayObserver) return;

    // Debounced injection on DOM changes
    let debounceTimer = null;
    overlayObserver = new MutationObserver(() => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (isV1VulnPage() && overlayEnabled) {
          injectOverlays();
        }
      }, 300);
    });

    overlayObserver.observe(document.body || document.documentElement, {
      childList: true, subtree: true
    });
  }

  function stopOverlayObserver() {
    if (overlayObserver) {
      overlayObserver.disconnect();
      overlayObserver = null;
    }
  }

  // Listen for storage changes (analysis data updated from popup)
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.v1h_analysis) {
      analysisCache = changes.v1h_analysis.newValue || null;
      removeOverlays();
      if (isV1VulnPage()) injectOverlays();
    }
    if (changes.v1h_overlay_enabled) {
      overlayEnabled = changes.v1h_overlay_enabled.newValue !== false;
      if (!overlayEnabled) {
        removeOverlays();
        stopOverlayObserver();
      } else if (isV1VulnPage()) {
        injectOverlays();
        startOverlayObserver();
      }
    }
  });

  // Listen for messages from popup/background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'v1h_injectOverlays') {
      loadAnalysisData().then(() => {
        removeOverlays();
        const count = injectOverlays();
        startOverlayObserver();
        return count;
      });
    }
    if (msg.type === 'v1h_removeOverlays') {
      removeOverlays();
      stopOverlayObserver();
    }
  });

  // ─── SPA Navigation Watcher ───

  let lastUrl = window.location.href;
  new MutationObserver(() => {
    const currentUrl = window.location.href;
    if (currentUrl !== lastUrl) {
      lastUrl = currentUrl;
      setTimeout(sendTechStackDetection, 200);

      // Re-check overlay on V1 SPA navigation
      if (isV1VulnPage() && overlayEnabled && analysisCache) {
        setTimeout(() => {
          removeOverlays();
          injectOverlays();
        }, 500);
      } else {
        removeOverlays();
        stopOverlayObserver();
      }
    }
  }).observe(document, { subtree: true, childList: true });

  window.addEventListener('popstate', () => setTimeout(sendTechStackDetection, 200));

  // ─── Initial Load ───

  async function init() {
    await loadAnalysisData();
    if (isV1VulnPage() && analysisCache && overlayEnabled) {
      // Wait for table to render
      setTimeout(() => {
        const count = injectOverlays();
        if (count > 0) console.log(`[V1 Helper] Injected ${count} CVE overlays`);
        startOverlayObserver();
      }, 1000);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}
