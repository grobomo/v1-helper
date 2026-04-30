/**
 * V1 Helper — Popup script.
 * Manages CVE analysis data, overlay toggle, and V1 API settings.
 */

const browserAPI = typeof chrome !== 'undefined' ? chrome : browser;

let state = {
  enabled: true,
  showSettings: false,
  version: '0.2.0',
  // V1 API settings
  v1ApiKey: '',
  v1Region: 'us-east-1',
  v1CustomerContext: '',
  v1TestResult: null, // null | 'testing' | 'ok:msg' | 'error:msg'
  // V1 analysis state
  analysisCount: 0,
  analysisRelevant: 0,
  analysisLow: 0,
  analysisNo: 0,
  overlayEnabled: true,
  // CVE list view
  showCveList: false,
  cveFilter: 'all',
  cveEntries: [],
};

// --- State Management ---

async function loadState() {
  const storage = await browserAPI.storage.local.get([
    'extensionEnabled', 'v1h_overlay_enabled',
    'v1h_api_key', 'v1h_region', 'v1h_customer_context'
  ]);

  state.enabled = storage.extensionEnabled !== false;
  state.overlayEnabled = storage.v1h_overlay_enabled !== false;
  state.v1ApiKey = storage.v1h_api_key || '';
  state.v1Region = storage.v1h_region || 'us-east-1';
  state.v1CustomerContext = storage.v1h_customer_context || '';

  const manifest = browserAPI.runtime.getManifest();
  state.version = manifest.version;

  await loadAnalysisStats();
  render();
}

// --- V1 Analysis ---

async function loadAnalysisStats() {
  const { v1h_analysis } = await browserAPI.storage.local.get(['v1h_analysis']);
  const data = v1h_analysis || {};
  const entries = Array.isArray(data) ? data : Object.values(data);

  state.analysisCount = entries.length;
  state.analysisRelevant = 0;
  state.analysisLow = 0;
  state.analysisNo = 0;
  state.cveEntries = entries;

  for (const e of entries) {
    const r = (e.relevant || '').toLowerCase();
    if (r === 'yes') state.analysisRelevant++;
    else if (r === 'low') state.analysisLow++;
    else if (r === 'no') state.analysisNo++;
  }
}

async function importAnalysis(file) {
  try {
    const text = await file.text();
    const json = JSON.parse(text);

    let normalized;
    if (Array.isArray(json)) {
      normalized = {};
      for (const item of json) {
        if (item.cve) normalized[item.cve] = item;
      }
    } else {
      normalized = json;
    }

    await browserAPI.storage.local.set({ v1h_analysis: normalized });
    await loadAnalysisStats();
    render();
  } catch (err) {
    console.error('[V1 Helper] Import failed:', err);
  }
}

// --- Toggle ---

async function toggleEnabled() {
  state.enabled = !state.enabled;
  await browserAPI.storage.local.set({ extensionEnabled: state.enabled });
  render();
}

// --- Settings ---

async function saveSettings() {
  await browserAPI.storage.local.set({
    v1h_api_key: state.v1ApiKey,
    v1h_region: state.v1Region,
    v1h_customer_context: state.v1CustomerContext,
  });
  state.showSettings = false;
  state.v1TestResult = null;
  render();
}

async function cancelSettings() {
  const storage = await browserAPI.storage.local.get([
    'v1h_api_key', 'v1h_region', 'v1h_customer_context'
  ]);
  state.v1ApiKey = storage.v1h_api_key || '';
  state.v1Region = storage.v1h_region || 'us-east-1';
  state.v1CustomerContext = storage.v1h_customer_context || '';
  state.showSettings = false;
  state.v1TestResult = null;
  render();
}

const V1_REGIONS = {
  'us-east-1': { label: 'US (Virginia)', base: 'https://api.xdr.trendmicro.com' },
  'eu-central-1': { label: 'EU (Frankfurt)', base: 'https://api.eu.xdr.trendmicro.com' },
  'ap-southeast-1': { label: 'Asia Pacific (Singapore)', base: 'https://api.sg.xdr.trendmicro.com' },
  'ap-northeast-1': { label: 'Japan (Tokyo)', base: 'https://api.jp.xdr.trendmicro.com' },
  'ap-southeast-2': { label: 'Australia (Sydney)', base: 'https://api.au.xdr.trendmicro.com' },
};

async function testV1Connection() {
  if (!state.v1ApiKey) {
    state.v1TestResult = 'error:No API key entered';
    render();
    return;
  }
  state.v1TestResult = 'testing';
  render();
  try {
    const region = V1_REGIONS[state.v1Region] || V1_REGIONS['us-east-1'];
    const resp = await fetch(`${region.base}/v3.0/containerSecurity/kubernetesClusters?top=1`, {
      headers: { 'Authorization': `Bearer ${state.v1ApiKey}` }
    });
    if (resp.ok) {
      const data = await resp.json();
      const count = data.totalCount ?? data.items?.length ?? '?';
      state.v1TestResult = `ok:${count} clusters`;
    } else if (resp.status === 401 || resp.status === 403) {
      state.v1TestResult = 'error:Invalid API key or insufficient permissions';
    } else {
      state.v1TestResult = `error:HTTP ${resp.status}`;
    }
  } catch (err) {
    state.v1TestResult = `error:${err.message}`;
  }
  render();
}

// --- Render ---

function render() {
  const root = document.getElementById('root');
  if (!root) return;
  if (state.showCveList) {
    root.innerHTML = renderCveList();
  } else if (state.showSettings) {
    root.innerHTML = renderSettings();
  } else {
    root.innerHTML = renderMain();
  }
  attachEventListeners();
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function renderMain() {
  return `
    <div class="popup-container">
      <div class="popup-header">
        <img src="/icons/icon-32.png" alt="V1 Helper" class="header-icon" />
        <h1>V1 Helper<span class="version-label">v${state.version}</span></h1>
      </div>
      <div class="popup-content">
        <!-- CVE Analysis Section -->
        <div class="v1-section">
          <h3>CVE Analysis</h3>
          ${state.analysisCount > 0 ? `
            <div class="v1-stat"><span class="v1-stat-label">CVEs loaded</span><span class="v1-stat-value">${state.analysisCount}</span></div>
            <div class="v1-stat"><span class="v1-stat-label">Relevant</span><span class="v1-stat-value" style="color:#D71920">${state.analysisRelevant}</span></div>
            <div class="v1-stat"><span class="v1-stat-label">Low priority</span><span class="v1-stat-value" style="color:#856404">${state.analysisLow}</span></div>
            <div class="v1-stat"><span class="v1-stat-label">Not relevant</span><span class="v1-stat-value" style="color:#155724">${state.analysisNo}</span></div>
          ` : `
            <p style="font-size:12px;color:#666">No analysis loaded. Import analysis.json to see CVE overlays on V1 Container Security pages.</p>
          `}
          <div style="display:flex;gap:8px;margin-top:8px;">
            <button class="v1-import-btn" id="importAnalysisBtn" style="flex:1">Import analysis.json</button>
            ${state.analysisCount > 0 ? `
              <button class="v1-import-btn" id="viewCvesBtn" style="flex:1">View CVEs</button>
              <button class="v1-import-btn" id="injectOverlayBtn"
                style="flex:1;background:${state.overlayEnabled ? '#16a34a' : '#9ca3af'}"
                title="${state.overlayEnabled ? 'Overlays auto-inject on V1 pages' : 'Overlays disabled'}">
                ${state.overlayEnabled ? 'Overlays On' : 'Overlays Off'}
              </button>
            ` : ''}
          </div>
          <input type="file" id="analysisFileInput" class="v1-file-input" accept=".json" />
        </div>

        <div class="toggle-row">
          <button class="toggle-button ${state.enabled ? 'enabled' : 'disabled'}" id="toggleButton">
            ${state.enabled ? 'Disable' : 'Enable'}
          </button>
        </div>

        <div class="links-section">
          <button class="settings-link" id="settingsButton">Settings</button>
        </div>
      </div>
    </div>
  `;
}

function renderSettings() {
  const regionOptions = Object.entries(V1_REGIONS).map(([key, val]) =>
    `<option value="${key}" ${state.v1Region === key ? 'selected' : ''}>${val.label}</option>`
  ).join('');

  const maskedKey = state.v1ApiKey
    ? state.v1ApiKey.slice(0, 6) + '...' + state.v1ApiKey.slice(-4)
    : '';

  let testResultHtml = '';
  if (state.v1TestResult === 'testing') {
    testResultHtml = '<span class="settings-test testing">Testing...</span>';
  } else if (state.v1TestResult?.startsWith('ok:')) {
    testResultHtml = `<span class="settings-test ok">${esc(state.v1TestResult.slice(3))}</span>`;
  } else if (state.v1TestResult?.startsWith('error:')) {
    testResultHtml = `<span class="settings-test error">${esc(state.v1TestResult.slice(6))}</span>`;
  }

  return `
    <div class="popup-container">
      <div class="popup-header">
        <img src="/icons/icon-32.png" alt="V1 Helper" class="header-icon" />
        <h1>Settings<span class="version-label">v${state.version}</span></h1>
      </div>
      <div class="popup-content settings-scroll">
        <div class="settings-form">
          <div class="settings-section-title">Vision One API</div>
          <label class="settings-label">
            API Key:
            <div class="settings-key-row">
              <input type="password" class="settings-input" id="v1ApiKeyInput"
                value="${state.v1ApiKey}" placeholder="Paste V1 API key" autocomplete="off" />
              <button class="settings-eye" id="toggleKeyVisibility" title="Show/hide key">
                <span id="eyeIcon">&#128065;</span>
              </button>
            </div>
          </label>
          ${maskedKey ? `<p class="settings-help">Current: ${maskedKey}</p>` : ''}

          <label class="settings-label">
            Region:
            <select class="settings-input" id="v1RegionSelect">${regionOptions}</select>
          </label>

          <div class="settings-test-row">
            <button class="settings-button test" id="testConnectionBtn"
              ${state.v1TestResult === 'testing' ? 'disabled' : ''}>Test Connection</button>
            ${testResultHtml}
          </div>

          <div class="settings-divider"></div>
          <div class="settings-section-title">Customer Context</div>
          <label class="settings-label">
            <textarea class="settings-textarea" id="customerContextInput"
              placeholder="Describe the customer environment: managed K8s type, runtime packages, workload purposes..."
              rows="4">${esc(state.v1CustomerContext)}</textarea>
          </label>
          <p class="settings-help">Used for CVE relevance reasoning. Markdown supported.</p>
        </div>
        <div class="settings-actions">
          <button class="settings-button save" id="saveButton">Save</button>
          <button class="settings-button cancel" id="cancelButton">Cancel</button>
        </div>
      </div>
    </div>
  `;
}

function getFilteredCves() {
  if (state.cveFilter === 'all') return state.cveEntries;
  return state.cveEntries.filter(e => (e.relevant || '').toLowerCase() === state.cveFilter);
}

function renderCveList() {
  const filters = [
    { key: 'all', label: 'All', count: state.analysisCount },
    { key: 'yes', label: 'Relevant', count: state.analysisRelevant, color: '#dc2626' },
    { key: 'low', label: 'Low', count: state.analysisLow, color: '#ca8a04' },
    { key: 'no', label: 'None', count: state.analysisNo, color: '#16a34a' },
  ];

  const filtered = getFilteredCves();
  const relevanceColors = {
    yes: { bg: '#fef2f2', border: '#dc2626', text: '#991b1b', label: 'RELEVANT' },
    low: { bg: '#fefce8', border: '#ca8a04', text: '#854d0e', label: 'LOW' },
    no:  { bg: '#f0fdf4', border: '#16a34a', text: '#166534', label: 'NOT RELEVANT' },
  };

  const rows = filtered.map(e => {
    const r = (e.relevant || '').toLowerCase();
    const c = relevanceColors[r] || { bg: '#f3f4f6', border: '#9ca3af', text: '#4b5563', label: r || '?' };
    const summary = e.summary || e.action || '';
    const truncated = summary.length > 60 ? summary.slice(0, 57) + '...' : summary;
    return `
      <div class="cve-row">
        <div class="cve-row-top">
          <span class="cve-id">${esc(e.cve || '')}</span>
          <span class="cve-badge" style="background:${c.bg};border-color:${c.border};color:${c.text}">
            ${esc(c.label)}
          </span>
        </div>
        ${truncated ? `<div class="cve-summary">${esc(truncated)}</div>` : ''}
      </div>
    `;
  }).join('');

  return `
    <div class="popup-container">
      <div class="popup-header">
        <img src="/icons/icon-32.png" alt="V1 Helper" class="header-icon" />
        <h1>CVE Analysis<span class="version-label">${filtered.length} of ${state.analysisCount}</span></h1>
      </div>
      <div class="popup-content">
        <div class="cve-filters">
          ${filters.map(f => `
            <button class="cve-filter-btn ${state.cveFilter === f.key ? 'active' : ''}"
              data-filter="${f.key}"
              ${f.color && state.cveFilter === f.key ? `style="border-color:${f.color};color:${f.color}"` : ''}>
              ${f.label} (${f.count})
            </button>
          `).join('')}
        </div>
        <div class="cve-list" id="cveListContainer">
          ${filtered.length > 0 ? rows : '<div class="cve-empty">No CVEs match this filter.</div>'}
        </div>
        <div class="cve-actions">
          <button class="cve-action-btn" id="copyCveIdsBtn" ${filtered.length === 0 ? 'disabled' : ''}>
            Copy ${filtered.length} CVE ID${filtered.length !== 1 ? 's' : ''}
          </button>
          <button class="cve-action-btn secondary" id="cveBackBtn">Back</button>
        </div>
      </div>
    </div>
  `;
}

// --- Event Listeners ---

function attachEventListeners() {
  if (state.showCveList) {
    document.querySelectorAll('.cve-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.cveFilter = btn.dataset.filter;
        render();
      });
    });
    document.getElementById('copyCveIdsBtn')?.addEventListener('click', async () => {
      const ids = getFilteredCves().map(e => e.cve).filter(Boolean).join('\n');
      await navigator.clipboard.writeText(ids);
      const btn = document.getElementById('copyCveIdsBtn');
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1500);
      }
    });
    document.getElementById('cveBackBtn')?.addEventListener('click', () => {
      state.showCveList = false;
      render();
    });
    return;
  }
  if (state.showSettings) {
    document.getElementById('saveButton')?.addEventListener('click', saveSettings);
    document.getElementById('cancelButton')?.addEventListener('click', cancelSettings);
    document.getElementById('testConnectionBtn')?.addEventListener('click', testV1Connection);
    const apiKeyInput = document.getElementById('v1ApiKeyInput');
    if (apiKeyInput) apiKeyInput.addEventListener('input', (e) => { state.v1ApiKey = e.target.value; });
    const regionSelect = document.getElementById('v1RegionSelect');
    if (regionSelect) regionSelect.addEventListener('change', (e) => { state.v1Region = e.target.value; });
    const contextInput = document.getElementById('customerContextInput');
    if (contextInput) contextInput.addEventListener('input', (e) => { state.v1CustomerContext = e.target.value; });
    document.getElementById('toggleKeyVisibility')?.addEventListener('click', () => {
      const input = document.getElementById('v1ApiKeyInput');
      if (input) input.type = input.type === 'password' ? 'text' : 'password';
    });
  } else {
    document.getElementById('toggleButton')?.addEventListener('click', toggleEnabled);
    document.getElementById('settingsButton')?.addEventListener('click', () => {
      state.showSettings = true;
      render();
    });
    document.getElementById('viewCvesBtn')?.addEventListener('click', () => {
      state.showCveList = true;
      state.cveFilter = 'all';
      render();
    });
    document.getElementById('importAnalysisBtn')?.addEventListener('click', () => {
      document.getElementById('analysisFileInput')?.click();
    });
    document.getElementById('analysisFileInput')?.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) importAnalysis(file);
      e.target.value = '';
    });
    document.getElementById('injectOverlayBtn')?.addEventListener('click', async () => {
      state.overlayEnabled = !state.overlayEnabled;
      await browserAPI.storage.local.set({ v1h_overlay_enabled: state.overlayEnabled });
      const tabs = await browserAPI.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]) {
        browserAPI.tabs.sendMessage(tabs[0].id, {
          type: state.overlayEnabled ? 'v1h_injectOverlays' : 'v1h_removeOverlays'
        }).catch(() => {});
      }
      render();
    });
  }
}

// --- Init ---

document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadState();
    browserAPI.storage.onChanged.addListener(async (changes, area) => {
      if (area === 'local') {
        if (changes.extensionEnabled) {
          state.enabled = changes.extensionEnabled.newValue !== false;
        }
        if (changes.v1h_analysis) {
          await loadAnalysisStats();
        }
        render();
      }
    });
  } catch (error) {
    console.error('[V1 Helper] Popup init error:', error);
    document.getElementById('root').innerHTML = `
      <div class="popup-container">
        <div class="popup-header"><h1>Error</h1></div>
        <div class="popup-content">
          <p style="color:red">Failed to initialize: ${error.message}</p>
        </div>
      </div>
    `;
  }
});
