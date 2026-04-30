/**
 * V1 Helper — Popup script.
 * Based on Blueprint Extra MCP popup, rebranded for Vision One.
 * Removed: PRO/Free mode, JWT auth, login, beer button.
 * Added: CVE analysis data import/stats.
 */

const browserAPI = typeof chrome !== 'undefined' ? chrome : browser;

function detectBrowserName() {
  const manifest = browserAPI.runtime.getManifest();
  const match = manifest.name.match(/V1 Helper for (\w+)/);
  return match ? match[1] : 'Chrome';
}

const browserName = detectBrowserName();

function log(...args) {
  if (state?.debugMode) {
    const t = new Date().toISOString().slice(11, 23);
    console.log(`[V1 Helper] ${t}`, ...args);
  }
}

let state = {
  enabled: true,
  currentTabConnected: false,
  stealthMode: null,
  anyConnected: false,
  connecting: false,
  showSettings: false,
  port: '5555',
  debugMode: false,
  version: '0.1.0',
  projectName: null,
  // V1 analysis state
  analysisCount: 0,
  analysisRelevant: 0,
  analysisLow: 0,
  analysisNo: 0,
};

// --- Status ---

async function updateStatus() {
  const tabs = await browserAPI.tabs.query({ active: true, currentWindow: true });
  const currentTab = tabs[0];
  const response = await browserAPI.runtime.sendMessage({ type: 'getConnectionStatus' });

  const connectedTabId = response?.connectedTabId;
  state.anyConnected = response?.connected === true;
  state.currentTabConnected = currentTab?.id === connectedTabId;
  state.stealthMode = state.currentTabConnected ? (response?.stealthMode ?? null) : null;
  state.projectName = response?.projectName || null;

  const storage = await browserAPI.storage.local.get(['extensionEnabled']);
  state.connecting = (storage.extensionEnabled !== false) && !state.anyConnected;

  render();
}

async function loadState() {
  const storage = await browserAPI.storage.local.get([
    'extensionEnabled', 'mcpPort', 'debugMode'
  ]);

  state.enabled = storage.extensionEnabled !== false;
  state.port = storage.mcpPort || '5555';
  state.debugMode = storage.debugMode || false;

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
    mcpPort: state.port,
    debugMode: state.debugMode,
  });
  browserAPI.runtime.reload();
  state.showSettings = false;
  render();
}

async function cancelSettings() {
  const storage = await browserAPI.storage.local.get(['mcpPort', 'debugMode']);
  state.port = storage.mcpPort || '5555';
  state.debugMode = storage.debugMode || false;
  state.showSettings = false;
  render();
}

// --- Render ---

function render() {
  const root = document.getElementById('root');
  if (!root) return;
  root.innerHTML = state.showSettings ? renderSettings() : renderMain();
  attachEventListeners();
}

function renderSettings() {
  return `
    <div class="popup-container">
      <div class="popup-header">
        <img src="/icons/icon-32.png" alt="V1 Helper" class="header-icon" />
        <h1>V1 Helper<span class="version-label">v${state.version}</span></h1>
      </div>
      <div class="popup-content">
        <div class="settings-form">
          <label class="settings-label">
            MCP Server Port:
            <input type="number" class="settings-input" id="portInput"
              value="${state.port}" min="1" max="65535" placeholder="5555" />
          </label>
          <p class="settings-help">Default: 5555. Change if your MCP server runs on a different port.</p>

          <div style="margin-top:16px;padding-top:12px;border-top:1px solid #e0e0e0">
            <label class="settings-label" style="display:flex;align-items:center;cursor:pointer">
              <input type="checkbox" id="debugModeCheckbox" ${state.debugMode ? 'checked' : ''}
                style="width:18px;height:18px;margin-right:10px;cursor:pointer" />
              <span>Debug Mode</span>
            </label>
            <p class="settings-help" style="margin-top:6px;margin-left:28px">
              Enable detailed logging for troubleshooting
            </p>
          </div>
        </div>
        <div class="settings-actions">
          <button class="settings-button save" id="saveButton">Save</button>
          <button class="settings-button cancel" id="cancelButton">Cancel</button>
        </div>
      </div>
    </div>
  `;
}

function renderMain() {
  const statusClass = state.connecting ? 'connecting' : state.anyConnected ? 'connected' : 'disconnected';
  const statusText = state.connecting ? 'Connecting' : state.anyConnected ? 'Connected' : 'Disconnected';

  return `
    <div class="popup-container">
      <div class="popup-header">
        <img src="/icons/icon-32.png" alt="V1 Helper" class="header-icon" />
        <h1>V1 Helper<span class="version-label">v${state.version}</span></h1>
      </div>
      <div class="popup-content">
        <div class="status-row">
          <span class="status-label">MCP Status:</span>
          <div class="status-indicator">
            <span class="status-dot ${statusClass}"></span>
            <span class="status-text">${statusText}</span>
          </div>
        </div>

        <div class="status-row">
          <span class="status-label">This tab:</span>
          <span class="status-text">${state.currentTabConnected ? '✓ Automated' : 'Not automated'}</span>
        </div>

        ${state.currentTabConnected && state.projectName ? `
          <div class="status-row">
            <span class="status-label"></span>
            <span class="status-text" style="font-size:0.9em;color:#666">${state.projectName}</span>
          </div>
        ` : ''}

        ${state.currentTabConnected ? `
          <div class="status-row">
            <span class="status-label">Stealth:</span>
            <span class="status-text">${state.stealthMode === null ? 'N/A' : state.stealthMode ? 'On' : 'Off'}</span>
          </div>
        ` : ''}

        <div class="toggle-row">
          <button class="toggle-button ${state.enabled ? 'enabled' : 'disabled'}" id="toggleButton">
            ${state.enabled ? 'Disable' : 'Enable'}
          </button>
        </div>

        <!-- V1 Analysis Section -->
        <div class="v1-section">
          <h3>CVE Analysis</h3>
          ${state.analysisCount > 0 ? `
            <div class="v1-stat"><span class="v1-stat-label">CVEs loaded</span><span class="v1-stat-value">${state.analysisCount}</span></div>
            <div class="v1-stat"><span class="v1-stat-label">Relevant</span><span class="v1-stat-value" style="color:#D71920">${state.analysisRelevant}</span></div>
            <div class="v1-stat"><span class="v1-stat-label">Low priority</span><span class="v1-stat-value" style="color:#856404">${state.analysisLow}</span></div>
            <div class="v1-stat"><span class="v1-stat-label">Not relevant</span><span class="v1-stat-value" style="color:#155724">${state.analysisNo}</span></div>
          ` : `
            <p style="font-size:12px;color:#666">No analysis loaded. Import analysis.json to see CVE overlays in V1 console.</p>
          `}
          <button class="v1-import-btn" id="importAnalysisBtn">Import analysis.json</button>
          <input type="file" id="analysisFileInput" class="v1-file-input" accept=".json" />
        </div>

        <div class="links-section">
          <button class="settings-link" id="settingsButton">Settings</button>
        </div>
      </div>
    </div>
  `;
}

// --- Event Listeners ---

function attachEventListeners() {
  if (state.showSettings) {
    document.getElementById('saveButton')?.addEventListener('click', saveSettings);
    document.getElementById('cancelButton')?.addEventListener('click', cancelSettings);
    const portInput = document.getElementById('portInput');
    if (portInput) portInput.addEventListener('input', (e) => { state.port = e.target.value; });
    const debugCb = document.getElementById('debugModeCheckbox');
    if (debugCb) debugCb.addEventListener('change', (e) => { state.debugMode = e.target.checked; });
  } else {
    document.getElementById('toggleButton')?.addEventListener('click', toggleEnabled);
    document.getElementById('settingsButton')?.addEventListener('click', () => {
      state.showSettings = true;
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
  }
}

// --- Init ---

document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadState();
    await updateStatus();

    browserAPI.runtime.onMessage.addListener((msg) => {
      if (msg.type === 'statusChanged') updateStatus();
    });
    browserAPI.tabs.onActivated.addListener(updateStatus);
    browserAPI.storage.onChanged.addListener(async (changes, area) => {
      if (area === 'local' && changes.extensionEnabled) {
        state.enabled = changes.extensionEnabled.newValue !== false;
        await updateStatus();
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
