/**
 * V1 Helper — Background service worker
 *
 * Minimal background script. Handles:
 * - Extension lifecycle (install, enable/disable)
 * - Message routing between popup and content scripts
 * - Storage initialization
 *
 * Browser automation is handled by Blueprint MCP (separate tool).
 * This extension only manages CVE overlays and popup UI.
 */

// ─── Lifecycle ───

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[V1 Helper] Extension installed');
    // Initialize default settings
    chrome.storage.local.set({
      extensionEnabled: true,
      v1h_overlay_enabled: true,
      v1h_region: 'us-east-1',
    });
  }
});

// Confirm service worker loaded
chrome.storage.local.set({
  backgroundScriptLoaded: {
    timestamp: new Date().toISOString(),
    message: 'V1 Helper service worker loaded'
  }
});

// ─── Message Handling ───

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'getConnectionStatus':
      // No MCP connection — extension works standalone
      sendResponse({
        connected: false,
        status: 'standalone',
        message: 'Extension operates independently. Use Blueprint MCP for browser automation.'
      });
      return true;

    case 'isStealthMode':
      sendResponse({ isStealthMode: false });
      return true;

    case 'console':
      // Forward console messages from content script (for debugging)
      if (message.level === 'error') {
        console.error(`[Content] ${message.text}`);
      }
      return false;

    case 'techStackDetected':
      // Log tech stack detection from content script
      console.log(`[V1 Helper] Tech stack on ${message.url}:`, message.stack?.frameworks?.join(', ') || 'none');
      return false;

    case 'focusTab':
      // Focus the tab that sent this message
      if (sender.tab?.id) {
        chrome.tabs.update(sender.tab.id, { active: true });
      }
      return false;
  }
});
