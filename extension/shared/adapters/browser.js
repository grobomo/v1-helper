/**
 * Browser API adapter
 * Provides a unified API that works across Chrome and Firefox
 * Handles differences between chrome.* and browser.* APIs
 */

/**
 * Get the browser API object
 * Returns the appropriate API based on the browser environment
 */
export function getBrowserAPI() {
  // Firefox uses 'browser' API (promise-based)
  if (typeof browser !== 'undefined' && browser.runtime) {
    return browser;
  }

  // Chrome uses 'chrome' API (callback-based, but supports promises in manifest v3)
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    return chrome;
  }

  throw new Error('No browser API available');
}

/**
 * Detect browser type
 */
export function detectBrowser() {
  if (typeof browser !== 'undefined' && browser.runtime) {
    return 'firefox';
  }
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    return 'chrome';
  }
  return 'unknown';
}

/**
 * Check if using manifest v3
 */
export function isManifestV3() {
  const browserAPI = getBrowserAPI();
  const manifest = browserAPI.runtime.getManifest();
  return manifest.manifest_version === 3;
}

/**
 * Browser adapter class
 * Provides cross-browser compatible methods
 */
export class BrowserAdapter {
  constructor() {
    this.api = getBrowserAPI();
    this.browserType = detectBrowser();
    this.manifestVersion = this.api.runtime.getManifest().manifest_version;
  }

  /**
   * Get the raw browser API
   */
  getRawAPI() {
    return this.api;
  }

  /**
   * Get browser type
   */
  getBrowserType() {
    return this.browserType;
  }

  /**
   * Get manifest version
   */
  getManifestVersion() {
    return this.manifestVersion;
  }

  /**
   * Storage API - unified interface
   */
  get storage() {
    return this.api.storage;
  }

  /**
   * Tabs API - unified interface
   */
  get tabs() {
    return this.api.tabs;
  }

  /**
   * Windows API - unified interface
   */
  get windows() {
    return this.api.windows;
  }

  /**
   * Runtime API - unified interface
   */
  get runtime() {
    return this.api.runtime;
  }

  /**
   * WebRequest API - unified interface
   */
  get webRequest() {
    return this.api.webRequest;
  }

  /**
   * WebNavigation API - unified interface
   */
  get webNavigation() {
    return this.api.webNavigation;
  }

  /**
   * Management API - unified interface
   */
  get management() {
    return this.api.management;
  }

  /**
   * Action/BrowserAction API - unified interface
   * Handles manifest v2 (browserAction) vs v3 (action) differences
   */
  get action() {
    // Chrome manifest v3 uses 'action'
    if (this.api.action) {
      return this.api.action;
    }

    // Firefox manifest v2 uses 'browserAction'
    if (this.api.browserAction) {
      return this.api.browserAction;
    }

    // Fallback
    throw new Error('No action/browserAction API available');
  }

  /**
   * Set badge text (cross-browser)
   */
  async setBadgeText(options) {
    return this.action.setBadgeText(options);
  }

  /**
   * Set badge background color (cross-browser)
   */
  async setBadgeBackgroundColor(options) {
    return this.action.setBadgeBackgroundColor(options);
  }

  /**
   * Set icon (cross-browser)
   */
  async setIcon(options) {
    return this.action.setIcon(options);
  }

  /**
   * Set title (cross-browser)
   */
  async setTitle(options) {
    return this.action.setTitle(options);
  }

  /**
   * Execute script in tab
   * Handles executeScript differences between browsers
   * Manifest V3 compatible - supports both MAIN and ISOLATED worlds
   *
   * Options:
   * - func: Function to execute (CSP-safe, preferred)
   * - args: Array of arguments to pass to func
   * - code: String code to execute (requires eval, blocked by CSP on some pages)
   * - world: 'MAIN' or 'ISOLATED' (default: ISOLATED)
   */
  async executeScript(tabId, options) {
    // Manifest v3 uses scripting.executeScript
    if (this.manifestVersion === 3 && this.api.scripting) {
      // Use specified world or default to ISOLATED
      // ISOLATED = isolated context for stealth (passes bot detection)
      // MAIN = page context (needed for console override, dialog override)
      const world = options.world || 'ISOLATED';

      // If func provided, use it directly (CSP-safe)
      if (options.func) {
        const results = await this.api.scripting.executeScript({
          target: { tabId: tabId },
          world: world,
          func: options.func,
          args: options.args || []
        });
        return results.map(r => r.result);
      }

      // If code provided, use eval (blocked by CSP on some pages)
      if (options.code) {
        const results = await this.api.scripting.executeScript({
          target: { tabId: tabId },
          world: world,
          func: (code) => { return eval(code); },
          args: [options.code]
        });
        return results.map(r => r.result);
      }

      throw new Error('executeScript requires either func or code option');
    }

    // Manifest v2 fallback (deprecated)
    if (this.api.tabs.executeScript) {
      return this.api.tabs.executeScript(tabId, options);
    }

    throw new Error('No executeScript API available - scripting permission may be missing');
  }

  /**
   * Check if browser info is available (Firefox only)
   */
  hasBrowserInfo() {
    return typeof this.api.runtime.getBrowserInfo === 'function';
  }

  /**
   * Get browser info (Firefox only)
   */
  async getBrowserInfo() {
    if (this.hasBrowserInfo()) {
      return this.api.runtime.getBrowserInfo();
    }
    return null;
  }

  /**
   * Check if alarms API is available
   */
  hasAlarms() {
    return typeof this.api.alarms !== 'undefined';
  }

  /**
   * Alarms API (Chrome manifest v3 only)
   */
  get alarms() {
    if (this.hasAlarms()) {
      return this.api.alarms;
    }
    throw new Error('Alarms API not available');
  }

  /**
   * Check if debugger API is available
   */
  hasDebugger() {
    return typeof this.api.debugger !== 'undefined';
  }

  /**
   * Debugger API (Chrome only)
   */
  get debugger() {
    if (this.hasDebugger()) {
      return this.api.debugger;
    }
    throw new Error('Debugger API not available');
  }
}

/**
 * Create a singleton instance
 */
let browserAdapterInstance = null;

export function createBrowserAdapter() {
  if (!browserAdapterInstance) {
    browserAdapterInstance = new BrowserAdapter();
  }
  return browserAdapterInstance;
}
