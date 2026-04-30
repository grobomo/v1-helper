/**
 * Icon and badge management for browser extensions
 * Handles icon states, badges, and tab-based icon updates
 */

/**
 * Icon manager class
 * Manages extension icon states and badges based on connection and tab states
 */
export class IconManager {
  constructor(browserAPI, logger) {
    this.browser = browserAPI;
    this.logger = logger;
    this.attachedTabId = null;
    this.stealthMode = false;
    this.isConnected = false;

    // Bind event handlers
    this._handleTabActivated = this._handleTabActivated.bind(this);
    this._handleTabRemoved = this._handleTabRemoved.bind(this);
  }

  /**
   * Initialize icon manager and set up event listeners
   */
  init() {
    // Listen for tab activation to update icon
    this.browser.tabs.onActivated.addListener(this._handleTabActivated);

    // Listen for tab close to reset icon if attached tab is closed
    this.browser.tabs.onRemoved.addListener(this._handleTabRemoved);
  }

  /**
   * Set the attached tab ID
   */
  setAttachedTab(tabId) {
    this.attachedTabId = tabId;
  }

  /**
   * Set stealth mode
   */
  setStealthMode(enabled) {
    this.stealthMode = enabled;
  }

  /**
   * Set connection state
   */
  setConnected(connected) {
    this.isConnected = connected;
  }

  /**
   * Update badge for attached tab based on stealth mode
   */
  async updateBadgeForTab() {
    if (!this.attachedTabId) {
      this.logger.log('[IconManager] No attached tab, skipping badge update');
      return;
    }

    const title = this.stealthMode ? 'Tab automated (Stealth Mode)' : 'Tab automated';

    // Set badge per-tab (not global) with checkmark
    if (this.stealthMode) {
      // Black badge for stealth mode
      await this.updateBadge(this.attachedTabId, { text: '✓', color: '#000000', title });
    } else {
      // Blue badge for attached mode
      await this.updateBadge(this.attachedTabId, { text: '✓', color: '#007AFF', title });
    }

    this.logger.log('[IconManager] Badge updated for tab:', this.attachedTabId, 'stealth:', this.stealthMode);
  }

  /**
   * Update badge text, color, and title for a specific tab
   * @param {number} tabId - Tab ID
   * @param {object} options - Badge options (text, color, title)
   */
  async updateBadge(tabId, { text, color, title }) {
    try {
      this.logger.log('[IconManager] Setting badge - tabId:', tabId, 'text:', text, 'color:', color, 'title:', title);

      // Chrome MV3 supports per-tab badges - set ONLY for specific tab (not global)
      try {
        await this._setBadgeText({ tabId, text });
        this.logger.log('[IconManager] setBadgeText (per-tab) succeeded');
      } catch (e) {
        this.logger.log('[IconManager] setBadgeText (per-tab) failed:', e.message);
      }

      // Set badge background color per-tab
      if (color) {
        try {
          await this._setBadgeBackgroundColor({ tabId, color });
          this.logger.log('[IconManager] setBadgeBackgroundColor (per-tab) succeeded');
        } catch (e) {
          this.logger.log('[IconManager] setBadgeBackgroundColor (per-tab) failed:', e.message);
        }
      }

      this.logger.log('[IconManager] Badge update complete for tab:', tabId);
    } catch (error) {
      this.logger.logAlways('[IconManager] Badge update error:', error.message, error.stack);
    }
  }

  /**
   * Clear badge for a specific tab
   */
  async clearBadge(tabId) {
    await this.updateBadge(tabId, { text: '', color: '#00000000' }); // Transparent color
  }

  /**
   * Update global badge (for connecting/connected states)
   */
  async updateGlobalBadge({ text, color, title }) {
    try {
      // Set badge text globally
      await this._setBadgeText({ text });

      // Set badge color if provided
      if (color) {
        await this._setBadgeBackgroundColor({ color });
      }

      // Set title if provided
      if (title) {
        await this._setTitle({ title });
      }

      this.logger.log('[IconManager] Global badge updated:', text, color, title);
    } catch (error) {
      this.logger.logAlways('[IconManager] Failed to update global badge:', error.message);
    }
  }

  /**
   * Show connecting icon (yellow dot)
   */
  async updateConnectingBadge() {
    await this.setGlobalIcon('connecting', 'Connecting to MCP server...');
  }

  /**
   * Set global icon based on state
   * @param {string} state - Icon state (connecting|connected|attached|attached-stealth)
   * @param {string} title - Tooltip title
   */
  async setGlobalIcon(state, title) {
    try {
      const iconSuffix = state === 'connecting'
        ? 'connecting'
        : state === 'connected'
        ? 'connected'
        : state === 'attached'
        ? 'attached'
        : state === 'attached-stealth'
        ? 'attached-stealth'
        : '';

      // Chrome MV3 requires path object with sizes
      // Use getURL to convert relative paths to absolute chrome-extension:// URLs
      // This is required for service workers which don't have relative path context
      const iconPath = {
        "16": this.browser.runtime.getURL(`icons/icon-16${iconSuffix ? '-' + iconSuffix : ''}.png`),
        "32": this.browser.runtime.getURL(`icons/icon-32${iconSuffix ? '-' + iconSuffix : ''}.png`),
        "48": this.browser.runtime.getURL(`icons/icon-48${iconSuffix ? '-' + iconSuffix : ''}.png`),
        "128": this.browser.runtime.getURL(`icons/icon-128${iconSuffix ? '-' + iconSuffix : ''}.png`)
      };

      await this._setIcon({ path: iconPath });
      await this._setTitle({ title: title || 'V1 Helper' });
      this.logger.log('[IconManager] Icon updated:', state);
    } catch (error) {
      this.logger.logAlways('[IconManager] Failed to update icon:', error.message);
    }
  }

  /**
   * Handle tab activation event
   */
  async _handleTabActivated(activeInfo) {
    this.logger.log('[IconManager] Tab activated:', activeInfo.tabId);

    // Check if the activated tab is the attached tab
    if (activeInfo.tabId === this.attachedTabId) {
      // Show attached icon
      await this.updateBadgeForTab();
      this.logger.log('[IconManager] Icon updated for attached tab');
    } else if (this.isConnected) {
      // Show connected icon (no tab attached)
      await this.setGlobalIcon('connected', 'Connected to MCP server');
      this.logger.log('[IconManager] Icon updated for non-attached tab');
    }
  }

  /**
   * Handle tab removal event
   */
  async _handleTabRemoved(tabId) {
    if (tabId === this.attachedTabId) {
      this.logger.log('[IconManager] Attached tab closed, resetting icon');
      this.attachedTabId = null;

      // Show connected icon (no tab attached)
      if (this.isConnected) {
        await this.setGlobalIcon('connected', 'Connected to MCP server');
      }
    }
  }

  /**
   * Browser API wrappers - allow for cross-browser compatibility
   */
  async _setBadgeText(options) {
    // Check if we're using Chrome or Firefox API
    if (this.browser.action) {
      // Chrome manifest v3
      return this.browser.action.setBadgeText(options);
    } else if (this.browser.browserAction) {
      // Firefox manifest v2
      return this.browser.browserAction.setBadgeText(options);
    }
    throw new Error('No badge API available');
  }

  async _setBadgeBackgroundColor(options) {
    if (this.browser.action) {
      return this.browser.action.setBadgeBackgroundColor(options);
    } else if (this.browser.browserAction) {
      return this.browser.browserAction.setBadgeBackgroundColor(options);
    }
    throw new Error('No badge API available');
  }

  async _setTitle(options) {
    if (this.browser.action) {
      return this.browser.action.setTitle(options);
    } else if (this.browser.browserAction) {
      return this.browser.browserAction.setTitle(options);
    }
    throw new Error('No title API available');
  }

  async _setIcon(options) {
    if (this.browser.action) {
      return this.browser.action.setIcon(options);
    } else if (this.browser.browserAction) {
      return this.browser.browserAction.setIcon(options);
    }
    throw new Error('No icon API available');
  }

  /**
   * Clean up event listeners
   */
  destroy() {
    this.browser.tabs.onActivated.removeListener(this._handleTabActivated);
    this.browser.tabs.onRemoved.removeListener(this._handleTabRemoved);
  }
}
