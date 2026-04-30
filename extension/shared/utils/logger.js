/**
 * Logger utility for browser extensions
 * Provides conditional logging based on debug mode stored in browser.storage
 */

class Logger {
  constructor(extensionName = 'V1 Helper') {
    this.extensionName = extensionName;
    this.debugMode = false;
    this.initialized = false;
  }

  /**
   * Initialize the logger by loading debug mode from storage
   * Call this once on extension startup
   */
  async init(browserAPI) {
    if (this.initialized) return;

    this.browser = browserAPI;

    // Load debug mode from storage
    const result = await this.browser.storage.local.get(['debugMode']);
    this.debugMode = result.debugMode || false;

    // Listen for debug mode changes
    this.browser.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local' && changes.debugMode) {
        this.debugMode = changes.debugMode.newValue || false;
      }
    });

    this.initialized = true;
  }

  /**
   * Format timestamp for log messages
   */
  _getTimestamp() {
    const now = new Date();
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const seconds = now.getSeconds().toString().padStart(2, '0');
    const milliseconds = now.getMilliseconds().toString().padStart(3, '0');
    return `${hours}:${minutes}:${seconds}.${milliseconds}`;
  }

  /**
   * Log message only if debug mode is enabled
   */
  log(...args) {
    if (this.debugMode) {
      const time = this._getTimestamp();
      console.log(`[${this.extensionName}] ${time}`, ...args);
    }
  }

  /**
   * Always log message regardless of debug mode
   * Use for important events like startup, errors, etc.
   */
  logAlways(...args) {
    const time = this._getTimestamp();
    console.log(`[${this.extensionName}] ${time}`, ...args);
  }

  /**
   * Log error message (always shown)
   */
  error(...args) {
    const time = this._getTimestamp();
    console.error(`[${this.extensionName}] ${time}`, ...args);
  }

  /**
   * Log warning message (always shown)
   */
  warn(...args) {
    const time = this._getTimestamp();
    console.warn(`[${this.extensionName}] ${time}`, ...args);
  }

  /**
   * Set debug mode programmatically
   */
  setDebugMode(enabled) {
    this.debugMode = enabled;
    if (this.browser) {
      this.browser.storage.local.set({ debugMode: enabled });
    }
  }
}

// Export as singleton for convenience
const logger = new Logger();

// Also export the class for custom instances
export { Logger, logger };
