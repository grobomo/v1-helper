/**
 * Console message capture for browser extensions
 * Injects console override to capture log/warn/error/info/debug messages
 */

/**
 * Console handler class
 * Manages console message capture and storage
 */
export class ConsoleHandler {
  constructor(browserAdapter, logger) {
    this.browserAdapter = browserAdapter;
    this.browser = browserAdapter.getRawAPI();
    this.logger = logger;

    // Console messages storage (per tab)
    this.messages = [];
    this.maxMessages = 1000; // Keep only last 1000 messages

    // Message listener tracking (prevent duplicates)
    this._messageListenerSetUp = false;
    this._messageListener = null;
  }

  /**
   * Get all captured console messages
   * @param {number} tabId - Optional tab ID to filter by
   */
  getMessages(tabId = null) {
    if (tabId === null) {
      return this.messages.slice(); // Return copy of all messages
    }
    // Filter by tab ID
    return this.messages.filter(msg => msg.tabId === tabId);
  }

  /**
   * Add a console message
   */
  addMessage(message) {
    this.messages.push(message);

    // Keep only last maxMessages
    if (this.messages.length > this.maxMessages) {
      this.messages.shift();
    }
  }

  /**
   * Clear all captured messages
   */
  clearMessages() {
    this.messages = [];
    this.logger.log('[ConsoleHandler] Messages cleared');
  }

  /**
   * Get messages count
   */
  getMessagesCount() {
    return this.messages.length;
  }

  /**
   * Inject console capture script into a tab
   * @param {number} tabId - Tab ID to inject console capture into
   */
  async injectConsoleCapture(tabId) {
    try {
      this.logger.log(`[ConsoleHandler] Injecting console capture into tab ${tabId}`);

      // Use func parameter (CSP-safe) instead of code string (requires eval)
      // Must pass standalone function, not class method
      await this.browserAdapter.executeScript(tabId, {
        func: function() {
          // Only inject once
          if (!window.__blueprintConsoleInjected) {
            window.__blueprintConsoleInjected = true;

            // Store original console methods
            const originalConsole = {
              log: console.log,
              warn: console.warn,
              error: console.error,
              info: console.info,
              debug: console.debug
            };

            // Override console methods to capture messages
            ['log', 'warn', 'error', 'info', 'debug'].forEach(method => {
              console[method] = function(...args) {
                // Call original
                originalConsole[method].apply(console, args);

                // Send to extension
                const message = {
                  type: 'console',
                  level: method,
                  text: args.map(arg => {
                    try {
                      return typeof arg === 'object' ? JSON.stringify(arg) : String(arg);
                    } catch (e) {
                      return String(arg);
                    }
                  }).join(' '),
                  timestamp: Date.now()
                };

                // Try to send via postMessage (extension will listen)
                window.postMessage({ __blueprintConsole: message }, '*');
              };
            });
          }
        },
        world: 'MAIN'  // Must use MAIN world to override page's console
      });

      this.logger.log('[ConsoleHandler] Console capture injected into tab:', tabId);
    } catch (error) {
      this.logger.logAlways('[ConsoleHandler] Failed to inject console capture:', error);
    }
  }

  /**
   * Set up message listener to receive console messages from content script
   * This should be called once during initialization
   *
   * Note: Chrome automatically restores listeners on service worker wake,
   * so we don't need persistent storage guards
   */
  setupMessageListener() {
    // Store the listener so we can track it
    this._messageListener = (message, sender) => {
      if (message.type === 'console' && sender.tab) {
        // Add console message with tab info
        this.addMessage({
          tabId: sender.tab.id,
          level: message.level,
          text: message.text,
          timestamp: message.timestamp,
          url: sender.url
        });
      }
    };

    // Note: This would typically be set up in the content script
    // The background script receives messages via runtime.onMessage
    this.browser.runtime.onMessage.addListener(this._messageListener);
    this._messageListenerSetUp = true;

    this.logger.log('[ConsoleHandler] Message listener set up');
  }
}
