/**
 * Dialog handlers for browser extensions
 * Auto-handles alert/confirm/prompt dialogs by injecting overrides
 */

/**
 * Dialog handler class
 * Manages dialog auto-responses and event logging
 */
export class DialogHandler {
  constructor(browserAdapter, logger) {
    this.browserAdapter = browserAdapter;
    this.browser = browserAdapter.getRawAPI();
    this.logger = logger;
  }

  /**
   * Set up dialog overrides on a tab
   * @param {number} tabId - Tab ID to inject dialog overrides into
   * @param {boolean} accept - Whether to accept dialogs (true) or dismiss (false)
   * @param {string} promptText - Text to return for prompt() calls when accepted
   */
  async setupDialogOverrides(tabId, accept = true, promptText = '') {
    const dialogResponse = { accept, promptText };

    try {
      // Use func parameter (CSP-safe) instead of code string (requires eval)
      // Must pass standalone function, not class method
      await this.browserAdapter.executeScript(tabId, {
        func: function(dialogResponse) {
          // Set up dialog response in window object
          window.__blueprintDialogResponse = dialogResponse;

          // Initialize dialog event log if not exists
          if (!window.__blueprintDialogEvents) {
            window.__blueprintDialogEvents = [];
          }

          // Store originals only once
          if (!window.__originalAlert) {
            window.__originalAlert = window.alert;
            window.__originalConfirm = window.confirm;
            window.__originalPrompt = window.prompt;

            // Override alert with auto-response
            window.alert = function(...args) {
              const message = args[0] || '';
              if (window.__blueprintDialogResponse) {
                // Don't pollute page console
                window.__blueprintDialogEvents.push({
                  type: 'alert',
                  message: message,
                  response: undefined,
                  timestamp: Date.now()
                });
                // Don't delete - keep handling all dialogs
                return undefined;
              }
              return window.__originalAlert.apply(this, args);
            };

            // Override confirm with auto-response
            window.confirm = function(...args) {
              const message = args[0] || '';
              if (window.__blueprintDialogResponse) {
                const response = window.__blueprintDialogResponse.accept;
                // Don't pollute page console
                window.__blueprintDialogEvents.push({
                  type: 'confirm',
                  message: message,
                  response: response,
                  timestamp: Date.now()
                });
                // Don't delete - keep handling all dialogs
                return response;
              }
              return window.__originalConfirm.apply(this, args);
            };

            // Override prompt with auto-response
            window.prompt = function(...args) {
              const message = args[0] || '';
              const defaultValue = args[1] || '';
              if (window.__blueprintDialogResponse) {
                const response = window.__blueprintDialogResponse.accept
                  ? window.__blueprintDialogResponse.promptText
                  : null;
                // Don't pollute page console
                window.__blueprintDialogEvents.push({
                  type: 'prompt',
                  message: message,
                  defaultValue: defaultValue,
                  response: response,
                  timestamp: Date.now()
                });
                // Don't delete - keep handling all dialogs
                return response;
              }
              return window.__originalPrompt.apply(this, args);
            };

            // Don't pollute page console - already logged in background worker
          } else {
            // Just update the response if already set up
            // Don't pollute page console
          }
        },
        args: [dialogResponse],
        world: 'MAIN'  // Must use MAIN world to override page's dialog functions
      });

      this.logger.log('[DialogHandler] Dialog overrides set up for tab:', tabId);
    } catch (error) {
      this.logger.log('[DialogHandler] Could not inject dialog overrides:', error.message);
    }
  }

  /**
   * Get dialog events from a tab
   * @param {number} tabId - Tab ID to get events from
   * @returns {Promise<Array>} Array of dialog events
   */
  async getDialogEvents(tabId) {
    try {
      const results = await this.browserAdapter.executeScript(tabId, {
        func: () => window.__blueprintDialogEvents || []
      });

      return results && results[0] ? results[0] : [];
    } catch (error) {
      this.logger.log('[DialogHandler] Could not get dialog events:', error.message);
      return [];
    }
  }

  /**
   * Clear dialog events from a tab
   * @param {number} tabId - Tab ID to clear events from
   */
  async clearDialogEvents(tabId) {
    try {
      await this.browserAdapter.executeScript(tabId, {
        func: () => { window.__blueprintDialogEvents = []; }
      });

      this.logger.log('[DialogHandler] Dialog events cleared for tab:', tabId);
    } catch (error) {
      this.logger.log('[DialogHandler] Could not clear dialog events:', error.message);
    }
  }
}
