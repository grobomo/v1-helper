/**
 * Network request tracking for browser extensions
 * Captures and stores network requests using webRequest API
 */

/**
 * Network tracker class
 * Tracks network requests with headers, bodies, and responses
 */
export class NetworkTracker {
  constructor(browserAPI, logger) {
    this.browser = browserAPI;
    this.logger = logger;

    // Network requests storage
    this.requests = [];
    this.maxRequests = 500; // Keep only last 500 requests

    // Bind event handlers
    this._handleBeforeRequest = this._handleBeforeRequest.bind(this);
    this._handleCompleted = this._handleCompleted.bind(this);
    this._handleBeforeSendHeaders = this._handleBeforeSendHeaders.bind(this);
    this._handleErrorOccurred = this._handleErrorOccurred.bind(this);
  }

  /**
   * Initialize network tracking
   */
  init() {
    // Listen for request start
    this.browser.webRequest.onBeforeRequest.addListener(
      this._handleBeforeRequest,
      { urls: ["<all_urls>"] },
      ["requestBody"]
    );

    // Listen for request completion
    this.browser.webRequest.onCompleted.addListener(
      this._handleCompleted,
      { urls: ["<all_urls>"] },
      ["responseHeaders"]
    );

    // Listen for request headers
    this.browser.webRequest.onBeforeSendHeaders.addListener(
      this._handleBeforeSendHeaders,
      { urls: ["<all_urls>"] },
      ["requestHeaders"]
    );

    // Listen for request errors
    this.browser.webRequest.onErrorOccurred.addListener(
      this._handleErrorOccurred,
      { urls: ["<all_urls>"] }
    );

    this.logger.log('[NetworkTracker] Initialized');
  }

  /**
   * Get all tracked requests
   */
  getRequests() {
    return this.requests;
  }

  /**
   * Clear all tracked requests
   */
  clearRequests() {
    this.requests = [];
    this.logger.log('[NetworkTracker] Cleared all requests');
  }

  /**
   * Get requests count
   */
  getRequestsCount() {
    return this.requests.length;
  }

  /**
   * Handle onBeforeRequest event
   * Captures initial request information
   */
  _handleBeforeRequest(details) {
    const requestId = `${details.requestId}`;

    this.requests.push({
      requestId: requestId,
      url: details.url,
      method: details.method,
      type: details.type,
      tabId: details.tabId,
      timestamp: details.timeStamp,
      statusCode: null,
      statusText: null,
      requestHeaders: null,
      responseHeaders: null,
      requestBody: details.requestBody
    });

    // Keep only last maxRequests requests (FIFO)
    if (this.requests.length > this.maxRequests) {
      this.requests.shift();
    }
  }

  /**
   * Handle onCompleted event
   * Captures response information
   */
  _handleCompleted(details) {
    const request = this.requests.find(r => r.requestId === `${details.requestId}`);
    if (request) {
      request.statusCode = details.statusCode;
      request.statusText = details.statusLine;
      request.responseHeaders = details.responseHeaders;
    }
  }

  /**
   * Handle onBeforeSendHeaders event
   * Captures request headers
   */
  _handleBeforeSendHeaders(details) {
    const request = this.requests.find(r => r.requestId === `${details.requestId}`);
    if (request) {
      request.requestHeaders = details.requestHeaders;
    }
  }

  /**
   * Handle onErrorOccurred event
   * Captures error information
   */
  _handleErrorOccurred(details) {
    const request = this.requests.find(r => r.requestId === `${details.requestId}`);
    if (request) {
      request.statusCode = 0;
      request.statusText = details.error || 'Error';
    }
  }

  /**
   * Clean up event listeners
   */
  destroy() {
    this.browser.webRequest.onBeforeRequest.removeListener(this._handleBeforeRequest);
    this.browser.webRequest.onCompleted.removeListener(this._handleCompleted);
    this.browser.webRequest.onBeforeSendHeaders.removeListener(this._handleBeforeSendHeaders);
    this.browser.webRequest.onErrorOccurred.removeListener(this._handleErrorOccurred);

    this.logger.log('[NetworkTracker] Destroyed');
  }
}
