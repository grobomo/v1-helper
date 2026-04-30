/**
 * WebSocket connection manager for V1 Helper extension.
 * Simplified from Blueprint Extra MCP — local connection only, no PRO/relay/JWT.
 */

export class WebSocketConnection {
  constructor(browserAPI, logger, iconManager, buildTimestamp = null) {
    this.browser = browserAPI;
    this.logger = logger;
    this.iconManager = iconManager;
    this.buildTimestamp = buildTimestamp;

    this.socket = null;
    this.isConnected = false;
    this.projectName = null;
    this.connectionUrl = null;
    this.reconnectTimeout = null;
    this.reconnectDelay = 5000;

    this.commandHandlers = new Map();
    this.notificationHandlers = new Map();
  }

  registerCommandHandler(method, handler) {
    this.commandHandlers.set(method, handler);
  }

  registerNotificationHandler(method, handler) {
    this.notificationHandlers.set(method, handler);
  }

  async isExtensionEnabled() {
    const result = await this.browser.storage.local.get(['extensionEnabled']);
    return result.extensionEnabled !== false;
  }

  async getConnectionUrl() {
    const result = await this.browser.storage.local.get(['mcpPort']);
    const port = result.mcpPort || '5555';
    return `ws://127.0.0.1:${port}/extension`;
  }

  async connect() {
    try {
      const isEnabled = await this.isExtensionEnabled();
      if (!isEnabled) {
        this.logger.log('[WebSocket] Extension disabled, skipping connect');
        return;
      }

      if (this.iconManager) {
        await this.iconManager.updateConnectingBadge();
      }

      const url = await this.getConnectionUrl();
      this.connectionUrl = url;

      this.socket = new WebSocket(url);
      this.socket.onopen = () => this._handleOpen();
      this.socket.onmessage = (event) => this._handleMessage(event);
      this.socket.onerror = (error) => this._handleError(error);
      this.socket.onclose = (event) => this._handleClose(event);
    } catch (error) {
      this.logger.logAlways('[WebSocket] Connection error:', error);
      if (this.iconManager) {
        await this.iconManager.setGlobalIcon('normal', 'Connection failed');
      }
      this._scheduleReconnect();
    }
  }

  disconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.isConnected = false;
    if (this.iconManager) {
      this.iconManager.setConnected(false);
      this.iconManager.setGlobalIcon('normal', 'Disconnected');
    }
    this.browser.runtime.sendMessage({ type: 'statusChanged' }).catch(() => {});
  }

  send(message) {
    if (this.socket && this.isConnected) {
      this.socket.send(JSON.stringify(message));
    }
  }

  sendNotification(method, params) {
    if (!this.socket || !this.isConnected) return;
    this.send({ jsonrpc: '2.0', method, params });
  }

  _handleOpen() {
    this.logger.logAlways(`Connected to ${this.connectionUrl}`);
    this.isConnected = true;

    if (this.iconManager) {
      this.iconManager.setConnected(true);
      this.iconManager.setGlobalIcon('connected', 'Connected to MCP server');
    }

    this.browser.runtime.sendMessage({ type: 'statusChanged' }).catch(() => {});

    this.send({
      type: 'handshake',
      browser: this._getBrowserName(),
      version: this.browser.runtime.getManifest().version,
      buildTimestamp: this.buildTimestamp,
    });
  }

  async _handleMessage(event) {
    let message;
    try {
      message = JSON.parse(event.data);
      this.logger.log('[WebSocket] Received:', message);

      if (message.error) {
        this.logger.logAlways('[WebSocket] Server error:', message.error);
        return;
      }

      // Notifications (no id)
      if (!message.id && message.method) {
        await this._handleNotification(message);
        return;
      }

      // Commands
      const response = await this._routeCommand(message);
      this.send({ jsonrpc: '2.0', id: message.id, result: response });
    } catch (error) {
      this.logger.logAlways('[WebSocket] Command error:', error);
      if (message?.id) {
        this.send({
          jsonrpc: '2.0', id: message.id,
          error: { message: error.message, stack: error.stack },
        });
      }
    }
  }

  async _handleNotification(message) {
    const { method, params } = message;
    if (method === 'authenticated' && params?.client_id) {
      this.projectName = params.client_id;
    }
    const handler = this.notificationHandlers.get(method);
    if (handler) await handler(params);
  }

  async _routeCommand(message) {
    const handler = this.commandHandlers.get(message.method);
    if (handler) return await handler(message.params, message);
    throw new Error(`Unknown command: ${message.method}`);
  }

  _handleError(error) {
    this.logger.logAlways('[WebSocket] Error:', error);
    this.isConnected = false;
    if (this.iconManager) this.iconManager.setConnected(false);
  }

  _handleClose(event) {
    this.logger.logAlways(`Disconnected - Code: ${event?.code}`);
    this.isConnected = false;
    if (this.iconManager) {
      this.iconManager.setConnected(false);
      this.iconManager.setGlobalIcon('normal', 'Disconnected');
    }
    this.browser.runtime.sendMessage({ type: 'statusChanged' }).catch(() => {});
    this._scheduleReconnect();
  }

  _scheduleReconnect() {
    if (this.reconnectTimeout) return;
    this.logger.log(`[WebSocket] Reconnecting in ${this.reconnectDelay}ms...`);
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      this.connect();
    }, this.reconnectDelay);
  }

  _getBrowserName() {
    const manifest = this.browser.runtime.getManifest();
    const match = manifest.name.match(/V1 Helper for (\w+)/);
    return match ? match[1] : 'Chrome';
  }
}
