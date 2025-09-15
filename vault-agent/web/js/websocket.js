// WebSocket functionality for real-time updates - DISABLED
class WebSocketManager {
    constructor(app) {
        this.app = app;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        
        // Disable websocket for local development
        console.log('WebSocket disabled for local development');
    }

    connect() {
        // Disabled - return early
        return;
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.reconnectAttempts = 0;
                this.app.updateStatusIndicator('online');
                
                // Send authentication if available
                if (this.app.authToken) {
                    this.send({
                        type: 'auth',
                        token: this.app.authToken
                    });
                }
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.ws.onclose = (event) => {
                console.log('WebSocket disconnected:', event.code, event.reason);
                this.app.updateStatusIndicator('offline');
                this.scheduleReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };

        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
            this.scheduleReconnect();
        }
    }

    handleMessage(data) {
        switch (data.type) {
            case 'metrics_update':
                this.app.handleWebSocketMessage(data);
                break;
            case 'audit_event':
                this.app.handleWebSocketMessage(data);
                break;
            case 'system_alert':
                this.app.showAlert(data.payload.message, data.payload.level);
                break;
            case 'secret_updated':
                this.app.handleWebSocketMessage(data);
                break;
            case 'heartbeat':
                // Respond to heartbeat
                this.send({ type: 'heartbeat_response' });
                break;
            default:
                console.log('Unknown WebSocket message type:', data.type);
        }
    }

    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
            
            setTimeout(() => {
                this.connect();
            }, delay);
        } else {
            console.log('Max reconnection attempts reached');
            this.app.showAlert('Connection lost. Please refresh the page.', 'error');
        }
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// Extend VaultApp to include WebSocket functionality
VaultApp.prototype.initializeWebSocket = function() {
    if (this.wsManager) {
        this.wsManager.disconnect();
    }
    
    this.wsManager = new WebSocketManager(this);
    this.wsManager.connect();
};