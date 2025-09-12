// Main Application JavaScript
class VaultApp {
    constructor() {
        this.apiBase = '/api/v1';
        this.currentPage = 'dashboard';
        this.websocket = null;
        this.authToken = localStorage.getItem('vault_token');
        
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.checkAuthentication();
        this.initializeWebSocket();
        
        // Load initial page
        this.showPage('dashboard');
    }

    setupNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.dataset.page;
                this.showPage(page);
            });
        });
    }

    setupEventListeners() {
        // Global error handler
        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled promise rejection:', event.reason);
            this.showAlert('An unexpected error occurred', 'error');
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'r':
                        e.preventDefault();
                        this.refreshCurrentPage();
                        break;
                    case 'n':
                        e.preventDefault();
                        this.handleNewItemShortcut();
                        break;
                }
            }
        });

        // Auto-refresh timer
        setInterval(() => {
            this.updateConnectionStatus();
        }, 30000);
    }

    showPage(pageName) {
        // Hide all pages
        document.querySelectorAll('.page').forEach(page => {
            page.classList.remove('active');
        });

        // Show selected page
        const targetPage = document.getElementById(`${pageName}-page`);
        if (targetPage) {
            targetPage.classList.add('active');
        }

        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        
        const activeNavItem = document.querySelector(`[data-page="${pageName}"]`);
        if (activeNavItem) {
            activeNavItem.classList.add('active');
        }

        this.currentPage = pageName;
        
        // Load page data
        this.loadPageData(pageName);
    }

    async loadPageData(pageName) {
        try {
            switch (pageName) {
                case 'dashboard':
                    await this.loadDashboardData();
                    break;
                case 'secrets':
                    await this.loadSecretsData();
                    break;
                case 'policies':
                    await this.loadPoliciesData();
                    break;
                case 'users':
                    await this.loadUsersData();
                    break;
                case 'audit':
                    await this.loadAuditData();
                    break;
                case 'analytics':
                    await this.loadAnalyticsData();
                    break;
                case 'settings':
                    await this.loadSettingsData();
                    break;
            }
        } catch (error) {
            console.error(`Error loading ${pageName} data:`, error);
            this.showAlert(`Failed to load ${pageName} data`, 'error');
        }
    }

    async apiRequest(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
            }
        };

        const finalOptions = { ...defaultOptions, ...options };
        if (finalOptions.body && typeof finalOptions.body === 'object') {
            finalOptions.body = JSON.stringify(finalOptions.body);
        }

        try {
            const response = await fetch(url, finalOptions);
            
            if (response.status === 401) {
                this.handleAuthError();
                throw new Error('Authentication required');
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }
            
            return await response.text();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    async checkAuthentication() {
        try {
            await this.apiRequest('/auth/verify');
        } catch (error) {
            if (error.message.includes('Authentication required')) {
                this.showLoginModal();
            }
        }
    }

    handleAuthError() {
        localStorage.removeItem('vault_token');
        this.authToken = null;
        this.showLoginModal();
    }

    showLoginModal() {
        // Implementation for login modal
        console.log('Login required');
    }

    async updateConnectionStatus() {
        try {
            const response = await fetch('/health');
            const status = response.ok ? 'online' : 'offline';
            this.updateStatusIndicator(status);
        } catch (error) {
            this.updateStatusIndicator('offline');
        }
    }

    updateStatusIndicator(status) {
        const statusElement = document.getElementById('connectionStatus');
        const statusDot = statusElement.querySelector('.status-dot');
        const statusText = statusElement.querySelector('span:last-child');

        statusDot.className = `status-dot ${status}`;
        statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    }

    initializeWebSocket() {
        if (this.websocket) {
            this.websocket.close();
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        try {
            this.websocket = new WebSocket(wsUrl);
            
            this.websocket.onopen = () => {
                console.log('WebSocket connected');
                this.updateStatusIndicator('online');
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.websocket.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateStatusIndicator('offline');
                
                // Attempt to reconnect after 5 seconds
                setTimeout(() => {
                    this.initializeWebSocket();
                }, 5000);
            };

            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'metrics_update':
                this.updateMetrics(data.payload);
                break;
            case 'audit_event':
                this.handleAuditEvent(data.payload);
                break;
            case 'system_alert':
                this.showAlert(data.payload.message, data.payload.level);
                break;
            case 'secret_updated':
                this.handleSecretUpdate(data.payload);
                break;
            default:
                console.log('Unknown WebSocket message type:', data.type);
        }
    }

    updateMetrics(metrics) {
        // Update dashboard metrics in real-time
        if (this.currentPage === 'dashboard') {
            this.updateDashboardMetrics(metrics);
        }
    }

    handleAuditEvent(event) {
        // Add new audit event to the audit log if visible
        if (this.currentPage === 'audit') {
            this.addAuditEvent(event);
        }
    }

    handleSecretUpdate(secretData) {
        // Update secret in the UI if secrets page is visible
        if (this.currentPage === 'secrets') {
            this.updateSecretInTable(secretData);
        }
    }

    showAlert(message, type = 'info', duration = 5000) {
        const alertContainer = this.getOrCreateAlertContainer();
        
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.innerHTML = `
            <span>${message}</span>
            <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; font-size: 1.2rem; cursor: pointer;">&times;</button>
        `;
        
        alertContainer.appendChild(alert);
        
        // Auto-remove after duration
        setTimeout(() => {
            if (alert.parentElement) {
                alert.remove();
            }
        }, duration);
    }

    getOrCreateAlertContainer() {
        let container = document.getElementById('alert-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'alert-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 3000;
                max-width: 400px;
            `;
            document.body.appendChild(container);
        }
        return container;
    }

    refreshCurrentPage() {
        this.loadPageData(this.currentPage);
    }

    handleNewItemShortcut() {
        switch (this.currentPage) {
            case 'secrets':
                showCreateSecretModal();
                break;
            case 'policies':
                showCreatePolicyModal();
                break;
            case 'users':
                showCreateUserModal();
                break;
        }
    }

    // Utility methods
    formatDate(dateString) {
        if (!dateString) return 'Never';
        const date = new Date(dateString);
        return date.toLocaleString();
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatDuration(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Placeholder methods for page-specific data loading
    async loadDashboardData() {
        // Implemented in dashboard.js
    }

    async loadSecretsData() {
        // Implemented in secrets.js
    }

    async loadPoliciesData() {
        // Implemented in policies.js
    }

    async loadUsersData() {
        // Implemented in users.js
    }

    async loadAuditData() {
        // Implemented in audit.js
    }

    async loadAnalyticsData() {
        // Implemented in analytics.js
    }

    async loadSettingsData() {
        // Implemented in settings.js
    }
}

// Modal utilities
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

// Initialize the application
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new VaultApp();
});

// Export for use in other modules
window.VaultApp = VaultApp;