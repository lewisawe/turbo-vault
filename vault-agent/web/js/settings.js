// Settings management functionality
class SettingsManager {
    constructor(app) {
        this.app = app;
        this.settings = {};
    }

    async loadData() {
        try {
            await this.loadSettings();
        } catch (error) {
            console.error('Error loading settings data:', error);
            this.app.showAlert('Failed to load settings data', 'error');
        }
    }

    async loadSettings() {
        try {
            const response = await this.app.apiRequest('/system/settings');
            this.settings = response.settings || {};
            this.populateSettingsForms();
        } catch (error) {
            console.error('Error loading settings:', error);
            throw error;
        }
    }

    populateSettingsForms() {
        // General settings
        if (document.getElementById('agentName')) {
            document.getElementById('agentName').value = this.settings.agent_name || '';
        }
        if (document.getElementById('logLevel')) {
            document.getElementById('logLevel').value = this.settings.log_level || 'info';
        }
        if (document.getElementById('enableMetrics')) {
            document.getElementById('enableMetrics').checked = this.settings.enable_metrics !== false;
        }

        // Security settings
        if (document.getElementById('sessionTimeout')) {
            document.getElementById('sessionTimeout').value = this.settings.session_timeout || 30;
        }
        if (document.getElementById('maxLoginAttempts')) {
            document.getElementById('maxLoginAttempts').value = this.settings.max_login_attempts || 5;
        }
        if (document.getElementById('requireMFA')) {
            document.getElementById('requireMFA').checked = this.settings.require_mfa === true;
        }

        // Backup settings
        if (document.getElementById('backupSchedule')) {
            document.getElementById('backupSchedule').value = this.settings.backup_schedule || 'disabled';
        }
        if (document.getElementById('backupRetention')) {
            document.getElementById('backupRetention').value = this.settings.backup_retention || 30;
        }
    }

    async updateSettings(category, settingsData) {
        try {
            const response = await this.app.apiRequest(`/system/settings/${category}`, {
                method: 'PUT',
                body: settingsData
            });

            this.app.showAlert(`${category} settings updated successfully`, 'success');
            
            // Update local settings
            Object.assign(this.settings, settingsData);
            
            return response;
        } catch (error) {
            console.error('Error updating settings:', error);
            this.app.showAlert(`Failed to update ${category} settings: ${error.message}`, 'error');
            throw error;
        }
    }

    async createBackup() {
        try {
            const response = await this.app.apiRequest('/system/backup', {
                method: 'POST'
            });

            this.app.showAlert('Backup created successfully', 'success');
            
            // Show backup details
            const modal = document.createElement('div');
            modal.className = 'modal active';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Backup Created</h3>
                        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="backup-details">
                            <div class="form-group">
                                <label>Backup ID</label>
                                <input type="text" value="${response.id}" readonly>
                            </div>
                            <div class="form-group">
                                <label>Created At</label>
                                <input type="text" value="${this.app.formatDate(response.created_at)}" readonly>
                            </div>
                            <div class="form-group">
                                <label>Size</label>
                                <input type="text" value="${response.size}" readonly>
                            </div>
                            <div class="form-group">
                                <label>Status</label>
                                <input type="text" value="${response.status}" readonly>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" onclick="this.closest('.modal').remove()">Close</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            return response;
        } catch (error) {
            console.error('Error creating backup:', error);
            this.app.showAlert(`Failed to create backup: ${error.message}`, 'error');
            throw error;
        }
    }

    async testNotification(channel) {
        try {
            const response = await this.app.apiRequest('/system/notifications/test', {
                method: 'POST',
                body: { channel }
            });

            this.app.showAlert('Test notification sent successfully', 'success');
            return response;
        } catch (error) {
            console.error('Error sending test notification:', error);
            this.app.showAlert(`Failed to send test notification: ${error.message}`, 'error');
            throw error;
        }
    }

    async exportConfiguration() {
        try {
            const response = await fetch(`${this.app.apiBase}/system/config/export`, {
                headers: {
                    ...(this.app.authToken && { 'Authorization': `Bearer ${this.app.authToken}` })
                }
            });
            
            if (!response.ok) {
                throw new Error('Export failed');
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vault-config-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            this.app.showAlert('Configuration exported successfully', 'success');
        } catch (error) {
            console.error('Error exporting configuration:', error);
            this.app.showAlert('Failed to export configuration', 'error');
        }
    }

    async importConfiguration(file) {
        try {
            const formData = new FormData();
            formData.append('config', file);
            
            const response = await fetch(`${this.app.apiBase}/system/config/import`, {
                method: 'POST',
                headers: {
                    ...(this.app.authToken && { 'Authorization': `Bearer ${this.app.authToken}` })
                },
                body: formData
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || 'Import failed');
            }
            
            const result = await response.json();
            this.app.showAlert('Configuration imported successfully', 'success');
            
            // Reload settings
            await this.loadSettings();
            
            return result;
        } catch (error) {
            console.error('Error importing configuration:', error);
            this.app.showAlert(`Failed to import configuration: ${error.message}`, 'error');
            throw error;
        }
    }
}

// Global functions for settings management
async function saveGeneralSettings() {
    const settingsData = {
        agent_name: document.getElementById('agentName').value,
        log_level: document.getElementById('logLevel').value,
        enable_metrics: document.getElementById('enableMetrics').checked
    };
    
    try {
        await window.settingsManager.updateSettings('general', settingsData);
    } catch (error) {
        // Error already handled in updateSettings method
    }
}

async function saveSecuritySettings() {
    const settingsData = {
        session_timeout: parseInt(document.getElementById('sessionTimeout').value),
        max_login_attempts: parseInt(document.getElementById('maxLoginAttempts').value),
        require_mfa: document.getElementById('requireMFA').checked
    };
    
    try {
        await window.settingsManager.updateSettings('security', settingsData);
    } catch (error) {
        // Error already handled in updateSettings method
    }
}

async function saveBackupSettings() {
    const settingsData = {
        backup_schedule: document.getElementById('backupSchedule').value,
        backup_retention: parseInt(document.getElementById('backupRetention').value)
    };
    
    try {
        await window.settingsManager.updateSettings('backup', settingsData);
    } catch (error) {
        // Error already handled in updateSettings method
    }
}

async function createBackup() {
    try {
        await window.settingsManager.createBackup();
    } catch (error) {
        // Error already handled in createBackup method
    }
}

function showNotificationSettings() {
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Notification Settings</h3>
                <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="notification-settings">
                    <div class="form-group">
                        <label>Email Notifications</label>
                        <div class="notification-channel">
                            <input type="checkbox" id="emailEnabled" checked>
                            <label for="emailEnabled">Enable email notifications</label>
                        </div>
                        <input type="email" id="emailAddress" placeholder="admin@example.com">
                        <button class="btn btn-sm btn-secondary" onclick="testNotification('email')">Test Email</button>
                    </div>
                    
                    <div class="form-group">
                        <label>Webhook Notifications</label>
                        <div class="notification-channel">
                            <input type="checkbox" id="webhookEnabled">
                            <label for="webhookEnabled">Enable webhook notifications</label>
                        </div>
                        <input type="url" id="webhookUrl" placeholder="https://hooks.example.com/vault">
                        <button class="btn btn-sm btn-secondary" onclick="testNotification('webhook')">Test Webhook</button>
                    </div>
                    
                    <div class="form-group">
                        <label>Slack Notifications</label>
                        <div class="notification-channel">
                            <input type="checkbox" id="slackEnabled">
                            <label for="slackEnabled">Enable Slack notifications</label>
                        </div>
                        <input type="text" id="slackWebhook" placeholder="Slack webhook URL">
                        <button class="btn btn-sm btn-secondary" onclick="testNotification('slack')">Test Slack</button>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                <button class="btn btn-primary" onclick="saveNotificationSettings(this.closest('.modal'))">Save Settings</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

async function saveNotificationSettings(modal) {
    const settingsData = {
        email: {
            enabled: document.getElementById('emailEnabled').checked,
            address: document.getElementById('emailAddress').value
        },
        webhook: {
            enabled: document.getElementById('webhookEnabled').checked,
            url: document.getElementById('webhookUrl').value
        },
        slack: {
            enabled: document.getElementById('slackEnabled').checked,
            webhook: document.getElementById('slackWebhook').value
        }
    };
    
    try {
        await window.settingsManager.updateSettings('notifications', settingsData);
        modal.remove();
    } catch (error) {
        // Error already handled in updateSettings method
    }
}

async function testNotification(channel) {
    try {
        await window.settingsManager.testNotification(channel);
    } catch (error) {
        // Error already handled in testNotification method
    }
}

function showConfigurationManager() {
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Configuration Manager</h3>
                <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="config-manager">
                    <div class="form-group">
                        <label>Export Configuration</label>
                        <p class="text-muted">Download current vault configuration as JSON file</p>
                        <button class="btn btn-primary" onclick="exportConfiguration()">
                            <i class="fas fa-download"></i> Export Configuration
                        </button>
                    </div>
                    
                    <div class="form-group">
                        <label>Import Configuration</label>
                        <p class="text-muted">Upload and apply configuration from JSON file</p>
                        <input type="file" id="configFile" accept=".json" onchange="handleConfigFileSelect(this)">
                        <button class="btn btn-warning" id="importConfigBtn" onclick="importConfiguration()" disabled>
                            <i class="fas fa-upload"></i> Import Configuration
                        </button>
                    </div>
                    
                    <div class="alert alert-warning">
                        <strong>Warning:</strong> Importing configuration will overwrite current settings. Make sure to export your current configuration first.
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

function handleConfigFileSelect(input) {
    const importBtn = document.getElementById('importConfigBtn');
    importBtn.disabled = !input.files.length;
}

async function exportConfiguration() {
    try {
        await window.settingsManager.exportConfiguration();
    } catch (error) {
        // Error already handled in exportConfiguration method
    }
}

async function importConfiguration() {
    const fileInput = document.getElementById('configFile');
    const file = fileInput.files[0];
    
    if (!file) {
        app.showAlert('Please select a configuration file', 'error');
        return;
    }
    
    if (!confirm('Are you sure you want to import this configuration? This will overwrite current settings.')) {
        return;
    }
    
    try {
        await window.settingsManager.importConfiguration(file);
        document.querySelector('.modal').remove();
    } catch (error) {
        // Error already handled in importConfiguration method
    }
}

// Setup form event handlers
document.addEventListener('DOMContentLoaded', () => {
    // General settings form
    const generalForm = document.getElementById('generalSettingsForm');
    if (generalForm) {
        generalForm.addEventListener('submit', (e) => {
            e.preventDefault();
            saveGeneralSettings();
        });
    }
    
    // Security settings form
    const securityForm = document.getElementById('securitySettingsForm');
    if (securityForm) {
        securityForm.addEventListener('submit', (e) => {
            e.preventDefault();
            saveSecuritySettings();
        });
    }
    
    // Backup settings form
    const backupForm = document.getElementById('backupSettingsForm');
    if (backupForm) {
        backupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            saveBackupSettings();
        });
    }
});

VaultApp.prototype.loadSettingsData = async function() {
    if (!this.settingsManager) {
        this.settingsManager = new SettingsManager(this);
    }
    await this.settingsManager.loadData();
    window.settingsManager = this.settingsManager;
};