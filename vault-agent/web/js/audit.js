// Audit logs functionality
class AuditManager {
    constructor(app) {
        this.app = app;
        this.auditLogs = [];
        this.filteredLogs = [];
        this.currentFilter = {
            startDate: '',
            endDate: '',
            eventType: '',
            user: ''
        };
    }

    async loadData() {
        try {
            await this.loadAuditLogs();
        } catch (error) {
            console.error('Error loading audit data:', error);
            this.app.showAlert('Failed to load audit data', 'error');
        }
    }

    async loadAuditLogs() {
        try {
            const params = new URLSearchParams();
            
            if (this.currentFilter.startDate) {
                params.append('start_date', this.currentFilter.startDate);
            }
            if (this.currentFilter.endDate) {
                params.append('end_date', this.currentFilter.endDate);
            }
            if (this.currentFilter.eventType) {
                params.append('event_type', this.currentFilter.eventType);
            }
            if (this.currentFilter.user) {
                params.append('user', this.currentFilter.user);
            }
            
            const url = `/audit/logs${params.toString() ? '?' + params.toString() : ''}`;
            const response = await this.app.apiRequest(url);
            
            this.auditLogs = response.logs || [];
            this.filteredLogs = [...this.auditLogs];
            this.renderAuditTable();
        } catch (error) {
            console.error('Error loading audit logs:', error);
            throw error;
        }
    }

    renderAuditTable() {
        const tbody = document.getElementById('auditTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (this.filteredLogs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No audit logs found</td></tr>';
            return;
        }

        this.filteredLogs.forEach(log => {
            const row = this.createAuditRow(log);
            tbody.appendChild(row);
        });
    }

    createAuditRow(log) {
        const row = document.createElement('tr');
        const resultClass = log.result === 'success' ? 'text-success' : 'text-danger';
        
        row.innerHTML = `
            <td>${this.app.formatDate(log.timestamp)}</td>
            <td>
                <span class="event-type-badge event-${log.event_type}">
                    ${this.formatEventType(log.event_type)}
                </span>
            </td>
            <td>${this.escapeHtml(log.actor?.username || log.actor?.id || 'System')}</td>
            <td>${this.escapeHtml(log.resource?.type || '')}: ${this.escapeHtml(log.resource?.id || '')}</td>
            <td>${this.escapeHtml(log.action)}</td>
            <td><span class="${resultClass}">${log.result}</span></td>
            <td>${log.ip_address || ''}</td>
        `;
        
        // Add click handler to show details
        row.style.cursor = 'pointer';
        row.onclick = () => this.showAuditDetails(log);
        
        return row;
    }

    formatEventType(eventType) {
        return eventType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    showAuditDetails(log) {
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Audit Log Details</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="audit-details">
                        <div class="form-group">
                            <label>Event ID</label>
                            <input type="text" value="${log.id}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Timestamp</label>
                            <input type="text" value="${this.app.formatDate(log.timestamp)}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Event Type</label>
                            <input type="text" value="${this.formatEventType(log.event_type)}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Actor</label>
                            <input type="text" value="${log.actor?.username || log.actor?.id || 'System'}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Resource</label>
                            <input type="text" value="${log.resource?.type || ''}: ${log.resource?.id || ''}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Action</label>
                            <input type="text" value="${log.action}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Result</label>
                            <input type="text" value="${log.result}" readonly>
                        </div>
                        <div class="form-group">
                            <label>IP Address</label>
                            <input type="text" value="${log.ip_address || ''}" readonly>
                        </div>
                        <div class="form-group">
                            <label>User Agent</label>
                            <input type="text" value="${log.user_agent || ''}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Context</label>
                            <pre>${JSON.stringify(log.context || {}, null, 2)}</pre>
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

    filterAuditLogs() {
        const startDate = document.getElementById('auditStartDate')?.value || '';
        const endDate = document.getElementById('auditEndDate')?.value || '';
        const eventType = document.getElementById('auditEventType')?.value || '';
        const user = document.getElementById('auditUserFilter')?.value.toLowerCase() || '';

        this.currentFilter = { startDate, endDate, eventType, user };

        this.filteredLogs = this.auditLogs.filter(log => {
            // Date filters
            if (startDate && new Date(log.timestamp) < new Date(startDate)) {
                return false;
            }
            if (endDate && new Date(log.timestamp) > new Date(endDate)) {
                return false;
            }

            // Event type filter
            if (eventType && log.event_type !== eventType) {
                return false;
            }

            // User filter
            if (user && !(log.actor?.username || '').toLowerCase().includes(user)) {
                return false;
            }

            return true;
        });

        this.renderAuditTable();
    }

    async exportAuditLogs() {
        try {
            const params = new URLSearchParams();
            params.append('format', 'csv');
            
            if (this.currentFilter.startDate) {
                params.append('start_date', this.currentFilter.startDate);
            }
            if (this.currentFilter.endDate) {
                params.append('end_date', this.currentFilter.endDate);
            }
            if (this.currentFilter.eventType) {
                params.append('event_type', this.currentFilter.eventType);
            }
            if (this.currentFilter.user) {
                params.append('user', this.currentFilter.user);
            }
            
            const response = await fetch(`${this.app.apiBase}/audit/logs/export?${params.toString()}`, {
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
            a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            this.app.showAlert('Audit logs exported successfully', 'success');
        } catch (error) {
            console.error('Error exporting audit logs:', error);
            this.app.showAlert('Failed to export audit logs', 'error');
        }
    }

    addAuditEvent(event) {
        // Add new audit event to the beginning of the list
        this.auditLogs.unshift(event);
        this.filterAuditLogs(); // Re-apply filters and re-render
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions for audit management
function filterAuditLogs() {
    if (window.auditManager) {
        window.auditManager.filterAuditLogs();
    }
}

function refreshAuditLogs() {
    if (window.auditManager) {
        window.auditManager.loadData();
    }
}

function exportAuditLogs() {
    if (window.auditManager) {
        window.auditManager.exportAuditLogs();
    }
}

VaultApp.prototype.loadAuditData = async function() {
    if (!this.auditManager) {
        this.auditManager = new AuditManager(this);
    }
    await this.auditManager.loadData();
    window.auditManager = this.auditManager;
};

VaultApp.prototype.addAuditEvent = function(event) {
    if (this.auditManager) {
        this.auditManager.addAuditEvent(event);
    }
};