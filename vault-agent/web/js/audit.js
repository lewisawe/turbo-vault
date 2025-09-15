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
        
        // Create cells safely
        const timestampCell = document.createElement('td');
        timestampCell.textContent = this.app.formatDate(log.timestamp);
        
        const eventTypeCell = document.createElement('td');
        const eventBadge = document.createElement('span');
        eventBadge.className = `event-type-badge event-${log.event_type}`;
        eventBadge.textContent = this.formatEventType(log.event_type);
        eventTypeCell.appendChild(eventBadge);
        
        const actorCell = document.createElement('td');
        actorCell.textContent = log.actor?.username || log.actor?.id || 'System';
        
        const resourceCell = document.createElement('td');
        resourceCell.textContent = `${log.resource?.type || ''}: ${log.resource?.id || ''}`;
        
        const actionCell = document.createElement('td');
        actionCell.textContent = log.action;
        
        const resultCell = document.createElement('td');
        const resultSpan = document.createElement('span');
        resultSpan.className = resultClass;
        resultSpan.textContent = log.result;
        resultCell.appendChild(resultSpan);
        
        const ipCell = document.createElement('td');
        ipCell.textContent = log.ip_address || '';
        
        row.appendChild(timestampCell);
        row.appendChild(eventTypeCell);
        row.appendChild(actorCell);
        row.appendChild(resourceCell);
        row.appendChild(actionCell);
        row.appendChild(resultCell);
        row.appendChild(ipCell);
        
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
        
        const modalContent = document.createElement('div');
        modalContent.className = 'modal-content';
        
        const modalHeader = document.createElement('div');
        modalHeader.className = 'modal-header';
        
        const title = document.createElement('h3');
        title.textContent = 'Audit Log Details';
        
        const closeButton = document.createElement('button');
        closeButton.className = 'modal-close';
        closeButton.textContent = '×';
        closeButton.onclick = () => modal.remove();
        
        modalHeader.appendChild(title);
        modalHeader.appendChild(closeButton);
        
        const modalBody = document.createElement('div');
        modalBody.className = 'modal-body';
        
        const auditDetails = document.createElement('div');
        auditDetails.className = 'audit-details';
        
        // Create form groups safely
        const createFormGroup = (label, value) => {
            const group = document.createElement('div');
            group.className = 'form-group';
            
            const labelEl = document.createElement('label');
            labelEl.textContent = label;
            
            const input = document.createElement('input');
            input.type = 'text';
            input.value = value;
            input.readOnly = true;
            
            group.appendChild(labelEl);
            group.appendChild(input);
            return group;
        };
        
        auditDetails.appendChild(createFormGroup('Event ID', log.id));
        auditDetails.appendChild(createFormGroup('Timestamp', this.app.formatDate(log.timestamp)));
        auditDetails.appendChild(createFormGroup('Event Type', this.formatEventType(log.event_type)));
        auditDetails.appendChild(createFormGroup('Actor', log.actor?.username || log.actor?.id || 'System'));
        auditDetails.appendChild(createFormGroup('Action', log.action));
        auditDetails.appendChild(createFormGroup('Result', log.result));
        auditDetails.appendChild(createFormGroup('IP Address', log.ip_address || 'N/A'));
        
        modalBody.appendChild(auditDetails);
        modalContent.appendChild(modalHeader);
        modalContent.appendChild(modalBody);
        modal.appendChild(modalContent);
        
        // Add modal body content
        modalBody.innerHTML = `
            <div class="form-group">
                <label>Event Type</label>
                <input type="text" value="${this.formatEventType(log.event_type)}" readonly>
            </div>
        `;
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