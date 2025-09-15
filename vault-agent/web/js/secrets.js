// Secrets management functionality
class SecretsManager {
    constructor(app) {
        this.app = app;
        this.secrets = [];
        this.filteredSecrets = [];
        this.currentFilter = {
            search: '',
            status: '',
            tag: ''
        };
    }

    async loadData() {
        try {
            await this.loadSecrets();
            await this.loadTags();
        } catch (error) {
            console.error('Error loading secrets data:', error);
            this.app.showAlert('Failed to load secrets data', 'error');
        }
    }

    async loadSecrets() {
        try {
            console.log('Loading secrets from API...');
            const response = await this.app.apiRequest('/secrets');
            console.log('API response:', response);
            this.secrets = response.data || [];
            this.filteredSecrets = [...this.secrets];
            console.log('Loaded secrets:', this.secrets.length);
            this.renderSecretsTable();
        } catch (error) {
            console.error('Error loading secrets:', error);
            throw error;
        }
    }

    async loadTags() {
        try {
            const response = await this.app.apiRequest('/secrets/tags');
            const tagFilter = document.getElementById('tagFilter');
            
            if (tagFilter && response.tags) {
                // Clear existing options except "All Tags"
                tagFilter.innerHTML = '<option value="">All Tags</option>';
                
                response.tags.forEach(tag => {
                    const option = document.createElement('option');
                    option.value = tag;
                    option.textContent = tag;
                    tagFilter.appendChild(option);
                });
            }
        } catch (error) {
            console.error('Error loading tags:', error);
        }
    }

    renderSecretsTable() {
        const tbody = document.getElementById('secretsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (this.filteredSecrets.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        ${this.secrets.length === 0 ? 'No secrets found' : 'No secrets match the current filter'}
                    </td>
                </tr>
            `;
            return;
        }

        this.filteredSecrets.forEach(secret => {
            const row = this.createSecretRow(secret);
            tbody.appendChild(row);
        });
    }

    createSecretRow(secret) {
        const row = document.createElement('tr');
        row.dataset.secretId = secret.id;
        
        const statusClass = this.getStatusClass(secret.status);
        const tags = secret.tags ? secret.tags.map(tag => `<span class="tag">${tag}</span>`).join('') : '';
        
        row.innerHTML = `
            <td>
                <div class="secret-name">${this.escapeHtml(secret.name)}</div>
                <div class="secret-id text-muted small">${secret.id}</div>
            </td>
            <td>
                <span class="status-badge ${statusClass}">${secret.status || 'active'}</span>
            </td>
            <td>${tags}</td>
            <td>${this.app.formatDate(secret.created_at)}</td>
            <td>${this.app.formatDate(secret.last_accessed)}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="viewSecret('${secret.id}')" title="View Secret">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="editSecret('${secret.id}')" title="Edit Secret">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="rotateSecret('${secret.id}')" title="Rotate Secret">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteSecret('${secret.id}')" title="Delete Secret">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        return row;
    }

    getStatusClass(status) {
        const statusClasses = {
            'active': 'status-active',
            'expired': 'status-expired',
            'rotating': 'status-rotating'
        };
        
        return statusClasses[status] || 'status-active';
    }

    filterSecrets() {
        const searchTerm = document.getElementById('secretSearch')?.value.toLowerCase() || '';
        const statusFilter = document.getElementById('statusFilter')?.value || '';
        const tagFilter = document.getElementById('tagFilter')?.value || '';

        this.currentFilter = {
            search: searchTerm,
            status: statusFilter,
            tag: tagFilter
        };

        this.filteredSecrets = this.secrets.filter(secret => {
            // Search filter
            if (searchTerm && !secret.name.toLowerCase().includes(searchTerm)) {
                return false;
            }

            // Status filter
            if (statusFilter && secret.status !== statusFilter) {
                return false;
            }

            // Tag filter
            if (tagFilter && (!secret.tags || !secret.tags.includes(tagFilter))) {
                return false;
            }

            return true;
        });

        this.renderSecretsTable();
    }

    async createSecret(secretData) {
        try {
            const response = await this.app.apiRequest('/secrets', {
                method: 'POST',
                body: secretData
            });

            this.app.showAlert('Secret created successfully', 'success');
            await this.loadSecrets();
            return response;
        } catch (error) {
            console.error('Error creating secret:', error);
            this.app.showAlert(`Failed to create secret: ${error.message}`, 'error');
            throw error;
        }
    }

    async updateSecret(secretId, updateData) {
        try {
            const response = await this.app.apiRequest(`/secrets/${secretId}`, {
                method: 'PUT',
                body: updateData
            });

            this.app.showAlert('Secret updated successfully', 'success');
            await this.loadSecrets();
            return response;
        } catch (error) {
            console.error('Error updating secret:', error);
            this.app.showAlert(`Failed to update secret: ${error.message}`, 'error');
            throw error;
        }
    }

    async deleteSecret(secretId) {
        try {
            await this.app.apiRequest(`/secrets/${secretId}`, {
                method: 'DELETE'
            });

            this.app.showAlert('Secret deleted successfully', 'success');
            await this.loadSecrets();
        } catch (error) {
            console.error('Error deleting secret:', error);
            this.app.showAlert(`Failed to delete secret: ${error.message}`, 'error');
            throw error;
        }
    }

    async rotateSecret(secretId) {
        try {
            const response = await this.app.apiRequest(`/secrets/${secretId}/rotate`, {
                method: 'POST'
            });

            this.app.showAlert('Secret rotation initiated', 'success');
            await this.loadSecrets();
            return response;
        } catch (error) {
            console.error('Error rotating secret:', error);
            this.app.showAlert(`Failed to rotate secret: ${error.message}`, 'error');
            throw error;
        }
    }

    async getSecret(secretId, includeValue = false) {
        try {
            const url = includeValue ? `/secrets/${secretId}?include_value=true` : `/secrets/${secretId}`;
            return await this.app.apiRequest(url);
        } catch (error) {
            console.error('Error getting secret:', error);
            throw error;
        }
    }

    updateSecretInTable(secretData) {
        // Update secret in the current list
        const index = this.secrets.findIndex(s => s.id === secretData.id);
        if (index !== -1) {
            this.secrets[index] = { ...this.secrets[index], ...secretData };
            this.filterSecrets(); // Re-apply filters and re-render
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions for secrets management
async function showCreateSecretModal() {
    showModal('createSecretModal');
    
    // Clear form
    document.getElementById('createSecretForm').reset();
}

async function createSecret() {
    const form = document.getElementById('createSecretForm');
    const formData = new FormData(form);
    
    const secretData = {
        name: document.getElementById('newSecretName').value,
        value: document.getElementById('newSecretValue').value,
        tags: document.getElementById('newSecretTags').value.split(',').map(t => t.trim()).filter(t => t),
        metadata: {}
    };
    
    const description = document.getElementById('newSecretDescription').value;
    if (description) {
        secretData.metadata.description = description;
    }
    
    const expiry = document.getElementById('newSecretExpiry').value;
    if (expiry) {
        secretData.expires_at = expiry;
    }
    
    try {
        await window.secretsManager.createSecret(secretData);
        closeModal('createSecretModal');
    } catch (error) {
        // Error already handled in createSecret method
    }
}

async function viewSecret(secretId) {
    try {
        const secret = await window.secretsManager.getSecret(secretId, true);
        
        // Create and show view modal
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Secret Details</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>Name</label>
                        <input type="text" value="${app.escapeHtml(secret.name)}" readonly>
                    </div>
                    <div class="form-group">
                        <label>Value</label>
                        <textarea rows="4" readonly>${secret.value || '[Value not retrieved]'}</textarea>
                    </div>
                    <div class="form-group">
                        <label>Status</label>
                        <input type="text" value="${secret.status || 'active'}" readonly>
                    </div>
                    <div class="form-group">
                        <label>Tags</label>
                        <input type="text" value="${(secret.tags || []).join(', ')}" readonly>
                    </div>
                    <div class="form-group">
                        <label>Created</label>
                        <input type="text" value="${app.formatDate(secret.created_at)}" readonly>
                    </div>
                    <div class="form-group">
                        <label>Last Accessed</label>
                        <input type="text" value="${app.formatDate(secret.last_accessed)}" readonly>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Close</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    } catch (error) {
        app.showAlert(`Failed to load secret details: ${error.message}`, 'error');
    }
}

async function editSecret(secretId) {
    try {
        const secret = await window.secretsManager.getSecret(secretId);
        
        // Create and show edit modal
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Edit Secret</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="editSecretForm">
                        <div class="form-group">
                            <label>Name</label>
                            <input type="text" id="editSecretName" value="${secret.name}" readonly>
                        </div>
                        <div class="form-group">
                            <label>New Value</label>
                            <textarea id="editSecretValue" rows="4" placeholder="Enter new value..."></textarea>
                        </div>
                        <div class="form-group">
                            <label>Tags</label>
                            <input type="text" id="editSecretTags" value="${(secret.tags || []).join(', ')}" placeholder="tag1, tag2, tag3">
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea id="editSecretDescription" rows="2">${secret.metadata?.description || ''}</textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="saveSecretEdit('${secretId}', this.closest('.modal'))">Save Changes</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    } catch (error) {
        app.showAlert(`Failed to load secret for editing: ${error.message}`, 'error');
    }
}

async function saveSecretEdit(secretId, modal) {
    const updateData = {};
    
    const newValue = document.getElementById('editSecretValue').value;
    if (newValue) {
        updateData.value = newValue;
    }
    
    const tags = document.getElementById('editSecretTags').value;
    updateData.tags = tags.split(',').map(t => t.trim()).filter(t => t);
    
    const description = document.getElementById('editSecretDescription').value;
    updateData.metadata = { description };
    
    try {
        await window.secretsManager.updateSecret(secretId, updateData);
        modal.remove();
    } catch (error) {
        // Error already handled in updateSecret method
    }
}

async function rotateSecret(secretId) {
    if (confirm('Are you sure you want to rotate this secret? This will generate a new value.')) {
        try {
            await window.secretsManager.rotateSecret(secretId);
        } catch (error) {
            // Error already handled in rotateSecret method
        }
    }
}

async function deleteSecret(secretId) {
    if (confirm('Are you sure you want to delete this secret? This action cannot be undone.')) {
        try {
            await window.secretsManager.deleteSecret(secretId);
        } catch (error) {
            // Error already handled in deleteSecret method
        }
    }
}

function filterSecrets() {
    if (window.secretsManager) {
        window.secretsManager.filterSecrets();
    }
}

function refreshSecrets() {
    if (window.secretsManager) {
        window.secretsManager.loadData();
    }
}

// Extend VaultApp to include secrets functionality
VaultApp.prototype.loadSecretsData = async function() {
    if (!this.secretsManager) {
        this.secretsManager = new SecretsManager(this);
    }
    
    await this.secretsManager.loadData();
    window.secretsManager = this.secretsManager;
};

VaultApp.prototype.handleSecretUpdate = function(secretData) {
    if (this.secretsManager) {
        this.secretsManager.updateSecretInTable(secretData);
    }
};