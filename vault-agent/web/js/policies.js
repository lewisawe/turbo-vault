// Policies management functionality
class PoliciesManager {
    constructor(app) {
        this.app = app;
        this.policies = [];
        this.policyBuilder = new PolicyBuilder();
    }

    async loadData() {
        try {
            await this.loadPolicies();
        } catch (error) {
            console.error('Error loading policies data:', error);
            this.app.showAlert('Failed to load policies data', 'error');
        }
    }

    async loadPolicies() {
        try {
            const response = await this.app.apiRequest('/policies');
            this.policies = response.policies || [];
            this.renderPoliciesTable();
        } catch (error) {
            console.error('Error loading policies:', error);
            throw error;
        }
    }

    renderPoliciesTable() {
        const tbody = document.getElementById('policiesTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (this.policies.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No policies found</td></tr>';
            return;
        }

        this.policies.forEach(policy => {
            const row = this.createPolicyRow(policy);
            tbody.appendChild(row);
        });
    }

    createPolicyRow(policy) {
        const row = document.createElement('tr');
        const statusClass = policy.enabled ? 'status-enabled' : 'status-disabled';
        
        row.innerHTML = `
            <td>
                <div class="policy-name">${this.escapeHtml(policy.name)}</div>
                <div class="policy-id text-muted small">${policy.id}</div>
            </td>
            <td>${this.escapeHtml(policy.description || '')}</td>
            <td>${policy.priority || 100}</td>
            <td><span class="status-badge ${statusClass}">${policy.enabled ? 'Enabled' : 'Disabled'}</span></td>
            <td>${this.app.formatDate(policy.created_at)}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="viewPolicy('${policy.id}')" title="View Policy">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="editPolicy('${policy.id}')" title="Edit Policy">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="togglePolicy('${policy.id}', ${!policy.enabled})" title="${policy.enabled ? 'Disable' : 'Enable'} Policy">
                        <i class="fas fa-${policy.enabled ? 'pause' : 'play'}"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deletePolicy('${policy.id}')" title="Delete Policy">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        return row;
    }

    async createPolicy(policyData) {
        try {
            const response = await this.app.apiRequest('/policies', {
                method: 'POST',
                body: policyData
            });

            this.app.showAlert('Policy created successfully', 'success');
            await this.loadPolicies();
            return response;
        } catch (error) {
            console.error('Error creating policy:', error);
            this.app.showAlert(`Failed to create policy: ${error.message}`, 'error');
            throw error;
        }
    }

    async updatePolicy(policyId, updateData) {
        try {
            const response = await this.app.apiRequest(`/policies/${policyId}`, {
                method: 'PUT',
                body: updateData
            });

            this.app.showAlert('Policy updated successfully', 'success');
            await this.loadPolicies();
            return response;
        } catch (error) {
            console.error('Error updating policy:', error);
            this.app.showAlert(`Failed to update policy: ${error.message}`, 'error');
            throw error;
        }
    }

    async deletePolicy(policyId) {
        try {
            await this.app.apiRequest(`/policies/${policyId}`, {
                method: 'DELETE'
            });

            this.app.showAlert('Policy deleted successfully', 'success');
            await this.loadPolicies();
        } catch (error) {
            console.error('Error deleting policy:', error);
            this.app.showAlert(`Failed to delete policy: ${error.message}`, 'error');
            throw error;
        }
    }

    async getPolicy(policyId) {
        try {
            return await this.app.apiRequest(`/policies/${policyId}`);
        } catch (error) {
            console.error('Error getting policy:', error);
            throw error;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Policy Builder for visual policy creation
class PolicyBuilder {
    constructor() {
        this.rules = [];
        this.conditions = [];
    }

    createPolicyModal() {
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.id = 'policyBuilderModal';
        modal.innerHTML = `
            <div class="modal-content policy-builder">
                <div class="modal-header">
                    <h3>Policy Builder</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="policy-builder-tabs">
                        <button class="tab-btn active" onclick="showPolicyTab('basic')">Basic Info</button>
                        <button class="tab-btn" onclick="showPolicyTab('rules')">Rules</button>
                        <button class="tab-btn" onclick="showPolicyTab('conditions')">Conditions</button>
                        <button class="tab-btn" onclick="showPolicyTab('preview')">Preview</button>
                    </div>
                    
                    <div class="tab-content">
                        <!-- Basic Info Tab -->
                        <div id="basic-tab" class="tab-pane active">
                            <div class="form-group">
                                <label for="policyName">Policy Name *</label>
                                <input type="text" id="policyName" required>
                            </div>
                            <div class="form-group">
                                <label for="policyDescription">Description</label>
                                <textarea id="policyDescription" rows="3"></textarea>
                            </div>
                            <div class="form-group">
                                <label for="policyPriority">Priority</label>
                                <input type="number" id="policyPriority" value="100" min="1" max="1000">
                            </div>
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" id="policyEnabled" checked>
                                    Enable Policy
                                </label>
                            </div>
                        </div>
                        
                        <!-- Rules Tab -->
                        <div id="rules-tab" class="tab-pane">
                            <div class="rules-builder">
                                <div class="rules-header">
                                    <h4>Access Rules</h4>
                                    <button class="btn btn-sm btn-primary" onclick="addPolicyRule()">
                                        <i class="fas fa-plus"></i> Add Rule
                                    </button>
                                </div>
                                <div id="rulesContainer">
                                    <!-- Rules will be added here -->
                                </div>
                            </div>
                        </div>
                        
                        <!-- Conditions Tab -->
                        <div id="conditions-tab" class="tab-pane">
                            <div class="conditions-builder">
                                <div class="conditions-header">
                                    <h4>Access Conditions</h4>
                                    <button class="btn btn-sm btn-primary" onclick="addPolicyCondition()">
                                        <i class="fas fa-plus"></i> Add Condition
                                    </button>
                                </div>
                                <div id="conditionsContainer">
                                    <!-- Conditions will be added here -->
                                </div>
                            </div>
                        </div>
                        
                        <!-- Preview Tab -->
                        <div id="preview-tab" class="tab-pane">
                            <div class="policy-preview">
                                <h4>Policy Preview</h4>
                                <pre id="policyPreview"></pre>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="savePolicyFromBuilder()">Create Policy</button>
                </div>
            </div>
        `;
        
        return modal;
    }

    addRule() {
        const ruleId = `rule-${Date.now()}`;
        const ruleHtml = `
            <div class="rule-item" id="${ruleId}">
                <div class="rule-header">
                    <h5>Rule ${this.rules.length + 1}</h5>
                    <button class="btn btn-sm btn-danger" onclick="removeRule('${ruleId}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
                <div class="rule-content">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Effect</label>
                            <select class="rule-effect">
                                <option value="allow">Allow</option>
                                <option value="deny">Deny</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Actions</label>
                            <select class="rule-actions" multiple>
                                <option value="read">Read</option>
                                <option value="write">Write</option>
                                <option value="delete">Delete</option>
                                <option value="rotate">Rotate</option>
                                <option value="list">List</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Resources (patterns)</label>
                        <input type="text" class="rule-resources" placeholder="secrets/*, policies/admin-*">
                    </div>
                </div>
            </div>
        `;
        
        document.getElementById('rulesContainer').insertAdjacentHTML('beforeend', ruleHtml);
        this.rules.push({ id: ruleId });
    }

    addCondition() {
        const conditionId = `condition-${Date.now()}`;
        const conditionHtml = `
            <div class="condition-item" id="${conditionId}">
                <div class="condition-header">
                    <h5>Condition ${this.conditions.length + 1}</h5>
                    <button class="btn btn-sm btn-danger" onclick="removeCondition('${conditionId}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
                <div class="condition-content">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Type</label>
                            <select class="condition-type" onchange="updateConditionFields(this)">
                                <option value="time">Time-based</option>
                                <option value="ip">IP Address</option>
                                <option value="user">User/Role</option>
                                <option value="custom">Custom</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Operator</label>
                            <select class="condition-operator">
                                <option value="equals">Equals</option>
                                <option value="not_equals">Not Equals</option>
                                <option value="contains">Contains</option>
                                <option value="matches">Matches Pattern</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Value</label>
                        <input type="text" class="condition-value" placeholder="Enter condition value">
                    </div>
                </div>
            </div>
        `;
        
        document.getElementById('conditionsContainer').insertAdjacentHTML('beforeend', conditionHtml);
        this.conditions.push({ id: conditionId });
    }

    generatePolicy() {
        const policy = {
            name: document.getElementById('policyName').value,
            description: document.getElementById('policyDescription').value,
            priority: parseInt(document.getElementById('policyPriority').value),
            enabled: document.getElementById('policyEnabled').checked,
            rules: this.collectRules(),
            conditions: this.collectConditions()
        };
        
        return policy;
    }

    collectRules() {
        const rules = [];
        document.querySelectorAll('.rule-item').forEach(ruleElement => {
            const effect = ruleElement.querySelector('.rule-effect').value;
            const actions = Array.from(ruleElement.querySelector('.rule-actions').selectedOptions).map(opt => opt.value);
            const resources = ruleElement.querySelector('.rule-resources').value.split(',').map(r => r.trim()).filter(r => r);
            
            rules.push({ effect, actions, resources });
        });
        
        return rules;
    }

    collectConditions() {
        const conditions = [];
        document.querySelectorAll('.condition-item').forEach(conditionElement => {
            const type = conditionElement.querySelector('.condition-type').value;
            const operator = conditionElement.querySelector('.condition-operator').value;
            const value = conditionElement.querySelector('.condition-value').value;
            
            if (value) {
                conditions.push({ type, operator, value });
            }
        });
        
        return conditions;
    }
}

// Global functions for policies management
async function showCreatePolicyModal() {
    const policyBuilder = new PolicyBuilder();
    const modal = policyBuilder.createPolicyModal();
    document.body.appendChild(modal);
    
    // Initialize with one rule
    addPolicyRule();
}

function showPolicyTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.classList.add('active');
    
    // Update preview if preview tab is selected
    if (tabName === 'preview') {
        updatePolicyPreview();
    }
}

function addPolicyRule() {
    if (window.policyBuilder) {
        window.policyBuilder.addRule();
    } else {
        window.policyBuilder = new PolicyBuilder();
        window.policyBuilder.addRule();
    }
}

function addPolicyCondition() {
    if (window.policyBuilder) {
        window.policyBuilder.addCondition();
    } else {
        window.policyBuilder = new PolicyBuilder();
        window.policyBuilder.addCondition();
    }
}

function removeRule(ruleId) {
    document.getElementById(ruleId).remove();
}

function removeCondition(conditionId) {
    document.getElementById(conditionId).remove();
}

function updateConditionFields(selectElement) {
    const conditionItem = selectElement.closest('.condition-item');
    const valueInput = conditionItem.querySelector('.condition-value');
    const type = selectElement.value;
    
    switch (type) {
        case 'time':
            valueInput.placeholder = 'e.g., 09:00-17:00, Monday-Friday';
            break;
        case 'ip':
            valueInput.placeholder = 'e.g., 192.168.1.0/24, 10.0.0.1';
            break;
        case 'user':
            valueInput.placeholder = 'e.g., admin, developer, user:john';
            break;
        case 'custom':
            valueInput.placeholder = 'Custom condition expression';
            break;
    }
}

function updatePolicyPreview() {
    if (!window.policyBuilder) {
        window.policyBuilder = new PolicyBuilder();
    }
    
    const policy = window.policyBuilder.generatePolicy();
    document.getElementById('policyPreview').textContent = JSON.stringify(policy, null, 2);
}

async function savePolicyFromBuilder() {
    if (!window.policyBuilder) {
        return;
    }
    
    try {
        const policy = window.policyBuilder.generatePolicy();
        
        if (!policy.name) {
            app.showAlert('Policy name is required', 'error');
            return;
        }
        
        await window.policiesManager.createPolicy(policy);
        document.getElementById('policyBuilderModal').remove();
    } catch (error) {
        // Error already handled in createPolicy method
    }
}

async function viewPolicy(policyId) {
    try {
        const policy = await window.policiesManager.getPolicy(policyId);
        
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Policy Details</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="policy-details">
                        <div class="form-group">
                            <label>Name</label>
                            <input type="text" value="${policy.name}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea rows="3" readonly>${policy.description || ''}</textarea>
                        </div>
                        <div class="form-group">
                            <label>Priority</label>
                            <input type="number" value="${policy.priority}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Status</label>
                            <input type="text" value="${policy.enabled ? 'Enabled' : 'Disabled'}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Rules</label>
                            <pre>${JSON.stringify(policy.rules || [], null, 2)}</pre>
                        </div>
                        <div class="form-group">
                            <label>Conditions</label>
                            <pre>${JSON.stringify(policy.conditions || [], null, 2)}</pre>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Close</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    } catch (error) {
        app.showAlert(`Failed to load policy details: ${error.message}`, 'error');
    }
}

async function editPolicy(policyId) {
    try {
        const policy = await window.policiesManager.getPolicy(policyId);
        
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Edit Policy</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="editPolicyForm">
                        <div class="form-group">
                            <label>Name</label>
                            <input type="text" id="editPolicyName" value="${policy.name}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea id="editPolicyDescription" rows="3">${policy.description || ''}</textarea>
                        </div>
                        <div class="form-group">
                            <label>Priority</label>
                            <input type="number" id="editPolicyPriority" value="${policy.priority}" min="1" max="1000">
                        </div>
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="editPolicyEnabled" ${policy.enabled ? 'checked' : ''}>
                                Enable Policy
                            </label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="savePolicyEdit('${policyId}', this.closest('.modal'))">Save Changes</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    } catch (error) {
        app.showAlert(`Failed to load policy for editing: ${error.message}`, 'error');
    }
}

async function savePolicyEdit(policyId, modal) {
    const updateData = {
        description: document.getElementById('editPolicyDescription').value,
        priority: parseInt(document.getElementById('editPolicyPriority').value),
        enabled: document.getElementById('editPolicyEnabled').checked
    };
    
    try {
        await window.policiesManager.updatePolicy(policyId, updateData);
        modal.remove();
    } catch (error) {
        // Error already handled in updatePolicy method
    }
}

async function togglePolicy(policyId, enabled) {
    try {
        await window.policiesManager.updatePolicy(policyId, { enabled });
    } catch (error) {
        // Error already handled in updatePolicy method
    }
}

async function deletePolicy(policyId) {
    if (confirm('Are you sure you want to delete this policy? This action cannot be undone.')) {
        try {
            await window.policiesManager.deletePolicy(policyId);
        } catch (error) {
            // Error already handled in deletePolicy method
        }
    }
}

function refreshPolicies() {
    if (window.policiesManager) {
        window.policiesManager.loadData();
    }
}

VaultApp.prototype.loadPoliciesData = async function() {
    if (!this.policiesManager) {
        this.policiesManager = new PoliciesManager(this);
    }
    await this.policiesManager.loadData();
    window.policiesManager = this.policiesManager;
};