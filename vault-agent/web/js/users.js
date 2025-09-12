// Users management functionality
class UsersManager {
    constructor(app) {
        this.app = app;
        this.users = [];
    }

    async loadData() {
        try {
            await this.loadUsers();
        } catch (error) {
            console.error('Error loading users data:', error);
            this.app.showAlert('Failed to load users data', 'error');
        }
    }

    async loadUsers() {
        try {
            const response = await this.app.apiRequest('/users');
            this.users = response.users || [];
            this.renderUsersTable();
        } catch (error) {
            console.error('Error loading users:', error);
            throw error;
        }
    }

    renderUsersTable() {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (this.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No users found</td></tr>';
            return;
        }

        this.users.forEach(user => {
            const row = this.createUserRow(user);
            tbody.appendChild(row);
        });
    }

    createUserRow(user) {
        const row = document.createElement('tr');
        const statusClass = user.status === 'active' ? 'status-active' : 'status-disabled';
        const roles = user.roles ? user.roles.map(role => `<span class="tag">${role}</span>`).join('') : '';
        
        row.innerHTML = `
            <td>
                <div class="user-name">${this.escapeHtml(user.username)}</div>
                <div class="user-id text-muted small">${user.id}</div>
            </td>
            <td>${this.escapeHtml(user.email || '')}</td>
            <td>${roles}</td>
            <td><span class="status-badge ${statusClass}">${user.status || 'active'}</span></td>
            <td>${this.app.formatDate(user.last_login)}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="viewUser('${user.id}')" title="View User">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="editUser('${user.id}')" title="Edit User">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="resetUserPassword('${user.id}')" title="Reset Password">
                        <i class="fas fa-key"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.id}')" title="Delete User">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        return row;
    }

    async createUser(userData) {
        try {
            const response = await this.app.apiRequest('/users', {
                method: 'POST',
                body: userData
            });

            this.app.showAlert('User created successfully', 'success');
            await this.loadUsers();
            return response;
        } catch (error) {
            console.error('Error creating user:', error);
            this.app.showAlert(`Failed to create user: ${error.message}`, 'error');
            throw error;
        }
    }

    async updateUser(userId, updateData) {
        try {
            const response = await this.app.apiRequest(`/users/${userId}`, {
                method: 'PUT',
                body: updateData
            });

            this.app.showAlert('User updated successfully', 'success');
            await this.loadUsers();
            return response;
        } catch (error) {
            console.error('Error updating user:', error);
            this.app.showAlert(`Failed to update user: ${error.message}`, 'error');
            throw error;
        }
    }

    async deleteUser(userId) {
        try {
            await this.app.apiRequest(`/users/${userId}`, {
                method: 'DELETE'
            });

            this.app.showAlert('User deleted successfully', 'success');
            await this.loadUsers();
        } catch (error) {
            console.error('Error deleting user:', error);
            this.app.showAlert(`Failed to delete user: ${error.message}`, 'error');
            throw error;
        }
    }

    async getUser(userId) {
        try {
            return await this.app.apiRequest(`/users/${userId}`);
        } catch (error) {
            console.error('Error getting user:', error);
            throw error;
        }
    }

    async resetPassword(userId) {
        try {
            const response = await this.app.apiRequest(`/users/${userId}/reset-password`, {
                method: 'POST'
            });

            this.app.showAlert('Password reset successfully', 'success');
            return response;
        } catch (error) {
            console.error('Error resetting password:', error);
            this.app.showAlert(`Failed to reset password: ${error.message}`, 'error');
            throw error;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions for user management
async function showCreateUserModal() {
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Create New User</h3>
                <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
            </div>
            <div class="modal-body">
                <form id="createUserForm">
                    <div class="form-group">
                        <label for="newUserUsername">Username *</label>
                        <input type="text" id="newUserUsername" required>
                    </div>
                    <div class="form-group">
                        <label for="newUserEmail">Email</label>
                        <input type="email" id="newUserEmail">
                    </div>
                    <div class="form-group">
                        <label for="newUserPassword">Password *</label>
                        <input type="password" id="newUserPassword" required>
                    </div>
                    <div class="form-group">
                        <label for="newUserRoles">Roles (comma-separated)</label>
                        <input type="text" id="newUserRoles" placeholder="admin, developer, viewer">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="newUserActive" checked>
                            Active User
                        </label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                <button class="btn btn-primary" onclick="createUser()">Create User</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

async function createUser() {
    const userData = {
        username: document.getElementById('newUserUsername').value,
        email: document.getElementById('newUserEmail').value,
        password: document.getElementById('newUserPassword').value,
        roles: document.getElementById('newUserRoles').value.split(',').map(r => r.trim()).filter(r => r),
        status: document.getElementById('newUserActive').checked ? 'active' : 'inactive'
    };
    
    if (!userData.username || !userData.password) {
        app.showAlert('Username and password are required', 'error');
        return;
    }
    
    try {
        await window.usersManager.createUser(userData);
        document.querySelector('.modal').remove();
    } catch (error) {
        // Error already handled in createUser method
    }
}

async function viewUser(userId) {
    try {
        const user = await window.usersManager.getUser(userId);
        
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>User Details</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="user-details">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" value="${user.username}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="text" value="${user.email || ''}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Roles</label>
                            <input type="text" value="${(user.roles || []).join(', ')}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Status</label>
                            <input type="text" value="${user.status || 'active'}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Created</label>
                            <input type="text" value="${app.formatDate(user.created_at)}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Last Login</label>
                            <input type="text" value="${app.formatDate(user.last_login)}" readonly>
                        </div>
                        <div class="form-group">
                            <label>API Keys</label>
                            <div class="api-keys-list">
                                ${(user.api_keys || []).map(key => `
                                    <div class="api-key-item">
                                        <span>${key.name}</span>
                                        <span class="text-muted">${app.formatDate(key.created_at)}</span>
                                    </div>
                                `).join('')}
                            </div>
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
        app.showAlert(`Failed to load user details: ${error.message}`, 'error');
    }
}

async function editUser(userId) {
    try {
        const user = await window.usersManager.getUser(userId);
        
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Edit User</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="editUserForm">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" id="editUserUsername" value="${user.username}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" id="editUserEmail" value="${user.email || ''}">
                        </div>
                        <div class="form-group">
                            <label>Roles</label>
                            <input type="text" id="editUserRoles" value="${(user.roles || []).join(', ')}" placeholder="admin, developer, viewer">
                        </div>
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="editUserActive" ${user.status === 'active' ? 'checked' : ''}>
                                Active User
                            </label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="saveUserEdit('${userId}', this.closest('.modal'))">Save Changes</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    } catch (error) {
        app.showAlert(`Failed to load user for editing: ${error.message}`, 'error');
    }
}

async function saveUserEdit(userId, modal) {
    const updateData = {
        email: document.getElementById('editUserEmail').value,
        roles: document.getElementById('editUserRoles').value.split(',').map(r => r.trim()).filter(r => r),
        status: document.getElementById('editUserActive').checked ? 'active' : 'inactive'
    };
    
    try {
        await window.usersManager.updateUser(userId, updateData);
        modal.remove();
    } catch (error) {
        // Error already handled in updateUser method
    }
}

async function resetUserPassword(userId) {
    if (confirm('Are you sure you want to reset this user\'s password? A new temporary password will be generated.')) {
        try {
            const response = await window.usersManager.resetPassword(userId);
            
            // Show the new password in a modal
            const modal = document.createElement('div');
            modal.className = 'modal active';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Password Reset</h3>
                        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-warning">
                            <strong>Important:</strong> Please save this temporary password and share it securely with the user.
                        </div>
                        <div class="form-group">
                            <label>New Temporary Password</label>
                            <div class="password-display">
                                <input type="text" value="${response.temporary_password}" readonly>
                                <button class="btn btn-sm btn-secondary" onclick="copyToClipboard(this.previousElementSibling.value)">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        <p class="text-muted">The user will be required to change this password on their next login.</p>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" onclick="this.closest('.modal').remove()">Close</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        } catch (error) {
            // Error already handled in resetPassword method
        }
    }
}

async function deleteUser(userId) {
    if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        try {
            await window.usersManager.deleteUser(userId);
        } catch (error) {
            // Error already handled in deleteUser method
        }
    }
}

function refreshUsers() {
    if (window.usersManager) {
        window.usersManager.loadData();
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        app.showAlert('Copied to clipboard', 'success');
    }).catch(() => {
        app.showAlert('Failed to copy to clipboard', 'error');
    });
}

VaultApp.prototype.loadUsersData = async function() {
    if (!this.usersManager) {
        this.usersManager = new UsersManager(this);
    }
    await this.usersManager.loadData();
    window.usersManager = this.usersManager;
};