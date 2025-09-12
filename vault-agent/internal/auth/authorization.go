package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/keyvault/agent/internal/policy"
)

// DefaultAuthorizationManager implements the AuthorizationManager interface
type DefaultAuthorizationManager struct {
	roleManager       RoleManager
	permissionManager PermissionManager
	policyEngine      policy.PolicyEngine
	auditLogger       AuditLogger
	config           *AuthzConfig
	logger           *logrus.Logger
}

// AuthzConfig contains authorization configuration
type AuthzConfig struct {
	// Policy evaluation
	DefaultDeny          bool          `json:"default_deny"`
	CacheEnabled         bool          `json:"cache_enabled"`
	CacheTTL            time.Duration `json:"cache_ttl"`
	EvaluationTimeout   time.Duration `json:"evaluation_timeout"`
	
	// Role hierarchy
	EnableRoleHierarchy bool `json:"enable_role_hierarchy"`
	MaxRoleDepth        int  `json:"max_role_depth"`
	
	// Permission inheritance
	InheritPermissions  bool `json:"inherit_permissions"`
	
	// Audit configuration
	LogAllDecisions     bool `json:"log_all_decisions"`
	LogDeniedOnly       bool `json:"log_denied_only"`
}

// NewDefaultAuthorizationManager creates a new authorization manager
func NewDefaultAuthorizationManager(
	roleManager RoleManager,
	permissionManager PermissionManager,
	policyEngine policy.PolicyEngine,
	auditLogger AuditLogger,
	config *AuthzConfig,
	logger *logrus.Logger,
) *DefaultAuthorizationManager {
	if config == nil {
		config = DefaultAuthzConfig()
	}

	return &DefaultAuthorizationManager{
		roleManager:       roleManager,
		permissionManager: permissionManager,
		policyEngine:      policyEngine,
		auditLogger:       auditLogger,
		config:           config,
		logger:           logger,
	}
}

// DefaultAuthzConfig returns default authorization configuration
func DefaultAuthzConfig() *AuthzConfig {
	return &AuthzConfig{
		DefaultDeny:         true,
		CacheEnabled:        true,
		CacheTTL:           5 * time.Minute,
		EvaluationTimeout:  5 * time.Second,
		EnableRoleHierarchy: true,
		MaxRoleDepth:       10,
		InheritPermissions: true,
		LogAllDecisions:    false,
		LogDeniedOnly:      true,
	}
}

// Permission Checks

func (am *DefaultAuthorizationManager) HasPermission(ctx context.Context, user *User, resource, action string) (bool, error) {
	startTime := time.Now()
	
	// Create access request
	request := &AccessRequest{
		UserID:    user.ID,
		Username:  user.Username,
		Resource:  resource,
		Action:    action,
		Context:   make(map[string]interface{}),
		IPAddress: getIPFromContext(ctx),
		UserAgent: getUserAgentFromContext(ctx),
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	// Check access
	decision, err := am.CheckAccess(ctx, user, request)
	if err != nil {
		return false, err
	}

	// Log decision if configured
	if am.config.LogAllDecisions || (am.config.LogDeniedOnly && !decision.Allowed) {
		am.logAuthzEvent(ctx, request, decision, time.Since(startTime))
	}

	return decision.Allowed, nil
}

func (am *DefaultAuthorizationManager) CheckAccess(ctx context.Context, user *User, request *AccessRequest) (*AccessDecision, error) {
	startTime := time.Now()
	
	// Set evaluation timeout
	evalCtx, cancel := context.WithTimeout(ctx, am.config.EvaluationTimeout)
	defer cancel()

	decision := &AccessDecision{
		Allowed:        false,
		Reason:         "Access denied by default policy",
		RequiredRoles:  []string{},
		RequiredPerms:  []string{},
		MatchedRoles:   []string{},
		MatchedPerms:   []string{},
		Conditions:     []string{},
		Metadata:       make(map[string]interface{}),
		EvaluationTime: 0, // Will be set at the end
		RequestID:      request.RequestID,
		Timestamp:      time.Now(),
	}

	// Check if user is active
	if user.Status != UserStatusActive {
		decision.Reason = fmt.Sprintf("User account is not active: %s", user.Status)
		decision.EvaluationTime = time.Since(startTime)
		return decision, nil
	}

	// Get user's effective roles (including inherited roles)
	effectiveRoles, err := am.getUserEffectiveRoles(evalCtx, user)
	if err != nil {
		decision.Reason = fmt.Sprintf("Failed to get user roles: %v", err)
		decision.EvaluationTime = time.Since(startTime)
		return decision, nil
	}

	// Get user's effective permissions (from roles and direct assignments)
	effectivePermissions, err := am.getUserEffectivePermissions(evalCtx, user, effectiveRoles)
	if err != nil {
		decision.Reason = fmt.Sprintf("Failed to get user permissions: %v", err)
		decision.EvaluationTime = time.Since(startTime)
		return decision, nil
	}

	// Check direct permissions first
	allowed, matchedPerms := am.checkDirectPermissions(effectivePermissions, request.Resource, request.Action)
	if allowed {
		decision.Allowed = true
		decision.Reason = "Access granted by direct permission"
		decision.MatchedPerms = matchedPerms
		decision.MatchedRoles = extractRoleNames(effectiveRoles)
		decision.EvaluationTime = time.Since(startTime)
		return decision, nil
	}

	// If policy engine is available, use it for advanced evaluation
	if am.policyEngine != nil {
		policyDecision, err := am.evaluateWithPolicyEngine(evalCtx, user, request, effectiveRoles)
		if err != nil {
			am.logger.WithError(err).Warn("Policy engine evaluation failed, falling back to basic RBAC")
		} else {
			// Merge policy decision with RBAC results
			decision.Allowed = policyDecision.Decision == policy.PolicyEffectAllow
			if decision.Allowed {
				decision.Reason = "Access granted by policy"
			} else {
				decision.Reason = "Access denied by policy"
			}
			decision.MatchedRoles = extractRoleNames(effectiveRoles)
			decision.MatchedPerms = matchedPerms
			decision.Metadata["policy_evaluation"] = true
			decision.EvaluationTime = time.Since(startTime)
			return decision, nil
		}
	}

	// Check role-based permissions
	for _, role := range effectiveRoles {
		rolePermissions, err := am.permissionManager.ListPermissions(evalCtx, &PermissionFilter{
			IDs: role.Permissions,
		})
		if err != nil {
			am.logger.WithError(err).WithField("role_id", role.ID).Warn("Failed to get role permissions")
			continue
		}

		allowed, perms := am.checkDirectPermissions(rolePermissions, request.Resource, request.Action)
		if allowed {
			decision.Allowed = true
			decision.Reason = fmt.Sprintf("Access granted by role: %s", role.Name)
			decision.MatchedRoles = append(decision.MatchedRoles, role.Name)
			decision.MatchedPerms = append(decision.MatchedPerms, perms...)
			decision.EvaluationTime = time.Since(startTime)
			return decision, nil
		}
	}

	// No permissions matched
	decision.Reason = "No matching permissions found"
	decision.RequiredPerms = []string{fmt.Sprintf("%s:%s", request.Resource, request.Action)}
	decision.EvaluationTime = time.Since(startTime)
	return decision, nil
}

// Role Management

func (am *DefaultAuthorizationManager) AssignRole(ctx context.Context, userID, roleID string) error {
	// Get user
	user, err := am.getUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Get role
	role, err := am.roleManager.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if user already has the role
	for _, existingRoleID := range user.Roles {
		if existingRoleID == roleID {
			return fmt.Errorf("user already has role: %s", role.Name)
		}
	}

	// Add role to user
	user.Roles = append(user.Roles, roleID)
	
	// Update user (this would be implemented by the user manager)
	// For now, we'll just log the assignment
	
	// Log role assignment
	if am.auditLogger != nil {
		am.auditLogger.LogRoleEvent(ctx, &RoleEvent{
			EventID:     uuid.New().String(),
			EventType:   RoleEventAssigned,
			RoleID:      roleID,
			RoleName:    role.Name,
			UserID:      userID,
			PerformedBy: getUserIDFromContext(ctx),
			Timestamp:   time.Now(),
		})
	}

	am.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"role_id": roleID,
		"role_name": role.Name,
	}).Info("Role assigned to user")

	return nil
}

func (am *DefaultAuthorizationManager) RevokeRole(ctx context.Context, userID, roleID string) error {
	// Get user
	user, err := am.getUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Get role
	role, err := am.roleManager.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Remove role from user
	var newRoles []string
	found := false
	for _, existingRoleID := range user.Roles {
		if existingRoleID != roleID {
			newRoles = append(newRoles, existingRoleID)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("user does not have role: %s", role.Name)
	}

	user.Roles = newRoles
	
	// Update user (this would be implemented by the user manager)
	
	// Log role revocation
	if am.auditLogger != nil {
		am.auditLogger.LogRoleEvent(ctx, &RoleEvent{
			EventID:     uuid.New().String(),
			EventType:   RoleEventRevoked,
			RoleID:      roleID,
			RoleName:    role.Name,
			UserID:      userID,
			PerformedBy: getUserIDFromContext(ctx),
			Timestamp:   time.Now(),
		})
	}

	am.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"role_id": roleID,
		"role_name": role.Name,
	}).Info("Role revoked from user")

	return nil
}

func (am *DefaultAuthorizationManager) GetUserRoles(ctx context.Context, userID string) ([]*Role, error) {
	user, err := am.getUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	var roles []*Role
	for _, roleID := range user.Roles {
		role, err := am.roleManager.GetRole(ctx, roleID)
		if err != nil {
			am.logger.WithError(err).WithField("role_id", roleID).Warn("Failed to get role")
			continue
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// Permission Management

func (am *DefaultAuthorizationManager) GrantPermission(ctx context.Context, roleID string, permission *Permission) error {
	// Get role
	role, err := am.roleManager.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if role already has the permission
	for _, existingPermID := range role.Permissions {
		if existingPermID == permission.ID {
			return fmt.Errorf("role already has permission: %s", permission.Name)
		}
	}

	// Add permission to role
	role.Permissions = append(role.Permissions, permission.ID)
	
	// Update role (this would be implemented by the role manager)
	
	am.logger.WithFields(logrus.Fields{
		"role_id": roleID,
		"permission_id": permission.ID,
		"permission_name": permission.Name,
	}).Info("Permission granted to role")

	return nil
}

func (am *DefaultAuthorizationManager) RevokePermission(ctx context.Context, roleID string, permissionID string) error {
	// Get role
	role, err := am.roleManager.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Remove permission from role
	var newPermissions []string
	found := false
	for _, existingPermID := range role.Permissions {
		if existingPermID != permissionID {
			newPermissions = append(newPermissions, existingPermID)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("role does not have permission: %s", permissionID)
	}

	role.Permissions = newPermissions
	
	// Update role (this would be implemented by the role manager)
	
	am.logger.WithFields(logrus.Fields{
		"role_id": roleID,
		"permission_id": permissionID,
	}).Info("Permission revoked from role")

	return nil
}

func (am *DefaultAuthorizationManager) GetRolePermissions(ctx context.Context, roleID string) ([]*Permission, error) {
	role, err := am.roleManager.GetRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	var permissions []*Permission
	for _, permissionID := range role.Permissions {
		permission, err := am.permissionManager.GetPermission(ctx, permissionID)
		if err != nil {
			am.logger.WithError(err).WithField("permission_id", permissionID).Warn("Failed to get permission")
			continue
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// Helper methods

func (am *DefaultAuthorizationManager) getUserEffectiveRoles(ctx context.Context, user *User) ([]*Role, error) {
	var effectiveRoles []*Role
	visited := make(map[string]bool)

	// Get direct roles
	for _, roleID := range user.Roles {
		if visited[roleID] {
			continue
		}

		role, err := am.roleManager.GetRole(ctx, roleID)
		if err != nil {
			am.logger.WithError(err).WithField("role_id", roleID).Warn("Failed to get role")
			continue
		}

		effectiveRoles = append(effectiveRoles, role)
		visited[roleID] = true

		// Get inherited roles if hierarchy is enabled
		if am.config.EnableRoleHierarchy {
			inheritedRoles, err := am.getInheritedRoles(ctx, role, visited, 0)
			if err != nil {
				am.logger.WithError(err).WithField("role_id", roleID).Warn("Failed to get inherited roles")
				continue
			}
			effectiveRoles = append(effectiveRoles, inheritedRoles...)
		}
	}

	return effectiveRoles, nil
}

func (am *DefaultAuthorizationManager) getInheritedRoles(ctx context.Context, role *Role, visited map[string]bool, depth int) ([]*Role, error) {
	if depth >= am.config.MaxRoleDepth {
		return nil, fmt.Errorf("maximum role hierarchy depth exceeded")
	}

	var inheritedRoles []*Role

	for _, parentRoleID := range role.ParentRoles {
		if visited[parentRoleID] {
			continue // Avoid cycles
		}

		parentRole, err := am.roleManager.GetRole(ctx, parentRoleID)
		if err != nil {
			am.logger.WithError(err).WithField("parent_role_id", parentRoleID).Warn("Failed to get parent role")
			continue
		}

		inheritedRoles = append(inheritedRoles, parentRole)
		visited[parentRoleID] = true

		// Recursively get parent roles
		grandParentRoles, err := am.getInheritedRoles(ctx, parentRole, visited, depth+1)
		if err != nil {
			am.logger.WithError(err).WithField("parent_role_id", parentRoleID).Warn("Failed to get grandparent roles")
			continue
		}
		inheritedRoles = append(inheritedRoles, grandParentRoles...)
	}

	return inheritedRoles, nil
}

func (am *DefaultAuthorizationManager) getUserEffectivePermissions(ctx context.Context, user *User, roles []*Role) ([]*Permission, error) {
	var effectivePermissions []*Permission
	permissionMap := make(map[string]*Permission)

	// Add direct user permissions
	for _, permissionID := range user.Permissions {
		permission, err := am.permissionManager.GetPermission(ctx, permissionID)
		if err != nil {
			am.logger.WithError(err).WithField("permission_id", permissionID).Warn("Failed to get user permission")
			continue
		}
		permissionMap[permission.ID] = permission
	}

	// Add role permissions
	for _, role := range roles {
		for _, permissionID := range role.Permissions {
			if _, exists := permissionMap[permissionID]; exists {
				continue // Already have this permission
			}

			permission, err := am.permissionManager.GetPermission(ctx, permissionID)
			if err != nil {
				am.logger.WithError(err).WithField("permission_id", permissionID).Warn("Failed to get role permission")
				continue
			}
			permissionMap[permission.ID] = permission
		}
	}

	// Convert map to slice
	for _, permission := range permissionMap {
		effectivePermissions = append(effectivePermissions, permission)
	}

	return effectivePermissions, nil
}

func (am *DefaultAuthorizationManager) checkDirectPermissions(permissions []*Permission, resource, action string) (bool, []string) {
	var matchedPermissions []string

	for _, permission := range permissions {
		if am.permissionMatches(permission, resource, action) {
			matchedPermissions = append(matchedPermissions, permission.Name)
			
			// If it's an allow permission, grant access
			if permission.Effect == PermissionEffectAllow {
				return true, matchedPermissions
			}
		}
	}

	// Check for explicit deny
	for _, permission := range permissions {
		if am.permissionMatches(permission, resource, action) && permission.Effect == PermissionEffectDeny {
			return false, matchedPermissions
		}
	}

	return false, matchedPermissions
}

func (am *DefaultAuthorizationManager) permissionMatches(permission *Permission, resource, action string) bool {
	// Check resource match
	if !am.resourceMatches(permission.Resource, resource) {
		return false
	}

	// Check action match
	if !am.actionMatches(permission.Action, action) {
		return false
	}

	return true
}

func (am *DefaultAuthorizationManager) resourceMatches(permissionResource, requestResource string) bool {
	// Exact match
	if permissionResource == requestResource {
		return true
	}

	// Wildcard match
	if permissionResource == "*" {
		return true
	}

	// Prefix match with wildcard
	if strings.HasSuffix(permissionResource, "*") {
		prefix := strings.TrimSuffix(permissionResource, "*")
		return strings.HasPrefix(requestResource, prefix)
	}

	// Suffix match with wildcard
	if strings.HasPrefix(permissionResource, "*") {
		suffix := strings.TrimPrefix(permissionResource, "*")
		return strings.HasSuffix(requestResource, suffix)
	}

	return false
}

func (am *DefaultAuthorizationManager) actionMatches(permissionAction, requestAction string) bool {
	// Exact match
	if permissionAction == requestAction {
		return true
	}

	// Wildcard match
	if permissionAction == "*" {
		return true
	}

	return false
}

func (am *DefaultAuthorizationManager) evaluateWithPolicyEngine(ctx context.Context, user *User, request *AccessRequest, roles []*Role) (*policy.AccessDecision, error) {
	// Convert auth request to policy request
	policyRequest := &policy.AccessRequest{
		Principal: user.Username,
		Resource:  request.Resource,
		Action:    request.Action,
		Context: &policy.RequestContext{
			UserID:    user.ID,
			Username:  user.Username,
			Roles:     extractRoleNames(roles),
			Groups:    user.Groups,
			IPAddress: request.IPAddress,
			UserAgent: request.UserAgent,
			SessionID: request.SessionID,
			Timestamp: request.Timestamp,
			Attributes: request.Context,
		},
		Attributes: request.Context,
		RequestID:  request.RequestID,
		Timestamp:  request.Timestamp,
	}

	return am.policyEngine.EvaluateAccess(ctx, policyRequest)
}

func (am *DefaultAuthorizationManager) logAuthzEvent(ctx context.Context, request *AccessRequest, decision *AccessDecision, duration time.Duration) {
	if am.auditLogger == nil {
		return
	}

	event := &AuthorizationEvent{
		EventID:      uuid.New().String(),
		EventType:    AuthzEventAccessGranted,
		UserID:       request.UserID,
		Username:     request.Username,
		Resource:     request.Resource,
		Action:       request.Action,
		Decision:     decision.Allowed,
		Reason:       decision.Reason,
		IPAddress:    request.IPAddress,
		UserAgent:    request.UserAgent,
		SessionID:    request.SessionID,
		RequestID:    request.RequestID,
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"evaluation_time_ms": duration.Milliseconds(),
			"matched_roles":      decision.MatchedRoles,
			"matched_permissions": decision.MatchedPerms,
		},
	}

	if !decision.Allowed {
		event.EventType = AuthzEventAccessDenied
	}

	if err := am.auditLogger.LogAuthorization(ctx, event); err != nil {
		am.logger.WithError(err).Error("Failed to log authorization event")
	}
}

// Helper functions

func extractRoleNames(roles []*Role) []string {
	var names []string
	for _, role := range roles {
		names = append(names, role.Name)
	}
	return names
}

func (am *DefaultAuthorizationManager) getUserByID(ctx context.Context, userID string) (*User, error) {
	// This would be implemented by injecting a user manager
	// For now, return a placeholder
	return &User{ID: userID}, nil
}

func getUserIDFromContext(ctx context.Context) string {
	// Implementation depends on your context structure
	return ""
}