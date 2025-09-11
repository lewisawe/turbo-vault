package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// SQLPolicyStorage implements PolicyStorage using SQL database
type SQLPolicyStorage struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewSQLPolicyStorage creates a new SQL-based policy storage
func NewSQLPolicyStorage(db *sql.DB, logger *logrus.Logger) *SQLPolicyStorage {
	return &SQLPolicyStorage{
		db:     db,
		logger: logger,
	}
}

// CreatePolicy creates a new policy in the database
func (s *SQLPolicyStorage) CreatePolicy(ctx context.Context, policy *Policy) error {
	query := `
		INSERT INTO policies (
			id, name, description, rules, conditions, actions, priority, 
			enabled, version, created_at, updated_at, created_by, tags, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// Marshal complex fields to JSON
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(policy.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	tagsJSON, err := json.Marshal(policy.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(policy.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Description, string(rulesJSON),
		string(conditionsJSON), string(actionsJSON), policy.Priority,
		policy.Enabled, policy.Version, policy.CreatedAt, policy.UpdatedAt,
		policy.CreatedBy, string(tagsJSON), string(metadataJSON))

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
	}).Info("Policy created in storage")

	return nil
}

// UpdatePolicy updates an existing policy in the database
func (s *SQLPolicyStorage) UpdatePolicy(ctx context.Context, id string, policy *Policy) error {
	query := `
		UPDATE policies SET 
			name = ?, description = ?, rules = ?, conditions = ?, actions = ?, 
			priority = ?, enabled = ?, version = ?, updated_at = ?, tags = ?, metadata = ?
		WHERE id = ?`

	// Marshal complex fields to JSON
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(policy.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	tagsJSON, err := json.Marshal(policy.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(policy.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	result, err := s.db.ExecContext(ctx, query,
		policy.Name, policy.Description, string(rulesJSON),
		string(conditionsJSON), string(actionsJSON), policy.Priority,
		policy.Enabled, policy.Version, policy.UpdatedAt,
		string(tagsJSON), string(metadataJSON), id)

	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("policy not found: %s", id)
	}

	s.logger.WithFields(logrus.Fields{
		"policy_id":   id,
		"policy_name": policy.Name,
		"version":     policy.Version,
	}).Info("Policy updated in storage")

	return nil
}

// DeletePolicy deletes a policy from the database
func (s *SQLPolicyStorage) DeletePolicy(ctx context.Context, id string) error {
	query := `DELETE FROM policies WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("policy not found: %s", id)
	}

	s.logger.WithField("policy_id", id).Info("Policy deleted from storage")
	return nil
}

// GetPolicy retrieves a policy by ID
func (s *SQLPolicyStorage) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	query := `
		SELECT id, name, description, rules, conditions, actions, priority, 
			   enabled, version, created_at, updated_at, created_by, tags, metadata
		FROM policies WHERE id = ?`

	row := s.db.QueryRowContext(ctx, query, id)

	policy := &Policy{}
	var rulesJSON, conditionsJSON, actionsJSON, tagsJSON, metadataJSON string

	err := row.Scan(
		&policy.ID, &policy.Name, &policy.Description, &rulesJSON,
		&conditionsJSON, &actionsJSON, &policy.Priority, &policy.Enabled,
		&policy.Version, &policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy,
		&tagsJSON, &metadataJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("policy not found: %s", id)
		}
		return nil, fmt.Errorf("failed to scan policy: %w", err)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal([]byte(rulesJSON), &policy.Rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	if err := json.Unmarshal([]byte(conditionsJSON), &policy.Conditions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
	}

	if err := json.Unmarshal([]byte(actionsJSON), &policy.Actions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal actions: %w", err)
	}

	if err := json.Unmarshal([]byte(tagsJSON), &policy.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &policy.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return policy, nil
}

// ListPolicies retrieves policies based on filter criteria
func (s *SQLPolicyStorage) ListPolicies(ctx context.Context, filter *PolicyFilter) ([]*Policy, error) {
	query, args := s.buildListQuery(filter)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}
	defer rows.Close()

	var policies []*Policy

	for rows.Next() {
		policy := &Policy{}
		var rulesJSON, conditionsJSON, actionsJSON, tagsJSON, metadataJSON string

		err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &rulesJSON,
			&conditionsJSON, &actionsJSON, &policy.Priority, &policy.Enabled,
			&policy.Version, &policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy,
			&tagsJSON, &metadataJSON)

		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal([]byte(rulesJSON), &policy.Rules); err != nil {
			s.logger.WithError(err).WithField("policy_id", policy.ID).Warn("Failed to unmarshal rules")
			continue
		}

		if err := json.Unmarshal([]byte(conditionsJSON), &policy.Conditions); err != nil {
			s.logger.WithError(err).WithField("policy_id", policy.ID).Warn("Failed to unmarshal conditions")
			continue
		}

		if err := json.Unmarshal([]byte(actionsJSON), &policy.Actions); err != nil {
			s.logger.WithError(err).WithField("policy_id", policy.ID).Warn("Failed to unmarshal actions")
			continue
		}

		if err := json.Unmarshal([]byte(tagsJSON), &policy.Tags); err != nil {
			s.logger.WithError(err).WithField("policy_id", policy.ID).Warn("Failed to unmarshal tags")
			continue
		}

		if err := json.Unmarshal([]byte(metadataJSON), &policy.Metadata); err != nil {
			s.logger.WithError(err).WithField("policy_id", policy.ID).Warn("Failed to unmarshal metadata")
			continue
		}

		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating policies: %w", err)
	}

	return policies, nil
}

// GetPoliciesByResource retrieves policies that apply to a specific resource
func (s *SQLPolicyStorage) GetPoliciesByResource(ctx context.Context, resource string) ([]*Policy, error) {
	// This is a simplified implementation
	// In production, you'd want to optimize this with proper indexing and pattern matching
	filter := &PolicyFilter{
		Enabled: &[]bool{true}[0],
		Limit:   1000, // Reasonable limit
	}

	allPolicies, err := s.ListPolicies(ctx, filter)
	if err != nil {
		return nil, err
	}

	var matchingPolicies []*Policy
	for _, policy := range allPolicies {
		if s.policyAppliesToResource(policy, resource) {
			matchingPolicies = append(matchingPolicies, policy)
		}
	}

	return matchingPolicies, nil
}

// GetPoliciesByRole retrieves policies that apply to a specific role
func (s *SQLPolicyStorage) GetPoliciesByRole(ctx context.Context, role string) ([]*Policy, error) {
	// This is a simplified implementation
	filter := &PolicyFilter{
		Enabled: &[]bool{true}[0],
		Limit:   1000,
	}

	allPolicies, err := s.ListPolicies(ctx, filter)
	if err != nil {
		return nil, err
	}

	var matchingPolicies []*Policy
	for _, policy := range allPolicies {
		if s.policyAppliesToRole(policy, role) {
			matchingPolicies = append(matchingPolicies, policy)
		}
	}

	return matchingPolicies, nil
}

// Helper methods

func (s *SQLPolicyStorage) buildListQuery(filter *PolicyFilter) (string, []interface{}) {
	query := `
		SELECT id, name, description, rules, conditions, actions, priority, 
			   enabled, version, created_at, updated_at, created_by, tags, metadata
		FROM policies WHERE 1=1`

	var args []interface{}
	var conditions []string

	if filter == nil {
		return query + " ORDER BY priority DESC, created_at DESC", args
	}

	// Add filter conditions
	if len(filter.IDs) > 0 {
		placeholders := make([]string, len(filter.IDs))
		for i, id := range filter.IDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.Names) > 0 {
		placeholders := make([]string, len(filter.Names))
		for i, name := range filter.Names {
			placeholders[i] = "?"
			args = append(args, name)
		}
		conditions = append(conditions, fmt.Sprintf("name IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.Enabled != nil {
		conditions = append(conditions, "enabled = ?")
		args = append(args, *filter.Enabled)
	}

	if filter.CreatedBy != "" {
		conditions = append(conditions, "created_by = ?")
		args = append(args, filter.CreatedBy)
	}

	if filter.CreatedAfter != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *filter.CreatedBefore)
	}

	// Add conditions to query
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}

	// Add ordering
	orderBy := "priority DESC, created_at DESC"
	if filter.SortBy != "" {
		orderBy = filter.SortBy
		if filter.SortOrder != "" {
			orderBy += " " + filter.SortOrder
		}
	}
	query += " ORDER BY " + orderBy

	// Add pagination
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	return query, args
}

func (s *SQLPolicyStorage) policyAppliesToResource(policy *Policy, resource string) bool {
	for _, rule := range policy.Rules {
		if s.matchesPattern(rule.Resource, resource) {
			return true
		}
	}
	return false
}

func (s *SQLPolicyStorage) policyAppliesToRole(policy *Policy, role string) bool {
	rolePattern := "role:" + role

	for _, rule := range policy.Rules {
		for _, principal := range rule.Principals {
			if principal == "*" || principal == rolePattern {
				return true
			}
		}
	}
	return false
}

func (s *SQLPolicyStorage) matchesPattern(pattern, resource string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(resource, suffix)
	}

	return pattern == resource
}

// InitializeSchema creates the necessary database tables
func (s *SQLPolicyStorage) InitializeSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS policies (
			id VARCHAR(36) PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			description TEXT,
			rules TEXT NOT NULL,
			conditions TEXT DEFAULT '[]',
			actions TEXT DEFAULT '[]',
			priority INTEGER DEFAULT 100,
			enabled BOOLEAN DEFAULT true,
			version INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) NOT NULL,
			tags TEXT DEFAULT '[]',
			metadata TEXT DEFAULT '{}'
		);

		CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
		CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);
		CREATE INDEX IF NOT EXISTS idx_policies_created_by ON policies(created_by);
		CREATE INDEX IF NOT EXISTS idx_policies_created_at ON policies(created_at);
		CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name);
	`

	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to initialize policy schema: %w", err)
	}

	s.logger.Info("Policy storage schema initialized")
	return nil
}