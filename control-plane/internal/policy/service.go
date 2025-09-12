package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/keyvault/control-plane/internal/registry"
)

// Policy represents a security policy
type Policy struct {
	ID             string            `json:"id" db:"id"`
	Name           string            `json:"name" db:"name"`
	Description    string            `json:"description" db:"description"`
	Rules          []PolicyRule      `json:"rules" db:"rules"`
	OrganizationID string            `json:"organization_id" db:"organization_id"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at" db:"updated_at"`
	Version        int               `json:"version" db:"version"`
	Active         bool              `json:"active" db:"active"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     []string               `json:"actions"`
	Effect      string                 `json:"effect"` // allow/deny
	Priority    int                    `json:"priority"`
}

// PolicyAssignment represents policy assignment to agents
type PolicyAssignment struct {
	ID             string    `json:"id" db:"id"`
	PolicyID       string    `json:"policy_id" db:"policy_id"`
	AgentID        string    `json:"agent_id" db:"agent_id"`
	OrganizationID string    `json:"organization_id" db:"organization_id"`
	AssignedAt     time.Time `json:"assigned_at" db:"assigned_at"`
	Status         string    `json:"status" db:"status"` // pending/applied/failed
}

// Service manages policy distribution
type Service struct {
	db       *sql.DB
	registry *registry.Service
	mutex    sync.RWMutex
}

// NewService creates a new policy service
func NewService(db *sql.DB, registry *registry.Service) *Service {
	return &Service{
		db:       db,
		registry: registry,
	}
}

// CreatePolicy creates a new policy
func (s *Service) CreatePolicy(ctx context.Context, policy *Policy) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.Version = 1

	rules, _ := json.Marshal(policy.Rules)

	query := `
		INSERT INTO policies (id, name, description, rules, organization_id, created_at, updated_at, version, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := s.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Description, rules,
		policy.OrganizationID, policy.CreatedAt, policy.UpdatedAt, policy.Version, policy.Active)

	return err
}

// GetPolicy retrieves policy by ID
func (s *Service) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `SELECT id, name, description, rules, organization_id, created_at, updated_at, version, active FROM policies WHERE id = $1`
	
	var policy Policy
	var rules []byte
	
	err := s.db.QueryRowContext(ctx, query, policyID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &rules,
		&policy.OrganizationID, &policy.CreatedAt, &policy.UpdatedAt, &policy.Version, &policy.Active)
	
	if err != nil {
		return nil, err
	}

	json.Unmarshal(rules, &policy.Rules)
	return &policy, nil
}

// ListPolicies lists policies for organization
func (s *Service) ListPolicies(ctx context.Context, orgID string) ([]*Policy, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `SELECT id, name, description, rules, organization_id, created_at, updated_at, version, active FROM policies WHERE organization_id = $1`
	
	rows, err := s.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*Policy
	for rows.Next() {
		var policy Policy
		var rules []byte
		
		err := rows.Scan(&policy.ID, &policy.Name, &policy.Description, &rules,
			&policy.OrganizationID, &policy.CreatedAt, &policy.UpdatedAt, &policy.Version, &policy.Active)
		if err != nil {
			continue
		}

		json.Unmarshal(rules, &policy.Rules)
		policies = append(policies, &policy)
	}

	return policies, nil
}

// AssignPolicy assigns policy to agent
func (s *Service) AssignPolicy(ctx context.Context, assignment *PolicyAssignment) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	assignment.AssignedAt = time.Now()
	assignment.Status = "pending"

	query := `
		INSERT INTO policy_assignments (id, policy_id, agent_id, organization_id, assigned_at, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (policy_id, agent_id) DO UPDATE SET
			assigned_at = EXCLUDED.assigned_at,
			status = EXCLUDED.status`

	_, err := s.db.ExecContext(ctx, query,
		assignment.ID, assignment.PolicyID, assignment.AgentID,
		assignment.OrganizationID, assignment.AssignedAt, assignment.Status)

	return err
}

// BulkAssignPolicy assigns policy to multiple agents
func (s *Service) BulkAssignPolicy(ctx context.Context, policyID, orgID string, agentIDs []string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO policy_assignments (id, policy_id, agent_id, organization_id, assigned_at, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (policy_id, agent_id) DO UPDATE SET
			assigned_at = EXCLUDED.assigned_at,
			status = EXCLUDED.status`

	for _, agentID := range agentIDs {
		assignmentID := fmt.Sprintf("%s_%s", policyID, agentID)
		_, err := tx.ExecContext(ctx, query,
			assignmentID, policyID, agentID, orgID, time.Now(), "pending")
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetAgentPolicies returns policies assigned to agent
func (s *Service) GetAgentPolicies(ctx context.Context, agentID string) ([]*Policy, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT p.id, p.name, p.description, p.rules, p.organization_id, p.created_at, p.updated_at, p.version, p.active
		FROM policies p
		JOIN policy_assignments pa ON p.id = pa.policy_id
		WHERE pa.agent_id = $1 AND p.active = true`
	
	rows, err := s.db.QueryContext(ctx, query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*Policy
	for rows.Next() {
		var policy Policy
		var rules []byte
		
		err := rows.Scan(&policy.ID, &policy.Name, &policy.Description, &rules,
			&policy.OrganizationID, &policy.CreatedAt, &policy.UpdatedAt, &policy.Version, &policy.Active)
		if err != nil {
			continue
		}

		json.Unmarshal(rules, &policy.Rules)
		policies = append(policies, &policy)
	}

	return policies, nil
}

// UpdateAssignmentStatus updates policy assignment status
func (s *Service) UpdateAssignmentStatus(ctx context.Context, policyID, agentID, status string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := `UPDATE policy_assignments SET status = $1 WHERE policy_id = $2 AND agent_id = $3`
	_, err := s.db.ExecContext(ctx, query, status, policyID, agentID)
	return err
}

// GetPolicyAssignments returns policy assignments for organization
func (s *Service) GetPolicyAssignments(ctx context.Context, orgID string) ([]*PolicyAssignment, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `SELECT id, policy_id, agent_id, organization_id, assigned_at, status FROM policy_assignments WHERE organization_id = $1`
	
	rows, err := s.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assignments []*PolicyAssignment
	for rows.Next() {
		var assignment PolicyAssignment
		
		err := rows.Scan(&assignment.ID, &assignment.PolicyID, &assignment.AgentID,
			&assignment.OrganizationID, &assignment.AssignedAt, &assignment.Status)
		if err != nil {
			continue
		}

		assignments = append(assignments, &assignment)
	}

	return assignments, nil
}

// InitSchema initializes database schema
func (s *Service) InitSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS policies (
		id VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		rules JSONB NOT NULL,
		organization_id VARCHAR(255) NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		version INTEGER NOT NULL,
		active BOOLEAN NOT NULL DEFAULT true,
		INDEX idx_organization_id (organization_id)
	);

	CREATE TABLE IF NOT EXISTS policy_assignments (
		id VARCHAR(255) PRIMARY KEY,
		policy_id VARCHAR(255) NOT NULL,
		agent_id VARCHAR(255) NOT NULL,
		organization_id VARCHAR(255) NOT NULL,
		assigned_at TIMESTAMP NOT NULL,
		status VARCHAR(50) NOT NULL,
		UNIQUE KEY unique_policy_agent (policy_id, agent_id),
		INDEX idx_agent_id (agent_id),
		INDEX idx_organization_id (organization_id)
	)`

	_, err := s.db.ExecContext(ctx, schema)
	return err
}
