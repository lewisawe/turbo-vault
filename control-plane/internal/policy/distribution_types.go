package policy

import (
	"context"
	"time"
)

// PolicyDistributionRequest represents a request to distribute a policy
type PolicyDistributionRequest struct {
	PolicyID       string   `json:"policy_id" validate:"required"`
	VaultIDs       []string `json:"vault_ids"`
	OrganizationID string   `json:"organization_id"`
	Force          bool     `json:"force"`
}

// BulkPolicyDistributionRequest represents a request to distribute multiple policies
type BulkPolicyDistributionRequest struct {
	Requests []PolicyDistributionRequest `json:"requests" validate:"required"`
}

// PolicyRemovalRequest represents a request to remove a policy from vaults
type PolicyRemovalRequest struct {
	PolicyID string   `json:"policy_id" validate:"required"`
	VaultIDs []string `json:"vault_ids" validate:"required"`
}

// DistributionStatus represents the status of a policy distribution
type DistributionStatus string

const (
	DistributionStatusPending        DistributionStatus = "pending"
	DistributionStatusInProgress     DistributionStatus = "in_progress"
	DistributionStatusCompleted      DistributionStatus = "completed"
	DistributionStatusFailed         DistributionStatus = "failed"
	DistributionStatusPartialSuccess DistributionStatus = "partial_success"
)

// VaultDistributionStatus represents the status of policy distribution to a single vault
type VaultDistributionStatus string

const (
	VaultDistributionStatusPending VaultDistributionStatus = "pending"
	VaultDistributionStatusSuccess VaultDistributionStatus = "success"
	VaultDistributionStatusFailed  VaultDistributionStatus = "failed"
)

// PolicyDistributionResult represents the result of a policy distribution
type PolicyDistributionResult struct {
	ID           string                           `json:"id"`
	PolicyID     string                           `json:"policy_id"`
	RequestedAt  time.Time                        `json:"requested_at"`
	CompletedAt  *time.Time                       `json:"completed_at,omitempty"`
	Status       DistributionStatus               `json:"status"`
	TargetVaults []string                         `json:"target_vaults"`
	Results      map[string]VaultDistributionResult `json:"results"`
	Error        string                           `json:"error,omitempty"`
}

// BulkPolicyDistributionResult represents the result of bulk policy distribution
type BulkPolicyDistributionResult struct {
	ID          string                              `json:"id"`
	RequestedAt time.Time                           `json:"requested_at"`
	CompletedAt *time.Time                          `json:"completed_at,omitempty"`
	Status      DistributionStatus                  `json:"status"`
	Results     map[string]*PolicyDistributionResult `json:"results"`
}

// VaultDistributionResult represents the result of policy distribution to a single vault
type VaultDistributionResult struct {
	VaultID   string                  `json:"vault_id"`
	Status    VaultDistributionStatus `json:"status"`
	Error     string                  `json:"error,omitempty"`
	Timestamp time.Time               `json:"timestamp"`
}

// DistributionFilter represents filtering options for distribution results
type DistributionFilter struct {
	PolicyID   string             `json:"policy_id"`
	VaultID    string             `json:"vault_id"`
	Status     DistributionStatus `json:"status"`
	Since      *time.Time         `json:"since"`
	Until      *time.Time         `json:"until"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
}

// PolicyDistributionStorage defines the interface for storing policy distribution data
type PolicyDistributionStorage interface {
	// CreateDistributionResult creates a new distribution result
	CreateDistributionResult(ctx context.Context, result *PolicyDistributionResult) error
	
	// GetDistributionResult retrieves a distribution result by ID
	GetDistributionResult(ctx context.Context, resultID string) (*PolicyDistributionResult, error)
	
	// UpdateDistributionResult updates an existing distribution result
	UpdateDistributionResult(ctx context.Context, resultID string, result *PolicyDistributionResult) error
	
	// ListDistributionResults lists distribution results with filtering
	ListDistributionResults(ctx context.Context, filter *DistributionFilter) ([]PolicyDistributionResult, error)
	
	// DeleteDistributionResult deletes a distribution result
	DeleteDistributionResult(ctx context.Context, resultID string) error
}

// VaultRegistry interface for accessing vault information
type VaultRegistry interface {
	GetVault(ctx context.Context, vaultID string) (*VaultAgent, error)
	UpdateVault(ctx context.Context, vaultID string, vault *VaultAgent) error
	GetVaultsByOrganization(ctx context.Context, orgID string) ([]VaultAgent, error)
}

// VaultAgent represents a vault agent (simplified for policy distribution)
type VaultAgent struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	OrganizationID string   `json:"organization_id"`
	Status         string   `json:"status"`
	Policies       []string `json:"policies"`
}

// PolicyStorage interface for accessing policy information
type PolicyStorage interface {
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
	CreateDistributionResult(ctx context.Context, result *PolicyDistributionResult) error
	GetDistributionResult(ctx context.Context, resultID string) (*PolicyDistributionResult, error)
	ListDistributionResults(ctx context.Context, filter *DistributionFilter) ([]PolicyDistributionResult, error)
}

// Policy represents a policy (simplified for distribution)
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}