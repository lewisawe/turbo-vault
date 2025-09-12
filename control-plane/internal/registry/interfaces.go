package registry

import (
	"context"
)

// VaultRegistry defines the interface for managing vault agent registrations
type VaultRegistry interface {
	// RegisterVault registers a new vault agent
	RegisterVault(ctx context.Context, req *RegistrationRequest) (*VaultAgent, error)
	
	// UpdateVault updates an existing vault agent
	UpdateVault(ctx context.Context, vaultID string, updates *VaultAgent) error
	
	// GetVault retrieves a vault agent by ID
	GetVault(ctx context.Context, vaultID string) (*VaultAgent, error)
	
	// ListVaults lists vault agents with optional filtering
	ListVaults(ctx context.Context, filter *VaultFilter) (*VaultListResponse, error)
	
	// DeregisterVault removes a vault agent from the registry
	DeregisterVault(ctx context.Context, vaultID string) error
	
	// UpdateHeartbeat updates the last heartbeat and status for a vault agent
	UpdateHeartbeat(ctx context.Context, req *HeartbeatRequest) error
	
	// GetVaultsByOrganization retrieves all vaults for an organization
	GetVaultsByOrganization(ctx context.Context, orgID string) ([]VaultAgent, error)
	
	// UpdateVaultStatus updates the status of a vault agent
	UpdateVaultStatus(ctx context.Context, vaultID string, status VaultStatus) error
	
	// GetOfflineVaults returns vaults that haven't sent heartbeat within threshold
	GetOfflineVaults(ctx context.Context, threshold int) ([]VaultAgent, error)
}

// VaultStorage defines the interface for vault registry storage operations
type VaultStorage interface {
	// CreateVault creates a new vault record
	CreateVault(ctx context.Context, vault *VaultAgent) error
	
	// UpdateVault updates an existing vault record
	UpdateVault(ctx context.Context, vaultID string, vault *VaultAgent) error
	
	// GetVault retrieves a vault by ID
	GetVault(ctx context.Context, vaultID string) (*VaultAgent, error)
	
	// ListVaults lists vaults with filtering and pagination
	ListVaults(ctx context.Context, filter *VaultFilter) ([]VaultAgent, int, error)
	
	// DeleteVault removes a vault record
	DeleteVault(ctx context.Context, vaultID string) error
	
	// UpdateHeartbeat updates heartbeat timestamp and metrics
	UpdateHeartbeat(ctx context.Context, vaultID string, metrics *VaultMetrics) error
	
	// GetVaultsByStatus retrieves vaults by status
	GetVaultsByStatus(ctx context.Context, status VaultStatus) ([]VaultAgent, error)
	
	// GetVaultsByOrganization retrieves vaults by organization
	GetVaultsByOrganization(ctx context.Context, orgID string) ([]VaultAgent, error)
	
	// GetStaleVaults returns vaults with heartbeat older than threshold
	GetStaleVaults(ctx context.Context, thresholdMinutes int) ([]VaultAgent, error)
}