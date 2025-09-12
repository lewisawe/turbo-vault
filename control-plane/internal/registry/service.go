package registry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Service implements the VaultRegistry interface
type Service struct {
	storage VaultStorage
}

// NewService creates a new registry service
func NewService(storage VaultStorage) *Service {
	return &Service{
		storage: storage,
	}
}

// RegisterVault registers a new vault agent
func (s *Service) RegisterVault(ctx context.Context, req *RegistrationRequest) (*VaultAgent, error) {
	// Validate certificate
	if err := s.validateCertificate(req.Certificate); err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	vault := &VaultAgent{
		ID:              uuid.New().String(),
		Name:            req.Name,
		OrganizationID:  req.OrganizationID,
		Version:         req.Version,
		Status:          VaultStatusOnline,
		LastHeartbeat:   time.Now(),
		Configuration:   req.Configuration,
		Policies:        []string{},
		Tags:            req.Tags,
		RegisteredAt:    time.Now(),
		UpdatedAt:       time.Now(),
		Certificate:     req.Certificate,
		Capabilities:    req.Capabilities,
		Metrics:         VaultMetrics{LastUpdated: time.Now()},
	}

	if err := s.storage.CreateVault(ctx, vault); err != nil {
		return nil, fmt.Errorf("failed to create vault: %w", err)
	}

	return vault, nil
}

// UpdateVault updates an existing vault agent
func (s *Service) UpdateVault(ctx context.Context, vaultID string, updates *VaultAgent) error {
	existing, err := s.storage.GetVault(ctx, vaultID)
	if err != nil {
		return fmt.Errorf("vault not found: %w", err)
	}

	// Merge updates with existing vault
	if updates.Name != "" {
		existing.Name = updates.Name
	}
	if updates.Version != "" {
		existing.Version = updates.Version
	}
	if updates.Tags != nil {
		existing.Tags = updates.Tags
	}
	if updates.Capabilities != nil {
		existing.Capabilities = updates.Capabilities
	}
	existing.UpdatedAt = time.Now()

	return s.storage.UpdateVault(ctx, vaultID, existing)
}

// GetVault retrieves a vault agent by ID
func (s *Service) GetVault(ctx context.Context, vaultID string) (*VaultAgent, error) {
	return s.storage.GetVault(ctx, vaultID)
}

// ListVaults lists vault agents with optional filtering
func (s *Service) ListVaults(ctx context.Context, filter *VaultFilter) (*VaultListResponse, error) {
	if filter == nil {
		filter = &VaultFilter{}
	}
	
	// Set default pagination
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	vaults, total, err := s.storage.ListVaults(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}

	return &VaultListResponse{
		Vaults:  vaults,
		Total:   total,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		HasMore: filter.Offset+len(vaults) < total,
	}, nil
}

// DeregisterVault removes a vault agent from the registry
func (s *Service) DeregisterVault(ctx context.Context, vaultID string) error {
	return s.storage.DeleteVault(ctx, vaultID)
}

// UpdateHeartbeat updates the last heartbeat and status for a vault agent
func (s *Service) UpdateHeartbeat(ctx context.Context, req *HeartbeatRequest) error {
	// Update vault status
	if err := s.UpdateVaultStatus(ctx, req.VaultID, req.Status); err != nil {
		return fmt.Errorf("failed to update vault status: %w", err)
	}

	// Update metrics and heartbeat
	req.Metrics.LastUpdated = time.Now()
	return s.storage.UpdateHeartbeat(ctx, req.VaultID, &req.Metrics)
}

// GetVaultsByOrganization retrieves all vaults for an organization
func (s *Service) GetVaultsByOrganization(ctx context.Context, orgID string) ([]VaultAgent, error) {
	return s.storage.GetVaultsByOrganization(ctx, orgID)
}

// UpdateVaultStatus updates the status of a vault agent
func (s *Service) UpdateVaultStatus(ctx context.Context, vaultID string, status VaultStatus) error {
	vault, err := s.storage.GetVault(ctx, vaultID)
	if err != nil {
		return fmt.Errorf("vault not found: %w", err)
	}

	vault.Status = status
	vault.UpdatedAt = time.Now()
	
	return s.storage.UpdateVault(ctx, vaultID, vault)
}

// GetOfflineVaults returns vaults that haven't sent heartbeat within threshold
func (s *Service) GetOfflineVaults(ctx context.Context, thresholdMinutes int) ([]VaultAgent, error) {
	return s.storage.GetStaleVaults(ctx, thresholdMinutes)
}

// validateCertificate validates the provided certificate
func (s *Service) validateCertificate(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	// Check if certificate is not yet valid
	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}

	return nil
}
