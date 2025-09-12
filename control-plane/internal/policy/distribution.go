package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DistributionService handles policy distribution to vault agents
type DistributionService struct {
	storage PolicyStorage
	registry VaultRegistry
}

// NewDistributionService creates a new policy distribution service
func NewDistributionService(storage PolicyStorage, registry VaultRegistry) *DistributionService {
	return &DistributionService{
		storage:  storage,
		registry: registry,
	}
}

// DistributePolicy distributes a policy to specified vault agents
func (s *DistributionService) DistributePolicy(ctx context.Context, req *PolicyDistributionRequest) (*PolicyDistributionResult, error) {
	policy, err := s.storage.GetPolicy(ctx, req.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	result := &PolicyDistributionResult{
		ID:           uuid.New().String(),
		PolicyID:     req.PolicyID,
		RequestedAt:  time.Now(),
		Status:       DistributionStatusInProgress,
		TargetVaults: req.VaultIDs,
		Results:      make(map[string]VaultDistributionResult),
	}

	// If no specific vaults specified, distribute to all vaults in organization
	vaultIDs := req.VaultIDs
	if len(vaultIDs) == 0 && req.OrganizationID != "" {
		vaults, err := s.registry.GetVaultsByOrganization(ctx, req.OrganizationID)
		if err != nil {
			return nil, fmt.Errorf("failed to get vaults for organization: %w", err)
		}
		
		vaultIDs = make([]string, len(vaults))
		for i, vault := range vaults {
			vaultIDs[i] = vault.ID
		}
		result.TargetVaults = vaultIDs
	}

	// Distribute policy to each vault
	successCount := 0
	for _, vaultID := range vaultIDs {
		vaultResult := s.distributePolicyToVault(ctx, vaultID, policy)
		result.Results[vaultID] = vaultResult
		
		if vaultResult.Status == VaultDistributionStatusSuccess {
			successCount++
		}
	}

	// Update overall status
	if successCount == len(vaultIDs) {
		result.Status = DistributionStatusCompleted
	} else if successCount > 0 {
		result.Status = DistributionStatusPartialSuccess
	} else {
		result.Status = DistributionStatusFailed
	}

	result.CompletedAt = &time.Time{}
	*result.CompletedAt = time.Now()

	// Store distribution result
	if err := s.storage.CreateDistributionResult(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to store distribution result: %w", err)
	}

	return result, nil
}

// BulkDistributePolicy distributes multiple policies to vault agents
func (s *DistributionService) BulkDistributePolicy(ctx context.Context, req *BulkPolicyDistributionRequest) (*BulkPolicyDistributionResult, error) {
	result := &BulkPolicyDistributionResult{
		ID:          uuid.New().String(),
		RequestedAt: time.Now(),
		Status:      DistributionStatusInProgress,
		Results:     make(map[string]*PolicyDistributionResult),
	}

	successCount := 0
	for _, policyReq := range req.Requests {
		policyResult, err := s.DistributePolicy(ctx, policyReq)
		if err != nil {
			result.Results[policyReq.PolicyID] = &PolicyDistributionResult{
				ID:       uuid.New().String(),
				PolicyID: policyReq.PolicyID,
				Status:   DistributionStatusFailed,
				Error:    err.Error(),
			}
		} else {
			result.Results[policyReq.PolicyID] = policyResult
			if policyResult.Status == DistributionStatusCompleted {
				successCount++
			}
		}
	}

	// Update overall status
	if successCount == len(req.Requests) {
		result.Status = DistributionStatusCompleted
	} else if successCount > 0 {
		result.Status = DistributionStatusPartialSuccess
	} else {
		result.Status = DistributionStatusFailed
	}

	result.CompletedAt = &time.Time{}
	*result.CompletedAt = time.Now()

	return result, nil
}

// GetDistributionResult retrieves a policy distribution result
func (s *DistributionService) GetDistributionResult(ctx context.Context, resultID string) (*PolicyDistributionResult, error) {
	return s.storage.GetDistributionResult(ctx, resultID)
}

// ListDistributionResults lists policy distribution results with filtering
func (s *DistributionService) ListDistributionResults(ctx context.Context, filter *DistributionFilter) ([]PolicyDistributionResult, error) {
	return s.storage.ListDistributionResults(ctx, filter)
}

// distributePolicyToVault distributes a policy to a single vault
func (s *DistributionService) distributePolicyToVault(ctx context.Context, vaultID string, policy *Policy) VaultDistributionResult {
	vault, err := s.registry.GetVault(ctx, vaultID)
	if err != nil {
		return VaultDistributionResult{
			VaultID:   vaultID,
			Status:    VaultDistributionStatusFailed,
			Error:     fmt.Sprintf("failed to get vault: %v", err),
			Timestamp: time.Now(),
		}
	}

	// Check if vault is online
	if vault.Status != "online" {
		return VaultDistributionResult{
			VaultID:   vaultID,
			Status:    VaultDistributionStatusFailed,
			Error:     "vault is not online",
			Timestamp: time.Now(),
		}
	}

	// In a real implementation, this would send the policy to the vault agent
	// For now, we'll simulate successful distribution
	
	// Add policy to vault's policy list
	vault.Policies = append(vault.Policies, policy.ID)
	if err := s.registry.UpdateVault(ctx, vaultID, vault); err != nil {
		return VaultDistributionResult{
			VaultID:   vaultID,
			Status:    VaultDistributionStatusFailed,
			Error:     fmt.Sprintf("failed to update vault policies: %v", err),
			Timestamp: time.Now(),
		}
	}

	return VaultDistributionResult{
		VaultID:   vaultID,
		Status:    VaultDistributionStatusSuccess,
		Timestamp: time.Now(),
	}
}

// RemovePolicy removes a policy from specified vault agents
func (s *DistributionService) RemovePolicy(ctx context.Context, req *PolicyRemovalRequest) (*PolicyDistributionResult, error) {
	result := &PolicyDistributionResult{
		ID:           uuid.New().String(),
		PolicyID:     req.PolicyID,
		RequestedAt:  time.Now(),
		Status:       DistributionStatusInProgress,
		TargetVaults: req.VaultIDs,
		Results:      make(map[string]VaultDistributionResult),
	}

	// Remove policy from each vault
	successCount := 0
	for _, vaultID := range req.VaultIDs {
		vaultResult := s.removePolicyFromVault(ctx, vaultID, req.PolicyID)
		result.Results[vaultID] = vaultResult
		
		if vaultResult.Status == VaultDistributionStatusSuccess {
			successCount++
		}
	}

	// Update overall status
	if successCount == len(req.VaultIDs) {
		result.Status = DistributionStatusCompleted
	} else if successCount > 0 {
		result.Status = DistributionStatusPartialSuccess
	} else {
		result.Status = DistributionStatusFailed
	}

	result.CompletedAt = &time.Time{}
	*result.CompletedAt = time.Now()

	return result, nil
}

// removePolicyFromVault removes a policy from a single vault
func (s *DistributionService) removePolicyFromVault(ctx context.Context, vaultID, policyID string) VaultDistributionResult {
	vault, err := s.registry.GetVault(ctx, vaultID)
	if err != nil {
		return VaultDistributionResult{
			VaultID:   vaultID,
			Status:    VaultDistributionStatusFailed,
			Error:     fmt.Sprintf("failed to get vault: %v", err),
			Timestamp: time.Now(),
		}
	}

	// Remove policy from vault's policy list
	newPolicies := make([]string, 0, len(vault.Policies))
	for _, p := range vault.Policies {
		if p != policyID {
			newPolicies = append(newPolicies, p)
		}
	}
	vault.Policies = newPolicies

	if err := s.registry.UpdateVault(ctx, vaultID, vault); err != nil {
		return VaultDistributionResult{
			VaultID:   vaultID,
			Status:    VaultDistributionStatusFailed,
			Error:     fmt.Sprintf("failed to update vault policies: %v", err),
			Timestamp: time.Now(),
		}
	}

	return VaultDistributionResult{
		VaultID:   vaultID,
		Status:    VaultDistributionStatusSuccess,
		Timestamp: time.Now(),
	}
}