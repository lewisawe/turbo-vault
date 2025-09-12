package internal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/keyvault/control-plane/internal/registry"
	"github.com/keyvault/control-plane/internal/monitoring"
	"github.com/keyvault/control-plane/internal/policy"
	"github.com/keyvault/control-plane/internal/analytics"
	"github.com/keyvault/control-plane/internal/users"
	"github.com/keyvault/control-plane/internal/dashboard"
)

// TestControlPlaneIntegration tests the integration between all control plane services
func TestControlPlaneIntegration(t *testing.T) {
	ctx := context.Background()
	
	// Setup test services with mock implementations
	vaultRegistry := setupMockVaultRegistry()
	monitoringService := setupMockMonitoringService()
	policyService := setupMockPolicyService()
	analyticsService := setupMockAnalyticsService()
	userService := setupMockUserService()
	dashboardService := setupMockDashboardService()
	
	t.Run("VaultRegistrationAndMonitoring", func(t *testing.T) {
		testVaultRegistrationAndMonitoring(t, ctx, vaultRegistry, monitoringService)
	})
	
	t.Run("PolicyDistribution", func(t *testing.T) {
		testPolicyDistribution(t, ctx, vaultRegistry, policyService)
	})
	
	t.Run("AnalyticsCollection", func(t *testing.T) {
		testAnalyticsCollection(t, ctx, analyticsService, vaultRegistry)
	})
	
	t.Run("UserManagement", func(t *testing.T) {
		testUserManagement(t, ctx, userService)
	})
	
	t.Run("DashboardIntegration", func(t *testing.T) {
		testDashboardIntegration(t, ctx, dashboardService)
	})
}

func testVaultRegistrationAndMonitoring(t *testing.T, ctx context.Context, 
	vaultRegistry registry.VaultRegistry, monitoringService monitoring.MonitoringService) {
	
	// Test vault registration
	regReq := &registry.RegistrationRequest{
		Name:           "test-vault-1",
		OrganizationID: "org-123",
		Version:        "1.0.0",
		Certificate:    generateTestCertificate(),
		Configuration: registry.VaultConfig{
			StorageBackend:   "sqlite",
			EncryptionMethod: "aes-256-gcm",
		},
	}
	
	vault, err := vaultRegistry.RegisterVault(ctx, regReq)
	require.NoError(t, err)
	assert.NotEmpty(t, vault.ID)
	assert.Equal(t, regReq.Name, vault.Name)
	
	// Test heartbeat
	heartbeatReq := &registry.HeartbeatRequest{
		VaultID: vault.ID,
		Status:  registry.VaultStatusOnline,
		Metrics: registry.VaultMetrics{
			RequestsPerSecond: 100.0,
			AverageLatency:    50.0,
			ErrorRate:         0.01,
		},
	}
	
	err = vaultRegistry.UpdateHeartbeat(ctx, heartbeatReq)
	require.NoError(t, err)
	
	// Test monitoring detection
	time.Sleep(100 * time.Millisecond) // Allow monitoring to process
	
	healthStatus, err := monitoringService.CheckVaultHealth(ctx, vault.ID)
	require.NoError(t, err)
	assert.Equal(t, "online", healthStatus.Status)
}

func generateTestCertificate() string {
	return `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKw7QDVrPyVDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDA5MTIwMDAwMDBaFw0yNTA5MTIwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890...
-----END CERTIFICATE-----`
}

func testPolicyDistribution(t *testing.T, ctx context.Context,
	vaultRegistry registry.VaultRegistry, policyService *policy.DistributionService) {
	
	// Register test vaults
	vault1, _ := vaultRegistry.RegisterVault(ctx, &registry.RegistrationRequest{
		Name:           "vault-1",
		OrganizationID: "org-123",
		Version:        "1.0.0",
		Certificate:    generateTestCertificate(),
	})
	
	vault2, _ := vaultRegistry.RegisterVault(ctx, &registry.RegistrationRequest{
		Name:           "vault-2", 
		OrganizationID: "org-123",
		Version:        "1.0.0",
		Certificate:    generateTestCertificate(),
	})
	
	// Test policy distribution
	distReq := &policy.PolicyDistributionRequest{
		PolicyID: "policy-123",
		VaultIDs: []string{vault1.ID, vault2.ID},
	}
	
	result, err := policyService.DistributePolicy(ctx, distReq)
	require.NoError(t, err)
	assert.Equal(t, policy.DistributionStatusCompleted, result.Status)
	assert.Len(t, result.Results, 2)
}

func testAnalyticsCollection(t *testing.T, ctx context.Context,
	analyticsService analytics.AnalyticsService, vaultRegistry registry.VaultRegistry) {
	
	// Register test vault
	vault, _ := vaultRegistry.RegisterVault(ctx, &registry.RegistrationRequest{
		Name:           "analytics-vault",
		OrganizationID: "org-123", 
		Version:        "1.0.0",
		Certificate:    generateTestCertificate(),
	})
	
	// Record usage metrics
	metrics := &analytics.UsageMetrics{
		VaultID:           vault.ID,
		OrganizationID:    "org-123",
		Timestamp:         time.Now(),
		RequestCount:      1000,
		SecretCount:       50,
		StorageUsageBytes: 1024 * 1024, // 1MB
		ErrorCount:        5,
		AverageLatencyMs:  25.5,
	}
	
	err := analyticsService.RecordUsageMetrics(ctx, metrics)
	require.NoError(t, err)
	
	// Generate usage report
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)
	
	report, err := analyticsService.GetUsageReport(ctx, "org-123", "daily", startTime, endTime)
	require.NoError(t, err)
	assert.Equal(t, "org-123", report.OrganizationID)
	assert.NotEmpty(t, report.Summary)
}

func testUserManagement(t *testing.T, ctx context.Context, userService users.UserService) {
	// Create organization first (would be done by organization service)
	
	// Create user
	createReq := &users.CreateUserRequest{
		Username:       "testuser",
		Email:          "test@example.com",
		Password:       "securepassword123",
		FirstName:      "Test",
		LastName:       "User",
		OrganizationID: "org-123",
		Roles:          []string{"admin"},
	}
	
	user, err := userService.CreateUser(ctx, createReq)
	require.NoError(t, err)
	assert.Equal(t, createReq.Username, user.Username)
	assert.Equal(t, createReq.Email, user.Email)
	assert.Empty(t, user.PasswordHash) // Should not be returned
	
	// Test authentication
	authUser, err := userService.AuthenticateUser(ctx, "testuser", "securepassword123")
	require.NoError(t, err)
	assert.Equal(t, user.ID, authUser.ID)
	
	// Test API key creation
	apiKeyReq := &users.CreateAPIKeyRequest{
		Name: "test-api-key",
		Permissions: []users.Permission{
			{Resource: "secrets", Actions: []string{"read", "write"}},
		},
	}
	
	apiKey, keyString, err := userService.CreateAPIKey(ctx, user.ID, apiKeyReq)
	require.NoError(t, err)
	assert.NotEmpty(t, keyString)
	assert.Equal(t, apiKeyReq.Name, apiKey.Name)
	
	// Test API key authentication
	authUser2, authAPIKey, err := userService.AuthenticateAPIKey(ctx, keyString)
	require.NoError(t, err)
	assert.Equal(t, user.ID, authUser2.ID)
	assert.Equal(t, apiKey.ID, authAPIKey.ID)
}

func testDashboardIntegration(t *testing.T, ctx context.Context, dashboardService dashboard.DashboardService) {
	// Test system overview
	overview, err := dashboardService.GetOverview(ctx, "org-123")
	require.NoError(t, err)
	assert.Equal(t, "org-123", overview.OrganizationID)
	assert.NotZero(t, overview.GeneratedAt)
	
	// Test vault summary
	vaultSummary, err := dashboardService.GetVaultSummary(ctx, "org-123")
	require.NoError(t, err)
	assert.Equal(t, "org-123", vaultSummary.OrganizationID)
	
	// Test performance metrics
	perfMetrics, err := dashboardService.GetPerformanceMetrics(ctx, "org-123", "24h")
	require.NoError(t, err)
	assert.Equal(t, "org-123", perfMetrics.OrganizationID)
	assert.Equal(t, "24h", perfMetrics.TimeRange)
}

// Mock service setup functions
func setupMockVaultRegistry() registry.VaultRegistry {
	// In a real test, this would use a mock implementation or test database
	return &MockVaultRegistry{
		vaults: make(map[string]*registry.VaultAgent),
	}
}

func setupMockMonitoringService() monitoring.MonitoringService {
	return &MockMonitoringService{
		events: make([]monitoring.MonitoringEvent, 0),
	}
}

func setupMockPolicyService() *policy.DistributionService {
	return policy.NewDistributionService(
		&MockPolicyStorage{},
		&MockVaultRegistryForPolicy{},
	)
}

func setupMockAnalyticsService() analytics.AnalyticsService {
	return &MockAnalyticsService{
		metrics: make([]analytics.UsageMetrics, 0),
	}
}

func setupMockUserService() users.UserService {
	return users.NewUserService(
		&MockUserStorage{users: make(map[string]*users.User)},
		&MockSessionStorage{},
		&MockAPIKeyStorage{},
		&MockRoleStorage{},
	)
}

func setupMockDashboardService() dashboard.DashboardService {
	return dashboard.NewService(
		&MockVaultRegistryForDashboard{},
		&MockAnalyticsServiceForDashboard{},
		&MockMonitoringServiceForDashboard{},
		&MockUserServiceForDashboard{},
	)
}