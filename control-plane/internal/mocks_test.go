package internal

import (
	"context"
	"fmt"
	"time"

	"github.com/keyvault/control-plane/internal/registry"
	"github.com/keyvault/control-plane/internal/monitoring"
	"github.com/keyvault/control-plane/internal/policy"
	"github.com/keyvault/control-plane/internal/analytics"
	"github.com/keyvault/control-plane/internal/users"
	"github.com/keyvault/control-plane/internal/dashboard"
)

// Mock implementations for testing

// MockVaultRegistry implements registry.VaultRegistry
type MockVaultRegistry struct {
	vaults map[string]*registry.VaultAgent
}

func (m *MockVaultRegistry) RegisterVault(ctx context.Context, req *registry.RegistrationRequest) (*registry.VaultAgent, error) {
	vault := &registry.VaultAgent{
		ID:             fmt.Sprintf("vault-%d", len(m.vaults)+1),
		Name:           req.Name,
		OrganizationID: req.OrganizationID,
		Version:        req.Version,
		Status:         registry.VaultStatusOnline,
		LastHeartbeat:  time.Now(),
		Configuration:  req.Configuration,
		Tags:           req.Tags,
		RegisteredAt:   time.Now(),
		UpdatedAt:      time.Now(),
		Certificate:    req.Certificate,
		Capabilities:   req.Capabilities,
	}
	m.vaults[vault.ID] = vault
	return vault, nil
}

func (m *MockVaultRegistry) UpdateVault(ctx context.Context, vaultID string, updates *registry.VaultAgent) error {
	if vault, exists := m.vaults[vaultID]; exists {
		*vault = *updates
		return nil
	}
	return fmt.Errorf("vault not found")
}

func (m *MockVaultRegistry) GetVault(ctx context.Context, vaultID string) (*registry.VaultAgent, error) {
	if vault, exists := m.vaults[vaultID]; exists {
		return vault, nil
	}
	return nil, fmt.Errorf("vault not found")
}

func (m *MockVaultRegistry) ListVaults(ctx context.Context, filter *registry.VaultFilter) (*registry.VaultListResponse, error) {
	var vaults []registry.VaultAgent
	for _, vault := range m.vaults {
		if filter.OrganizationID == "" || vault.OrganizationID == filter.OrganizationID {
			vaults = append(vaults, *vault)
		}
	}
	return &registry.VaultListResponse{
		Vaults: vaults,
		Total:  len(vaults),
	}, nil
}

func (m *MockVaultRegistry) DeregisterVault(ctx context.Context, vaultID string) error {
	delete(m.vaults, vaultID)
	return nil
}

func (m *MockVaultRegistry) UpdateHeartbeat(ctx context.Context, req *registry.HeartbeatRequest) error {
	if vault, exists := m.vaults[req.VaultID]; exists {
		vault.LastHeartbeat = time.Now()
		vault.Status = req.Status
		vault.Metrics = req.Metrics
		return nil
	}
	return fmt.Errorf("vault not found")
}

func (m *MockVaultRegistry) GetVaultsByOrganization(ctx context.Context, orgID string) ([]registry.VaultAgent, error) {
	var vaults []registry.VaultAgent
	for _, vault := range m.vaults {
		if vault.OrganizationID == orgID {
			vaults = append(vaults, *vault)
		}
	}
	return vaults, nil
}

func (m *MockVaultRegistry) UpdateVaultStatus(ctx context.Context, vaultID string, status registry.VaultStatus) error {
	if vault, exists := m.vaults[vaultID]; exists {
		vault.Status = status
		return nil
	}
	return fmt.Errorf("vault not found")
}

func (m *MockVaultRegistry) GetOfflineVaults(ctx context.Context, thresholdMinutes int) ([]registry.VaultAgent, error) {
	var offlineVaults []registry.VaultAgent
	threshold := time.Now().Add(-time.Duration(thresholdMinutes) * time.Minute)
	
	for _, vault := range m.vaults {
		if vault.LastHeartbeat.Before(threshold) {
			offlineVaults = append(offlineVaults, *vault)
		}
	}
	return offlineVaults, nil
}

// MockMonitoringService implements monitoring.MonitoringService
type MockMonitoringService struct {
	events []monitoring.MonitoringEvent
}

func (m *MockMonitoringService) StartMonitoring(ctx context.Context) error {
	return nil
}

func (m *MockMonitoringService) StopMonitoring() error {
	return nil
}

func (m *MockMonitoringService) CheckVaultHealth(ctx context.Context, vaultID string) (*monitoring.VaultHealthStatus, error) {
	return &monitoring.VaultHealthStatus{
		VaultID:     vaultID,
		Status:      "online",
		HealthScore: 95.0,
		CheckedAt:   time.Now(),
	}, nil
}

func (m *MockMonitoringService) CheckAllVaults(ctx context.Context) ([]monitoring.VaultHealthStatus, error) {
	return []monitoring.VaultHealthStatus{}, nil
}

func (m *MockMonitoringService) GetMonitoringStats(ctx context.Context) (*monitoring.MonitoringStats, error) {
	return &monitoring.MonitoringStats{
		TotalVaults:      1,
		OnlineVaults:     1,
		OfflineVaults:    0,
		ActiveAlerts:     0,
		EventsByType:     make(map[monitoring.MonitoringEventType]int),
		EventsBySeverity: make(map[monitoring.Severity]int),
		GeneratedAt:      time.Now(),
	}, nil
}

func (m *MockMonitoringService) GetEvents(ctx context.Context, filter *monitoring.EventFilter) ([]monitoring.MonitoringEvent, error) {
	return m.events, nil
}

func (m *MockMonitoringService) CreateAlertRule(ctx context.Context, rule *monitoring.AlertRule) error {
	return nil
}

func (m *MockMonitoringService) UpdateAlertRule(ctx context.Context, ruleID string, rule *monitoring.AlertRule) error {
	return nil
}

func (m *MockMonitoringService) DeleteAlertRule(ctx context.Context, ruleID string) error {
	return nil
}

func (m *MockMonitoringService) GetAlertRules(ctx context.Context) ([]monitoring.AlertRule, error) {
	return []monitoring.AlertRule{}, nil
}

// MockPolicyStorage implements policy.PolicyStorage
type MockPolicyStorage struct {
	policies map[string]*policy.Policy
	results  map[string]*policy.PolicyDistributionResult
}

func (m *MockPolicyStorage) GetPolicy(ctx context.Context, policyID string) (*policy.Policy, error) {
	if m.policies == nil {
		m.policies = make(map[string]*policy.Policy)
	}
	
	if policy, exists := m.policies[policyID]; exists {
		return policy, nil
	}
	
	// Return a default policy for testing
	return &policy.Policy{
		ID:          policyID,
		Name:        "Test Policy",
		Description: "Test policy for integration testing",
		Content:     "test policy content",
	}, nil
}

func (m *MockPolicyStorage) CreateDistributionResult(ctx context.Context, result *policy.PolicyDistributionResult) error {
	if m.results == nil {
		m.results = make(map[string]*policy.PolicyDistributionResult)
	}
	m.results[result.ID] = result
	return nil
}

func (m *MockPolicyStorage) GetDistributionResult(ctx context.Context, resultID string) (*policy.PolicyDistributionResult, error) {
	if result, exists := m.results[resultID]; exists {
		return result, nil
	}
	return nil, fmt.Errorf("result not found")
}

func (m *MockPolicyStorage) ListDistributionResults(ctx context.Context, filter *policy.DistributionFilter) ([]policy.PolicyDistributionResult, error) {
	var results []policy.PolicyDistributionResult
	for _, result := range m.results {
		results = append(results, *result)
	}
	return results, nil
}

// MockVaultRegistryForPolicy implements policy.VaultRegistry
type MockVaultRegistryForPolicy struct {
	vaults map[string]*policy.VaultAgent
}

func (m *MockVaultRegistryForPolicy) GetVault(ctx context.Context, vaultID string) (*policy.VaultAgent, error) {
	if m.vaults == nil {
		m.vaults = make(map[string]*policy.VaultAgent)
	}
	
	if vault, exists := m.vaults[vaultID]; exists {
		return vault, nil
	}
	
	// Return a default vault for testing
	vault := &policy.VaultAgent{
		ID:             vaultID,
		Name:           "Test Vault",
		OrganizationID: "org-123",
		Status:         "online",
		Policies:       []string{},
	}
	m.vaults[vaultID] = vault
	return vault, nil
}

func (m *MockVaultRegistryForPolicy) UpdateVault(ctx context.Context, vaultID string, vault *policy.VaultAgent) error {
	if m.vaults == nil {
		m.vaults = make(map[string]*policy.VaultAgent)
	}
	m.vaults[vaultID] = vault
	return nil
}

func (m *MockVaultRegistryForPolicy) GetVaultsByOrganization(ctx context.Context, orgID string) ([]policy.VaultAgent, error) {
	var vaults []policy.VaultAgent
	for _, vault := range m.vaults {
		if vault.OrganizationID == orgID {
			vaults = append(vaults, *vault)
		}
	}
	return vaults, nil
}

// MockAnalyticsService implements analytics.AnalyticsService
type MockAnalyticsService struct {
	metrics []analytics.UsageMetrics
}

func (m *MockAnalyticsService) RecordUsageMetrics(ctx context.Context, metrics *analytics.UsageMetrics) error {
	m.metrics = append(m.metrics, *metrics)
	return nil
}

func (m *MockAnalyticsService) GetUsageReport(ctx context.Context, orgID string, period string, startTime, endTime time.Time) (*analytics.UsageReport, error) {
	return &analytics.UsageReport{
		OrganizationID: orgID,
		ReportPeriod:   period,
		StartTime:      startTime,
		EndTime:        endTime,
		GeneratedAt:    time.Now(),
		Summary: analytics.UsageSummary{
			TotalVaults:   1,
			TotalRequests: 1000,
		},
	}, nil
}

func (m *MockAnalyticsService) GetPerformanceMetrics(ctx context.Context, filter *analytics.MetricsFilter) ([]analytics.PerformanceMetrics, error) {
	return []analytics.PerformanceMetrics{}, nil
}

func (m *MockAnalyticsService) GetCapacityMetrics(ctx context.Context, orgID string, period string) (*analytics.CapacityMetrics, error) {
	return &analytics.CapacityMetrics{
		OrganizationID: orgID,
		Timestamp:      time.Now(),
	}, nil
}

func (m *MockAnalyticsService) GetTimeSeriesData(ctx context.Context, filter *analytics.MetricsFilter) ([]analytics.TimeSeriesData, error) {
	return []analytics.TimeSeriesData{}, nil
}

func (m *MockAnalyticsService) GetDashboardData(ctx context.Context, orgID string, timeRange string) (*analytics.DashboardData, error) {
	return &analytics.DashboardData{
		OrganizationID: orgID,
		GeneratedAt:    time.Now(),
		TimeRange:      timeRange,
	}, nil
}

func (m *MockAnalyticsService) RecordEvent(ctx context.Context, event *analytics.AnalyticsEvent) error {
	return nil
}

func (m *MockAnalyticsService) CreateAlertThreshold(ctx context.Context, threshold *analytics.AlertThreshold) error {
	return nil
}

func (m *MockAnalyticsService) UpdateAlertThreshold(ctx context.Context, thresholdID string, threshold *analytics.AlertThreshold) error {
	return nil
}

func (m *MockAnalyticsService) DeleteAlertThreshold(ctx context.Context, thresholdID string) error {
	return nil
}

func (m *MockAnalyticsService) GetAlertThresholds(ctx context.Context, orgID string) ([]analytics.AlertThreshold, error) {
	return []analytics.AlertThreshold{}, nil
}

func (m *MockAnalyticsService) CheckThresholds(ctx context.Context, orgID string) ([]analytics.AlertSummary, error) {
	return []analytics.AlertSummary{}, nil
}

func (m *MockAnalyticsService) GenerateRecommendations(ctx context.Context, orgID string) ([]string, error) {
	return []string{"Test recommendation"}, nil
}

// MockUserStorage implements users.UserStorage
type MockUserStorage struct {
	users map[string]*users.User
}

func (m *MockUserStorage) CreateUser(ctx context.Context, user *users.User) error {
	if m.users == nil {
		m.users = make(map[string]*users.User)
	}
	m.users[user.ID] = user
	return nil
}

func (m *MockUserStorage) GetUser(ctx context.Context, userID string) (*users.User, error) {
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserStorage) GetUserByUsername(ctx context.Context, username string) (*users.User, error) {
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserStorage) GetUserByEmail(ctx context.Context, email string) (*users.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserStorage) UpdateUser(ctx context.Context, userID string, user *users.User) error {
	m.users[userID] = user
	return nil
}

func (m *MockUserStorage) DeleteUser(ctx context.Context, userID string) error {
	delete(m.users, userID)
	return nil
}

func (m *MockUserStorage) ListUsers(ctx context.Context, filter *users.UserFilter) ([]users.User, int, error) {
	var userList []users.User
	for _, user := range m.users {
		if filter.OrganizationID == "" || user.OrganizationID == filter.OrganizationID {
			userList = append(userList, *user)
		}
	}
	return userList, len(userList), nil
}

func (m *MockUserStorage) UpdateLastLogin(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		now := time.Now()
		user.LastLogin = &now
		return nil
	}
	return fmt.Errorf("user not found")
}

// MockSessionStorage implements users.SessionStorage
type MockSessionStorage struct{}

func (m *MockSessionStorage) CreateSession(ctx context.Context, session *users.Session) error {
	return nil
}

func (m *MockSessionStorage) GetSession(ctx context.Context, token string) (*users.Session, error) {
	return nil, fmt.Errorf("session not found")
}

func (m *MockSessionStorage) UpdateSession(ctx context.Context, token string, session *users.Session) error {
	return nil
}

func (m *MockSessionStorage) DeleteSession(ctx context.Context, token string) error {
	return nil
}

func (m *MockSessionStorage) ListUserSessions(ctx context.Context, userID string) ([]users.Session, error) {
	return []users.Session{}, nil
}

func (m *MockSessionStorage) DeleteUserSessions(ctx context.Context, userID string) error {
	return nil
}

func (m *MockSessionStorage) DeleteExpiredSessions(ctx context.Context) error {
	return nil
}

// MockAPIKeyStorage implements users.APIKeyStorage
type MockAPIKeyStorage struct{}

func (m *MockAPIKeyStorage) CreateAPIKey(ctx context.Context, apiKey *users.APIKey) error {
	return nil
}

func (m *MockAPIKeyStorage) GetAPIKey(ctx context.Context, keyID string) (*users.APIKey, error) {
	return nil, fmt.Errorf("API key not found")
}

func (m *MockAPIKeyStorage) GetAPIKeyByHash(ctx context.Context, keyHash string) (*users.APIKey, error) {
	return &users.APIKey{
		ID:             "test-key-id",
		UserID:         "test-user-id",
		OrganizationID: "org-123",
		Name:           "Test API Key",
		KeyHash:        keyHash,
		Status:         "active",
	}, nil
}

func (m *MockAPIKeyStorage) UpdateAPIKey(ctx context.Context, keyID string, apiKey *users.APIKey) error {
	return nil
}

func (m *MockAPIKeyStorage) DeleteAPIKey(ctx context.Context, keyID string) error {
	return nil
}

func (m *MockAPIKeyStorage) ListUserAPIKeys(ctx context.Context, userID string) ([]users.APIKey, error) {
	return []users.APIKey{}, nil
}

func (m *MockAPIKeyStorage) UpdateLastUsed(ctx context.Context, keyID string) error {
	return nil
}

// MockRoleStorage implements users.RoleStorage
type MockRoleStorage struct{}

func (m *MockRoleStorage) CreateRole(ctx context.Context, role *users.Role) error {
	return nil
}

func (m *MockRoleStorage) GetRole(ctx context.Context, roleID string) (*users.Role, error) {
	return nil, fmt.Errorf("role not found")
}

func (m *MockRoleStorage) UpdateRole(ctx context.Context, roleID string, role *users.Role) error {
	return nil
}

func (m *MockRoleStorage) DeleteRole(ctx context.Context, roleID string) error {
	return nil
}

func (m *MockRoleStorage) ListRoles(ctx context.Context) ([]users.Role, error) {
	return []users.Role{}, nil
}

func (m *MockRoleStorage) GetUserRoles(ctx context.Context, userID string) ([]users.Role, error) {
	return []users.Role{}, nil
}

// Dashboard service mocks

// MockVaultRegistryForDashboard implements dashboard.VaultRegistry
type MockVaultRegistryForDashboard struct{}

func (m *MockVaultRegistryForDashboard) ListVaults(ctx context.Context, filter *dashboard.VaultFilter) (*dashboard.VaultListResponse, error) {
	return &dashboard.VaultListResponse{
		Vaults: []dashboard.VaultAgent{
			{
				ID:            "vault-1",
				Name:          "Test Vault",
				Status:        "online",
				Version:       "1.0.0",
				LastHeartbeat: time.Now(),
				Metrics: dashboard.VaultMetrics{
					SecretCount:       10,
					RequestsPerSecond: 100.0,
					ErrorRate:         0.01,
					AverageLatency:    50.0,
					StorageUsage:      1024 * 1024,
				},
				Tags: map[string]string{"region": "us-east-1"},
			},
		},
	}, nil
}

// MockAnalyticsServiceForDashboard implements dashboard.AnalyticsService
type MockAnalyticsServiceForDashboard struct{}

func (m *MockAnalyticsServiceForDashboard) GetDashboardData(ctx context.Context, orgID string, timeRange string) (*dashboard.DashboardData, error) {
	return &dashboard.DashboardData{
		OverviewMetrics: dashboard.OverviewMetrics{
			TotalVaults:      1,
			OnlineVaults:     1,
			TotalRequests24h: 10000,
			AverageLatency:   50.0,
			ErrorRate:        0.01,
			StorageUsageGB:   1.0,
		},
		PerformanceTrends: []dashboard.TimeSeriesData{
			{
				DataPoints: []dashboard.TimeSeriesDataPoint{
					{Timestamp: time.Now(), Value: 50.0},
				},
			},
		},
	}, nil
}

func (m *MockAnalyticsServiceForDashboard) GetCapacityMetrics(ctx context.Context, orgID string, period string) (*dashboard.CapacityMetrics, error) {
	return &dashboard.CapacityMetrics{
		StorageUsageBytes:    1024 * 1024 * 1024,
		StorageCapacityBytes: 10 * 1024 * 1024 * 1024,
		StorageUtilization:   0.1,
	}, nil
}

// MockMonitoringServiceForDashboard implements dashboard.MonitoringService
type MockMonitoringServiceForDashboard struct{}

func (m *MockMonitoringServiceForDashboard) GetMonitoringStats(ctx context.Context) (*dashboard.MonitoringStats, error) {
	return &dashboard.MonitoringStats{
		EventsBySeverity: map[dashboard.Severity]int{
			"critical": 0,
			"warning":  1,
			"info":     5,
		},
		ActiveAlerts: 1,
	}, nil
}

func (m *MockMonitoringServiceForDashboard) GetEvents(ctx context.Context, filter *dashboard.EventFilter) ([]dashboard.MonitoringEvent, error) {
	return []dashboard.MonitoringEvent{
		{
			ID:        "event-1",
			VaultID:   "vault-1",
			EventType: "heartbeat_missed",
			Severity:  "warning",
			Message:   "Vault heartbeat missed",
			Details:   map[string]interface{}{},
			Timestamp: time.Now(),
			Resolved:  false,
		},
	}, nil
}

// MockUserServiceForDashboard implements dashboard.UserService
type MockUserServiceForDashboard struct{}

func (m *MockUserServiceForDashboard) ListUsers(ctx context.Context, filter *dashboard.UserFilter) (*dashboard.UserListResponse, error) {
	return &dashboard.UserListResponse{
		Total: 5,
	}, nil
}