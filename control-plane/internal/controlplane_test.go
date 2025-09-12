package internal

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyvault/control-plane/internal/analytics"
	"github.com/keyvault/control-plane/internal/monitoring"
	"github.com/keyvault/control-plane/internal/policy"
	"github.com/keyvault/control-plane/internal/registry"
	"github.com/keyvault/control-plane/internal/users"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	return db
}

func TestRegistryService(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	service := registry.NewService(db)
	ctx := context.Background()

	// Initialize schema
	err := service.InitSchema(ctx)
	require.NoError(t, err)

	// Test agent registration
	agent := &registry.Agent{
		ID:             "test-agent-1",
		Hostname:       "test-host",
		Version:        "1.0.0",
		Capabilities:   []string{"secrets", "rotation"},
		Metadata:       map[string]string{"env": "test"},
		OrganizationID: "test-org",
	}

	err = service.RegisterAgent(ctx, agent)
	assert.NoError(t, err)

	// Test get agent
	retrieved, err := service.GetAgent(ctx, "test-agent-1")
	assert.NoError(t, err)
	assert.Equal(t, agent.ID, retrieved.ID)
	assert.Equal(t, agent.Hostname, retrieved.Hostname)

	// Test list agents
	agents, err := service.ListAgents(ctx, "test-org")
	assert.NoError(t, err)
	assert.Len(t, agents, 1)

	// Test heartbeat update
	err = service.UpdateHeartbeat(ctx, "test-agent-1", map[string]interface{}{"status": "healthy"})
	assert.NoError(t, err)

	// Test offline agents detection
	time.Sleep(100 * time.Millisecond)
	offlineAgents, err := service.GetOfflineAgents(ctx, 50*time.Millisecond)
	assert.NoError(t, err)
	assert.Len(t, offlineAgents, 1)
}

func TestMonitoringService(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	registryService := registry.NewService(db)
	ctx := context.Background()

	// Initialize schema
	err := registryService.InitSchema(ctx)
	require.NoError(t, err)

	// Register test agent
	agent := &registry.Agent{
		ID:             "test-agent-1",
		Hostname:       "test-host",
		Version:        "1.0.0",
		OrganizationID: "test-org",
	}
	err = registryService.RegisterAgent(ctx, agent)
	require.NoError(t, err)

	// Create monitoring service
	monitoringService := monitoring.NewService(registryService)

	// Start monitoring
	err = monitoringService.Start(ctx)
	assert.NoError(t, err)
	defer monitoringService.Stop()

	// Subscribe to alerts
	alertCh := monitoringService.Subscribe()

	// Wait for offline detection
	time.Sleep(200 * time.Millisecond)

	// Check for alerts
	select {
	case alert := <-alertCh:
		assert.Equal(t, monitoring.AlertAgentOffline, alert.Type)
		assert.Equal(t, "test-agent-1", alert.AgentID)
	case <-time.After(1 * time.Second):
		t.Fatal("Expected offline alert but none received")
	}

	// Get alerts for organization
	alerts, err := monitoringService.GetAlerts(ctx, "test-org")
	assert.NoError(t, err)
	assert.Len(t, alerts, 1)
}

func TestPolicyService(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	registryService := registry.NewService(db)
	policyService := policy.NewService(db, registryService)
	ctx := context.Background()

	// Initialize schemas
	err := registryService.InitSchema(ctx)
	require.NoError(t, err)
	err = policyService.InitSchema(ctx)
	require.NoError(t, err)

	// Create test policy
	testPolicy := &policy.Policy{
		ID:             "test-policy-1",
		Name:           "Test Policy",
		Description:    "Test policy description",
		OrganizationID: "test-org",
		Rules: []policy.PolicyRule{
			{
				ID:         "rule-1",
				Type:       "access_control",
				Conditions: map[string]interface{}{"time": "business_hours"},
				Actions:    []string{"read", "write"},
				Effect:     "allow",
				Priority:   1,
			},
		},
		Active: true,
	}

	err = policyService.CreatePolicy(ctx, testPolicy)
	assert.NoError(t, err)

	// Test get policy
	retrieved, err := policyService.GetPolicy(ctx, "test-policy-1")
	assert.NoError(t, err)
	assert.Equal(t, testPolicy.Name, retrieved.Name)
	assert.Len(t, retrieved.Rules, 1)

	// Test list policies
	policies, err := policyService.ListPolicies(ctx, "test-org")
	assert.NoError(t, err)
	assert.Len(t, policies, 1)

	// Register test agent
	agent := &registry.Agent{
		ID:             "test-agent-1",
		Hostname:       "test-host",
		OrganizationID: "test-org",
	}
	err = registryService.RegisterAgent(ctx, agent)
	require.NoError(t, err)

	// Test policy assignment
	assignment := &policy.PolicyAssignment{
		ID:             "assignment-1",
		PolicyID:       "test-policy-1",
		AgentID:        "test-agent-1",
		OrganizationID: "test-org",
	}

	err = policyService.AssignPolicy(ctx, assignment)
	assert.NoError(t, err)

	// Test get agent policies
	agentPolicies, err := policyService.GetAgentPolicies(ctx, "test-agent-1")
	assert.NoError(t, err)
	assert.Len(t, agentPolicies, 1)

	// Test bulk assignment
	err = policyService.BulkAssignPolicy(ctx, "test-policy-1", "test-org", []string{"test-agent-1", "test-agent-2"})
	assert.NoError(t, err)
}

func TestAnalyticsService(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	registryService := registry.NewService(db)
	analyticsService := analytics.NewService(db, registryService)
	ctx := context.Background()

	// Initialize schemas
	err := registryService.InitSchema(ctx)
	require.NoError(t, err)
	err = analyticsService.InitSchema(ctx)
	require.NoError(t, err)

	// Record test metrics
	testMetrics := map[string]interface{}{
		"total_secrets":      10,
		"total_operations":   100,
		"average_latency":    50.5,
		"error_rate":         0.1,
		"concurrent_requests": 5,
		"cpu_usage":          75.0,
		"storage_usage":      60.0,
	}

	err = analyticsService.RecordMetrics(ctx, "test-agent-1", "test-org", testMetrics)
	assert.NoError(t, err)

	// Test usage report generation
	report, err := analyticsService.GenerateUsageReport(ctx, "test-org", "daily")
	assert.NoError(t, err)
	assert.Equal(t, "test-org", report.OrganizationID)
	assert.Equal(t, "daily", report.Period)

	// Test capacity metrics generation
	capacity, err := analyticsService.GenerateCapacityMetrics(ctx, "test-org")
	assert.NoError(t, err)
	assert.Equal(t, "test-org", capacity.OrganizationID)
	assert.NotEmpty(t, capacity.Recommendations)

	// Test metrics history
	history, err := analyticsService.GetMetricsHistory(ctx, "test-org", 24)
	assert.NoError(t, err)
	assert.Len(t, history, 1)
}

func TestUserService(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	service := users.NewService(db)
	ctx := context.Background()

	// Initialize schema
	err := service.InitSchema(ctx)
	require.NoError(t, err)

	// Create test organization
	org := &users.Organization{
		ID:   "test-org",
		Name: "Test Organization",
		Plan: "enterprise",
	}

	err = service.CreateOrganization(ctx, org)
	assert.NoError(t, err)

	// Test get organization
	retrieved, err := service.GetOrganization(ctx, "test-org")
	assert.NoError(t, err)
	assert.Equal(t, org.Name, retrieved.Name)

	// Create test user
	user := &users.User{
		ID:             "test-user-1",
		Email:          "test@example.com",
		Role:           users.RoleAdmin,
		OrganizationID: "test-org",
	}

	err = service.CreateUser(ctx, user, "password123")
	assert.NoError(t, err)

	// Test authentication
	authenticated, err := service.AuthenticateUser(ctx, "test@example.com", "password123")
	assert.NoError(t, err)
	assert.Equal(t, user.Email, authenticated.Email)

	// Test wrong password
	_, err = service.AuthenticateUser(ctx, "test@example.com", "wrongpassword")
	assert.Error(t, err)

	// Test list users
	users, err := service.ListUsers(ctx, "test-org")
	assert.NoError(t, err)
	assert.Len(t, users, 1)

	// Test API key creation
	apiKey := &users.APIKey{
		ID:             "api-key-1",
		UserID:         "test-user-1",
		OrganizationID: "test-org",
		Name:           "Test API Key",
		Permissions:    []string{"read", "write"},
	}

	key, err := service.CreateAPIKey(ctx, apiKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
	assert.Contains(t, key, "kv_")

	// Test API key validation
	validatedUser, err := service.ValidateAPIKey(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, validatedUser.Email)
}

func TestIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Initialize all services
	registryService := registry.NewService(db)
	userService := users.NewService(db)
	policyService := policy.NewService(db, registryService)
	analyticsService := analytics.NewService(db, registryService)
	monitoringService := monitoring.NewService(registryService)

	ctx := context.Background()

	// Initialize schemas
	err := registryService.InitSchema(ctx)
	require.NoError(t, err)
	err = userService.InitSchema(ctx)
	require.NoError(t, err)
	err = policyService.InitSchema(ctx)
	require.NoError(t, err)
	err = analyticsService.InitSchema(ctx)
	require.NoError(t, err)

	// Create organization and user
	org := &users.Organization{
		ID:   "integration-org",
		Name: "Integration Test Org",
		Plan: "enterprise",
	}
	err = userService.CreateOrganization(ctx, org)
	require.NoError(t, err)

	user := &users.User{
		ID:             "integration-user",
		Email:          "integration@example.com",
		Role:           users.RoleAdmin,
		OrganizationID: "integration-org",
	}
	err = userService.CreateUser(ctx, user, "password123")
	require.NoError(t, err)

	// Register agents
	for i := 1; i <= 3; i++ {
		agent := &registry.Agent{
			ID:             fmt.Sprintf("agent-%d", i),
			Hostname:       fmt.Sprintf("host-%d", i),
			Version:        "1.0.0",
			Capabilities:   []string{"secrets", "rotation"},
			OrganizationID: "integration-org",
		}
		err = registryService.RegisterAgent(ctx, agent)
		require.NoError(t, err)
	}

	// Create and assign policies
	testPolicy := &policy.Policy{
		ID:             "integration-policy",
		Name:           "Integration Policy",
		OrganizationID: "integration-org",
		Rules: []policy.PolicyRule{
			{
				ID:      "rule-1",
				Type:    "access_control",
				Effect:  "allow",
				Actions: []string{"read", "write"},
			},
		},
		Active: true,
	}
	err = policyService.CreatePolicy(ctx, testPolicy)
	require.NoError(t, err)

	// Bulk assign policy to all agents
	err = policyService.BulkAssignPolicy(ctx, "integration-policy", "integration-org", []string{"agent-1", "agent-2", "agent-3"})
	assert.NoError(t, err)

	// Record metrics for agents
	for i := 1; i <= 3; i++ {
		metrics := map[string]interface{}{
			"total_secrets":    i * 10,
			"total_operations": i * 100,
			"average_latency":  float64(i * 50),
			"error_rate":       0.01 * float64(i),
		}
		err = analyticsService.RecordMetrics(ctx, fmt.Sprintf("agent-%d", i), "integration-org", metrics)
		assert.NoError(t, err)
	}

	// Start monitoring
	err = monitoringService.Start(ctx)
	require.NoError(t, err)
	defer monitoringService.Stop()

	// Verify integration
	agents, err := registryService.ListAgents(ctx, "integration-org")
	assert.NoError(t, err)
	assert.Len(t, agents, 3)

	policies, err := policyService.ListPolicies(ctx, "integration-org")
	assert.NoError(t, err)
	assert.Len(t, policies, 1)

	assignments, err := policyService.GetPolicyAssignments(ctx, "integration-org")
	assert.NoError(t, err)
	assert.Len(t, assignments, 3)

	report, err := analyticsService.GenerateUsageReport(ctx, "integration-org", "daily")
	assert.NoError(t, err)
	assert.Equal(t, 60, report.TotalSecrets) // 10+20+30

	metrics, err := monitoringService.GetAgentMetrics(ctx, "integration-org")
	assert.NoError(t, err)
	assert.Equal(t, 3, metrics["total_agents"])
}
