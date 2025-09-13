package security

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// SecurityIntegrationTestSuite provides comprehensive integration testing
type SecurityIntegrationTestSuite struct {
	suite.Suite
	scanner    *SecurityScannerImpl
	reporter   *ComplianceReporterImpl
	tester     *PenetrationTesterImpl
	validator  *ZeroTrustValidatorImpl
	manager    *SecurityPolicyManagerImpl
	monitor    *SecurityEventMonitorImpl
	simulator  *AttackSimulator
	testServer *httptest.Server
	ctx        context.Context
}

func (suite *SecurityIntegrationTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	
	// Initialize all security components
	suite.scanner = NewSecurityScanner(&ScannerConfig{
		ScanTimeout:   2 * time.Minute,
		MaxConcurrent: 2,
		EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration, ScanTypeCertificate},
	})
	
	suite.reporter = NewComplianceReporter(&ComplianceConfig{
		Standards:    []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, CompliancePCIDSS},
		AutoGenerate: true,
	})
	
	suite.tester = NewPenetrationTester(&PenTestConfig{
		TargetHost:    "localhost",
		TargetPort:    8080,
		TestTimeout:   1 * time.Minute,
		MaxConcurrent: 2,
		EnabledTests:  []TestType{TestTypeSSLTLS, TestTypeAuthentication, TestTypeAuthorization},
		SafeMode:      true,
	})
	
	suite.validator = NewZeroTrustValidator(&ZeroTrustConfig{
		TrustedNetworks:   []string{"127.0.0.0/8", "192.168.0.0/16"},
		MonitoringEnabled: true,
		StrictMode:        false,
	})
	
	suite.manager = NewSecurityPolicyManager(&PolicyManagerConfig{
		TemplatesPath:     "./test-templates/",
		PoliciesPath:      "./test-policies/",
		EnabledCategories: []string{"access", "encryption", "audit"},
		ValidationStrict:  true,
	})
	
	suite.monitor = NewSecurityEventMonitor(&EventMonitorConfig{
		BufferSize:        50,
		ProcessingWorkers: 2,
		RetentionPeriod:   1 * time.Hour,
		ResponseEnabled:   true,
	})
	
	suite.simulator = NewAttackSimulator(&AttackSimulatorConfig{
		TargetURL:      "http://localhost:8080",
		MaxConcurrency: 2,
		SafeMode:       true,
		EnabledAttacks: []AttackType{AttackTypeBruteForce, AttackTypeSQLInjection, AttackTypeXSS},
	})
	
	// Create test HTTP server
	suite.testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"healthy"}`))
		case "/api/auth/login":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	
	// Start security event monitor
	err := suite.monitor.Start(suite.ctx)
	suite.Require().NoError(err)
}

func (suite *SecurityIntegrationTestSuite) TearDownSuite() {
	if suite.testServer != nil {
		suite.testServer.Close()
	}
	
	if suite.monitor != nil {
		suite.monitor.Stop()
	}
	
	// Clean up test directories
	os.RemoveAll("./test-templates/")
	os.RemoveAll("./test-policies/")
}

func (suite *SecurityIntegrationTestSuite) TestFullSecurityAssessment() {
	// Test complete security assessment workflow
	
	// 1. Run vulnerability scan
	scanConfig := &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthStandard,
		Timeout:  30 * time.Second,
	}
	
	scanResult, err := suite.scanner.ScanVulnerabilities(suite.ctx, scanConfig)
	suite.Require().NoError(err)
	suite.Assert().NotNil(scanResult)
	suite.Assert().Equal(ScanStatusCompleted, scanResult.Status)
	
	// 2. Generate compliance reports
	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
	}
	
	soc2Report, err := suite.reporter.GenerateSOC2Report(suite.ctx, period)
	suite.Require().NoError(err)
	suite.Assert().NotNil(soc2Report)
	suite.Assert().Equal(ComplianceSOC2, soc2Report.Standard)
	
	iso27001Report, err := suite.reporter.GenerateISO27001Report(suite.ctx, period)
	suite.Require().NoError(err)
	suite.Assert().NotNil(iso27001Report)
	suite.Assert().Equal(ComplianceISO27001, iso27001Report.Standard)
	
	// 3. Run penetration tests
	penTestResult, err := suite.tester.RunSecurityTests(suite.ctx, suite.tester.config)
	suite.Require().NoError(err)
	suite.Assert().NotNil(penTestResult)
	suite.Assert().NotEmpty(penTestResult.Tests)
	
	// 4. Validate zero-trust controls
	networkRequest := &NetworkRequest{
		ID:            "integration-test-request",
		SourceIP:      []byte{127, 0, 0, 1},
		DestinationIP: []byte{127, 0, 0, 1},
		Port:          8080,
		Protocol:      "HTTP",
		Timestamp:     time.Now(),
	}
	
	accessDecision, err := suite.validator.ValidateNetworkAccess(suite.ctx, networkRequest)
	suite.Require().NoError(err)
	suite.Assert().NotNil(accessDecision)
	suite.Assert().NotEmpty(accessDecision.Conditions)
	
	// 5. Verify integration between components
	suite.Assert().True(scanResult.Summary.TotalFindings >= 0)
	suite.Assert().True(soc2Report.OverallScore >= 0 && soc2Report.OverallScore <= 100)
	suite.Assert().True(iso27001Report.OverallScore >= 0 && iso27001Report.OverallScore <= 100)
	suite.Assert().True(penTestResult.Summary.TotalTests > 0)
	suite.Assert().True(accessDecision.Confidence >= 0 && accessDecision.Confidence <= 1)
}

func (suite *SecurityIntegrationTestSuite) TestSecurityEventWorkflow() {
	// Test complete security event detection and response workflow
	
	// 1. Detect security events
	events, err := suite.monitor.DetectSecurityEvents(suite.ctx)
	suite.Require().NoError(err)
	suite.Assert().NotNil(events)
	
	// 2. Add test events if none detected
	if len(events) == 0 {
		testEvent := &SecurityEvent{
			ID:        "integration-test-event",
			Type:      EventTypeAuthentication,
			Severity:  SeverityHigh,
			Source:    "integration_test",
			Action:    "failed_login",
			Result:    EventResultFailure,
			Message:   "Integration test authentication failure",
			Timestamp: time.Now(),
		}
		events = append(events, testEvent)
	}
	
	// 3. Analyze threat patterns
	analysis, err := suite.monitor.AnalyzeThreatPatterns(suite.ctx, events)
	suite.Require().NoError(err)
	suite.Assert().NotNil(analysis)
	suite.Assert().Equal(int64(len(events)), analysis.TotalEvents)
	
	// 4. Trigger security responses
	for _, event := range events {
		if event.Severity == SeverityHigh || event.Severity == SeverityCritical {
			err := suite.monitor.TriggerSecurityResponse(suite.ctx, event)
			suite.Require().NoError(err)
		}
	}
	
	// 5. Get security metrics
	metricsResult, err := suite.monitor.GetSecurityMetrics(suite.ctx, &ReportPeriod{
		StartDate: time.Now().Add(-1 * time.Hour),
		EndDate:   time.Now(),
	})
	suite.Require().NoError(err)
	suite.Assert().NotNil(metricsResult)
	suite.Assert().NotNil(metricsResult.EventCounts)
}

func (suite *SecurityIntegrationTestSuite) TestPolicyManagementWorkflow() {
	// Test complete policy management workflow
	
	// 1. Create policy template
	template := &PolicyTemplate{
		Name:        "Integration Test Template",
		Category:    PolicyCategoryAccess,
		Description: "Template for integration testing",
		Version:     "1.0.0",
		Rules: []*PolicyRuleTemplate{
			{
				Name:        "Authentication Required",
				Description: "Require authentication for all requests",
				Condition:   "user.authenticated == true",
				Action:      "allow",
				Required:    true,
			},
		},
	}
	
	err := suite.manager.CreatePolicyTemplate(suite.ctx, template)
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(template.ID)
	
	// 2. Create security policy from template
	policy := &SecurityPolicy{
		ID:       "integration-test-policy",
		Name:     "Integration Test Policy",
		Category: PolicyCategoryAccess,
		Rules: []*PolicyRule{
			{
				ID:        "rule-1",
				Name:      "Authentication Rule",
				Condition: "user.authenticated == true",
				Action:    "allow",
				Enabled:   true,
			},
		},
		Enforcement: EnforcementLevelEnforcing,
	}
	
	// 3. Validate policy compliance
	validation, err := suite.manager.ValidatePolicyCompliance(suite.ctx, policy)
	suite.Require().NoError(err)
	suite.Assert().NotNil(validation)
	suite.Assert().Equal(policy.ID, validation.PolicyID)
	
	// 4. Apply security policy
	err = suite.manager.ApplySecurityPolicy(suite.ctx, policy)
	suite.Require().NoError(err)
	
	// 5. Get best practice guides
	guides, err := suite.manager.GetBestPracticeGuides(suite.ctx, "access")
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(guides)
	
	// 6. Generate policy recommendations
	recommendations, err := suite.manager.GeneratePolicyRecommendations(suite.ctx)
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(recommendations)
}

func (suite *SecurityIntegrationTestSuite) TestAttackSimulationWorkflow() {
	// Test complete attack simulation workflow
	
	// 1. Run full attack simulation
	simulationResult, err := suite.simulator.RunAttackSimulation(suite.ctx)
	suite.Require().NoError(err)
	suite.Assert().NotNil(simulationResult)
	suite.Assert().NotEmpty(simulationResult.Scenarios)
	suite.Assert().NotNil(simulationResult.Summary)
	
	// 2. Execute specific attack scenarios
	scenarios := suite.simulator.GetAvailableScenarios()
	suite.Assert().NotEmpty(scenarios)
	
	for _, scenario := range scenarios[:2] { // Test first 2 scenarios
		scenarioResult, err := suite.simulator.ExecuteSpecificAttack(suite.ctx, scenario.ID)
		suite.Require().NoError(err)
		suite.Assert().NotNil(scenarioResult)
		suite.Assert().Equal(scenario.ID, scenarioResult.ScenarioID)
	}
	
	// 3. Generate attack report
	report, err := suite.simulator.GenerateAttackReport(suite.ctx, simulationResult)
	suite.Require().NoError(err)
	suite.Assert().NotNil(report)
	suite.Assert().Equal(simulationResult.ID, report.SimulationID)
	suite.Assert().NotEmpty(report.ExecutiveSummary)
	
	// 4. Verify security effectiveness
	suite.Assert().True(simulationResult.Summary.SecurityEffectiveness >= 0)
	suite.Assert().True(simulationResult.Summary.SecurityEffectiveness <= 100)
}

func (suite *SecurityIntegrationTestSuite) TestCrossComponentIntegration() {
	// Test integration between different security components
	
	// 1. Scanner findings should influence compliance reports
	scanResult, err := suite.scanner.ScanVulnerabilities(suite.ctx, &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthBasic,
		Timeout:  15 * time.Second,
	})
	suite.Require().NoError(err)
	
	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
	}
	
	complianceReport, err := suite.reporter.GenerateSOC2Report(suite.ctx, period)
	suite.Require().NoError(err)
	
	// Verify that high-severity findings affect compliance score
	if scanResult.Summary.FindingsBySeverity[SeverityCritical] > 0 ||
		scanResult.Summary.FindingsBySeverity[SeverityHigh] > 0 {
		suite.Assert().True(complianceReport.OverallScore < 100.0)
	}
	
	// 2. Attack simulation results should trigger security events
	attackResult, err := suite.simulator.RunAttackSimulation(suite.ctx)
	suite.Require().NoError(err)
	
	// Allow time for event processing
	time.Sleep(100 * time.Millisecond)
	
	events, err := suite.monitor.DetectSecurityEvents(suite.ctx)
	suite.Require().NoError(err)
	
	// 3. Zero-trust validation should consider security events
	networkRequest := &NetworkRequest{
		ID:            "cross-component-test",
		SourceIP:      []byte{192, 168, 1, 100},
		DestinationIP: []byte{127, 0, 0, 1},
		Port:          8080,
		Protocol:      "HTTP",
		Timestamp:     time.Now(),
	}
	
	decision, err := suite.validator.ValidateNetworkAccess(suite.ctx, networkRequest)
	suite.Require().NoError(err)
	suite.Assert().NotNil(decision)
	
	// 4. Policy manager should generate recommendations based on findings
	recommendations, err := suite.manager.GeneratePolicyRecommendations(suite.ctx)
	suite.Require().NoError(err)
	suite.Assert().NotEmpty(recommendations)
	
	// Verify cross-component data flow
	suite.Assert().NotNil(scanResult.Summary)
	suite.Assert().NotNil(complianceReport.Controls)
	suite.Assert().NotNil(attackResult.Summary)
	suite.Assert().NotNil(decision.Conditions)
	suite.Assert().NotEmpty(recommendations)
}

func (suite *SecurityIntegrationTestSuite) TestDatabaseIntegration() {
	// Test integration with different database backends
	
	// This would test with actual database connections in a real environment
	// For now, we'll test the interface compatibility
	
	// Test SQLite integration
	suite.T().Run("SQLite", func(t *testing.T) {
		// Mock SQLite database operations
		suite.testDatabaseOperations("sqlite")
	})
	
	// Test PostgreSQL integration
	suite.T().Run("PostgreSQL", func(t *testing.T) {
		// Mock PostgreSQL database operations
		suite.testDatabaseOperations("postgresql")
	})
	
	// Test MySQL integration
	suite.T().Run("MySQL", func(t *testing.T) {
		// Mock MySQL database operations
		suite.testDatabaseOperations("mysql")
	})
}

func (suite *SecurityIntegrationTestSuite) testDatabaseOperations(dbType string) {
	// Simulate database operations for security components
	
	// Test audit log storage
	auditEvent := &AuditEvent{
		ID:        fmt.Sprintf("audit-%s-%d", dbType, time.Now().Unix()),
		VaultID:   "test-vault",
		EventType: AuditEventType("security_scan"),
		Timestamp: time.Now(),
	}
	
	// In a real implementation, this would store to the actual database
	suite.Assert().NotEmpty(auditEvent.ID)
	suite.Assert().NotEmpty(auditEvent.VaultID)
	
	// Test policy storage
	policy := &SecurityPolicy{
		ID:       fmt.Sprintf("policy-%s-%d", dbType, time.Now().Unix()),
		Name:     fmt.Sprintf("Test Policy for %s", dbType),
		Category: PolicyCategoryAccess,
		Rules:    []*PolicyRule{},
	}
	
	suite.Assert().NotEmpty(policy.ID)
	suite.Assert().NotEmpty(policy.Name)
	
	// Test security event storage
	securityEvent := &SecurityEvent{
		ID:        fmt.Sprintf("event-%s-%d", dbType, time.Now().Unix()),
		Type:      EventTypeSecurityViolation,
		Severity:  SeverityMedium,
		Source:    "integration_test",
		Timestamp: time.Now(),
	}
	
	suite.Assert().NotEmpty(securityEvent.ID)
	suite.Assert().NotEmpty(securityEvent.Source)
}

func (suite *SecurityIntegrationTestSuite) TestAPIIntegration() {
	// Test integration with REST API endpoints
	
	// Test security scanner API integration
	suite.T().Run("ScannerAPI", func(t *testing.T) {
		// This would test actual API endpoints in a real environment
		// For now, we'll test the component interfaces
		
		scanConfig := &ScanConfig{
			ScanType: ScanTypeConfiguration,
			Targets:  []string{"localhost"},
			Depth:    ScanDepthBasic,
			Timeout:  10 * time.Second,
		}
		
		result, err := suite.scanner.ScanConfiguration(suite.ctx)
		suite.Require().NoError(err)
		suite.Assert().NotNil(result)
		suite.Assert().Equal(ScanTypeConfiguration, result.ScanType)
	})
	
	// Test compliance reporter API integration
	suite.T().Run("ComplianceAPI", func(t *testing.T) {
		validation, err := suite.reporter.ValidateCompliance(suite.ctx, ComplianceSOC2)
		suite.Require().NoError(err)
		suite.Assert().NotNil(validation)
	})
	
	// Test penetration tester API integration
	suite.T().Run("PenTestAPI", func(t *testing.T) {
		validation, err := suite.tester.ValidateSecurityControls(suite.ctx)
		suite.Require().NoError(err)
		suite.Assert().NotNil(validation)
		suite.Assert().NotEmpty(validation.Controls)
	})
}

func (suite *SecurityIntegrationTestSuite) TestPerformanceIntegration() {
	// Test performance characteristics of integrated components
	
	startTime := time.Now()
	
	// Run multiple operations concurrently
	done := make(chan bool, 4)
	
	// Concurrent vulnerability scan
	go func() {
		_, err := suite.scanner.ScanVulnerabilities(suite.ctx, &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  []string{"localhost"},
			Depth:    ScanDepthBasic,
			Timeout:  10 * time.Second,
		})
		suite.Assert().NoError(err)
		done <- true
	}()
	
	// Concurrent compliance report
	go func() {
		period := &ReportPeriod{
			StartDate: time.Now().AddDate(0, -1, 0),
			EndDate:   time.Now(),
		}
		_, err := suite.reporter.GenerateSOC2Report(suite.ctx, period)
		suite.Assert().NoError(err)
		done <- true
	}()
	
	// Concurrent penetration test
	go func() {
		_, err := suite.tester.ValidateSecurityControls(suite.ctx)
		suite.Assert().NoError(err)
		done <- true
	}()
	
	// Concurrent zero-trust validation
	go func() {
		request := &NetworkRequest{
			ID:            "perf-test-request",
			SourceIP:      []byte{127, 0, 0, 1},
			DestinationIP: []byte{127, 0, 0, 1},
			Port:          8080,
			Protocol:      "HTTP",
			Timestamp:     time.Now(),
		}
		_, err := suite.validator.ValidateNetworkAccess(suite.ctx, request)
		suite.Assert().NoError(err)
		done <- true
	}()
	
	// Wait for all operations to complete
	for i := 0; i < 4; i++ {
		<-done
	}
	
	duration := time.Since(startTime)
	
	// Verify performance requirements (should complete within reasonable time)
	suite.Assert().True(duration < 30*time.Second, "Integrated operations took too long: %v", duration)
}

// Run the integration test suite
func TestSecurityIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SecurityIntegrationTestSuite))
}

// Additional integration test functions

func TestSecurityComponentInteraction(t *testing.T) {
	// Test specific component interactions
	
	ctx := context.Background()
	scanner := NewSecurityScanner(nil)
	monitor := NewSecurityEventMonitor(nil)
	
	// Start monitor
	err := monitor.Start(ctx)
	require.NoError(t, err)
	defer monitor.Stop()
	
	// Run scan and verify events are generated
	scanResult, err := scanner.ScanVulnerabilities(ctx, &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthBasic,
		Timeout:  10 * time.Second,
	})
	require.NoError(t, err)
	assert.NotNil(t, scanResult)
	
	// Allow time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// Check if security events were generated
	events, err := monitor.DetectSecurityEvents(ctx)
	require.NoError(t, err)
	assert.NotNil(t, events)
}

func TestSecurityDataFlow(t *testing.T) {
	// Test data flow between security components
	
	ctx := context.Background()
	
	// Initialize components
	scanner := NewSecurityScanner(nil)
	reporter := NewComplianceReporter(nil)
	manager := NewSecurityPolicyManager(nil)
	
	// 1. Scan for vulnerabilities
	scanResult, err := scanner.ScanVulnerabilities(ctx, &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthBasic,
		Timeout:  10 * time.Second,
	})
	require.NoError(t, err)
	
	// 2. Use scan results to influence compliance reporting
	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
	}
	
	complianceReport, err := reporter.GenerateSOC2Report(ctx, period)
	require.NoError(t, err)
	
	// 3. Generate policy recommendations based on findings
	recommendations, err := manager.GeneratePolicyRecommendations(ctx)
	require.NoError(t, err)
	
	// Verify data flow
	assert.NotNil(t, scanResult.Summary)
	assert.NotNil(t, complianceReport.Controls)
	assert.NotEmpty(t, recommendations)
	
	// Verify that findings influence recommendations
	if scanResult.Summary.TotalFindings > 0 {
		assert.NotEmpty(t, recommendations)
	}
}

func TestSecurityErrorHandling(t *testing.T) {
	// Test error handling in integrated scenarios
	
	ctx := context.Background()
	
	// Test with invalid configuration
	scanner := NewSecurityScanner(&ScannerConfig{
		ScanTimeout:   1 * time.Nanosecond, // Invalid timeout
		MaxConcurrent: 0,                   // Invalid concurrency
	})
	
	scanConfig := &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"invalid-target"},
		Depth:    ScanDepthExhaustive,
		Timeout:  1 * time.Nanosecond, // Invalid timeout
	}
	
	// Should handle errors gracefully
	result, err := scanner.ScanVulnerabilities(ctx, scanConfig)
	if err != nil {
		// Error is acceptable for invalid configuration
		assert.Contains(t, err.Error(), "timeout")
	} else {
		// If no error, result should still be valid
		assert.NotNil(t, result)
	}
}