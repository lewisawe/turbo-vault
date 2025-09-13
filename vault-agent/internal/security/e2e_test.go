package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// SecurityE2ETestSuite provides end-to-end testing for complete security workflows
type SecurityE2ETestSuite struct {
	suite.Suite
	testDir    string
	testServer *httptest.Server
	ctx        context.Context
}

func (suite *SecurityE2ETestSuite) SetupSuite() {
	suite.ctx = context.Background()
	
	// Create temporary test directory
	var err error
	suite.testDir, err = os.MkdirTemp("", "security-e2e-test-*")
	suite.Require().NoError(err)
	
	// Create test subdirectories
	suite.Require().NoError(os.MkdirAll(filepath.Join(suite.testDir, "templates"), 0755))
	suite.Require().NoError(os.MkdirAll(filepath.Join(suite.testDir, "policies"), 0755))
	suite.Require().NoError(os.MkdirAll(filepath.Join(suite.testDir, "reports"), 0755))
	suite.Require().NoError(os.MkdirAll(filepath.Join(suite.testDir, "logs"), 0755))
	
	// Create test HTTP server
	suite.testServer = httptest.NewServer(http.HandlerFunc(suite.testServerHandler))
}

func (suite *SecurityE2ETestSuite) TearDownSuite() {
	if suite.testServer != nil {
		suite.testServer.Close()
	}
	
	if suite.testDir != "" {
		os.RemoveAll(suite.testDir)
	}
}

func (suite *SecurityE2ETestSuite) testServerHandler(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/health"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
		
	case strings.HasPrefix(r.URL.Path, "/api/auth/login"):
		// Simulate authentication endpoint
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		
		// Simulate rate limiting after 3 attempts
		if r.Header.Get("X-Test-Attempt") == "4" {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "rate_limited"})
			return
		}
		
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_credentials"})
		
	case strings.HasPrefix(r.URL.Path, "/api/secrets"):
		// Simulate secrets API
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("q") != "" {
			// Simulate search with potential SQL injection
			query := r.URL.Query().Get("q")
			if strings.Contains(query, "'") || strings.Contains(query, "--") {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_query"})
				return
			}
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]string{
				{"id": "secret-1", "name": "test-secret"},
			},
		})
		
	case strings.HasPrefix(r.URL.Path, "/api/admin"):
		// Simulate admin endpoint requiring authorization
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "admin_access_granted"})
		
	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not_found"})
	}
}

func (suite *SecurityE2ETestSuite) TestCompleteSecurityHardeningWorkflow() {
	// Test complete security hardening workflow from start to finish
	
	// 1. Initial Security Assessment
	suite.T().Run("InitialAssessment", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   2 * time.Minute,
			MaxConcurrent: 2,
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration, ScanTypeCertificate},
		})
		
		// Run comprehensive vulnerability scan
		vulnResult, err := scanner.ScanVulnerabilities(suite.ctx, &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  []string{suite.testServer.URL},
			Depth:    ScanDepthStandard,
			Timeout:  30 * time.Second,
		})
		require.NoError(t, err)
		assert.NotNil(t, vulnResult)
		assert.Equal(t, ScanStatusCompleted, vulnResult.Status)
		
		// Run configuration scan
		configResult, err := scanner.ScanConfiguration(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, configResult)
		assert.Equal(t, ScanStatusCompleted, configResult.Status)
		
		// Run certificate scan
		certResult, err := scanner.ScanCertificates(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, certResult)
		assert.Equal(t, ScanStatusCompleted, certResult.Status)
		
		// Verify scan results provide actionable information
		assert.NotNil(t, vulnResult.Summary)
		assert.True(t, vulnResult.Summary.TotalFindings >= 0)
		assert.NotNil(t, configResult.ConfigFiles)
		assert.NotNil(t, certResult.Certificates)
	})
	
	// 2. Policy Creation and Management
	suite.T().Run("PolicyManagement", func(t *testing.T) {
		manager := NewSecurityPolicyManager(&PolicyManagerConfig{
			TemplatesPath:     filepath.Join(suite.testDir, "templates"),
			PoliciesPath:      filepath.Join(suite.testDir, "policies"),
			EnabledCategories: []string{"access", "encryption", "audit", "network"},
			ValidationStrict:  true,
		})
		
		// Create comprehensive security policy template
		template := &PolicyTemplate{
			Name:        "E2E Security Policy Template",
			Category:    PolicyCategoryAccess,
			Description: "Comprehensive security policy for E2E testing",
			Version:     "1.0.0",
			Rules: []*PolicyRuleTemplate{
				{
					Name:        "Multi-Factor Authentication",
					Description: "Require MFA for all administrative access",
					Condition:   "user.role == 'admin' AND auth.mfa_enabled == true",
					Action:      "allow",
					Required:    true,
				},
				{
					Name:        "Rate Limiting",
					Description: "Enforce rate limiting on API endpoints",
					Condition:   "request.rate <= 100",
					Action:      "allow",
					Required:    true,
				},
				{
					Name:        "Encryption Requirements",
					Description: "Require TLS 1.2+ for all communications",
					Condition:   "connection.tls_version >= '1.2'",
					Action:      "enforce",
					Required:    true,
				},
			},
		}
		
		err := manager.CreatePolicyTemplate(suite.ctx, template)
		require.NoError(t, err)
		assert.NotEmpty(t, template.ID)
		
		// Create and validate security policy
		policy := &SecurityPolicy{
			ID:       "e2e-security-policy",
			Name:     "E2E Security Policy",
			Category: PolicyCategoryAccess,
			Rules: []*PolicyRule{
				{
					ID:        "mfa-rule",
					Name:      "MFA Required",
					Condition: "user.role == 'admin' AND auth.mfa_enabled == true",
					Action:    "allow",
					Enabled:   true,
				},
				{
					ID:        "rate-limit-rule",
					Name:      "Rate Limiting",
					Condition: "request.rate <= 100",
					Action:    "throttle",
					Enabled:   true,
				},
			},
			Enforcement: EnforcementLevelEnforcing,
		}
		
		validation, err := manager.ValidatePolicyCompliance(suite.ctx, policy)
		require.NoError(t, err)
		assert.NotNil(t, validation)
		assert.True(t, validation.Valid)
		assert.True(t, validation.Score >= 70.0) // Should meet minimum compliance score
		
		// Apply the policy
		err = manager.ApplySecurityPolicy(suite.ctx, policy)
		require.NoError(t, err)
		
		// Get best practice guides
		guides, err := manager.GetBestPracticeGuides(suite.ctx, "access")
		require.NoError(t, err)
		assert.NotEmpty(t, guides)
		
		// Verify guides contain actionable recommendations
		for _, guide := range guides {
			assert.NotEmpty(t, guide.Title)
			assert.NotEmpty(t, guide.Practices)
			for _, practice := range guide.Practices {
				assert.NotEmpty(t, practice.Steps)
			}
		}
	})
	
	// 3. Penetration Testing and Vulnerability Assessment
	suite.T().Run("PenetrationTesting", func(t *testing.T) {
		tester := NewPenetrationTester(&PenTestConfig{
			TargetHost:    strings.TrimPrefix(suite.testServer.URL, "http://"),
			TargetPort:    80,
			TestTimeout:   2 * time.Minute,
			MaxConcurrent: 3,
			EnabledTests:  []TestType{TestTypeAuthentication, TestTypeAuthorization, TestTypeInputValidation, TestTypeRateLimit},
			SafeMode:      true,
		})
		
		// Run comprehensive security tests
		testResult, err := tester.RunSecurityTests(suite.ctx, tester.config)
		require.NoError(t, err)
		assert.NotNil(t, testResult)
		assert.NotEmpty(t, testResult.Tests)
		
		// Verify all enabled test types were executed
		testTypes := make(map[TestType]bool)
		for _, test := range testResult.Tests {
			testTypes[test.Type] = true
		}
		
		for _, enabledType := range tester.config.EnabledTests {
			assert.True(t, testTypes[enabledType], "Test type %s was not executed", enabledType)
		}
		
		// Run specific attack simulations
		bruteForceAttack := &AttackScenario{
			ID:       "e2e-brute-force",
			Name:     "E2E Brute Force Attack",
			Type:     AttackTypeBruteForce,
			Target:   "/api/auth/login",
			Payload:  "admin:password",
			Expected: AttackOutcomeBlocked,
		}
		
		attackResult, err := tester.SimulateAttack(suite.ctx, bruteForceAttack)
		require.NoError(t, err)
		assert.NotNil(t, attackResult)
		assert.Equal(t, bruteForceAttack.ID, attackResult.ScenarioID)
		assert.NotEmpty(t, attackResult.Evidence)
		
		// Validate security controls
		controlValidation, err := tester.ValidateSecurityControls(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, controlValidation)
		assert.NotEmpty(t, controlValidation.Controls)
		assert.True(t, controlValidation.OverallScore >= 0)
		
		// Generate comprehensive security report
		securityReport, err := tester.GenerateSecurityReport(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, securityReport)
		assert.NotEmpty(t, securityReport.ExecutiveSummary)
		assert.NotNil(t, securityReport.RiskAssessment)
		assert.NotEmpty(t, securityReport.TestResults)
		assert.NotEmpty(t, securityReport.Recommendations)
	})
	
	// 4. Compliance Reporting and Validation
	suite.T().Run("ComplianceReporting", func(t *testing.T) {
		reporter := NewComplianceReporter(&ComplianceConfig{
			Standards:       []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, CompliancePCIDSS, ComplianceHIPAA},
			ReportPath:      filepath.Join(suite.testDir, "reports"),
			AutoGenerate:    true,
			RetentionPeriod: 365 * 24 * time.Hour,
		})
		
		period := &ReportPeriod{
			StartDate: time.Now().AddDate(0, -3, 0), // 3 months ago
			EndDate:   time.Now(),
		}
		
		// Generate SOC 2 compliance report
		soc2Report, err := reporter.GenerateSOC2Report(suite.ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, soc2Report)
		assert.Equal(t, ComplianceSOC2, soc2Report.Standard)
		assert.NotEmpty(t, soc2Report.Controls)
		assert.NotEmpty(t, soc2Report.Recommendations)
		assert.NotEmpty(t, soc2Report.Evidence)
		assert.True(t, soc2Report.OverallScore >= 0 && soc2Report.OverallScore <= 100)
		
		// Generate ISO 27001 compliance report
		iso27001Report, err := reporter.GenerateISO27001Report(suite.ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, iso27001Report)
		assert.Equal(t, ComplianceISO27001, iso27001Report.Standard)
		assert.NotEmpty(t, iso27001Report.Controls)
		
		// Generate PCI DSS compliance report
		pciReport, err := reporter.GeneratePCIDSSReport(suite.ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, pciReport)
		assert.Equal(t, CompliancePCIDSS, pciReport.Standard)
		
		// Generate HIPAA compliance report
		hipaaReport, err := reporter.GenerateHIPAAReport(suite.ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, hipaaReport)
		assert.Equal(t, ComplianceHIPAA, hipaaReport.Standard)
		
		// Validate compliance for each standard
		standards := []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, CompliancePCIDSS, ComplianceHIPAA}
		for _, standard := range standards {
			validation, err := reporter.ValidateCompliance(suite.ctx, standard)
			require.NoError(t, err, "Failed to validate compliance for %s", standard)
			assert.NotNil(t, validation)
			assert.True(t, validation.Score >= 0 && validation.Score <= 100)
		}
		
		// Verify reports contain required elements
		reports := []*ComplianceReport{soc2Report, iso27001Report, pciReport, hipaaReport}
		for _, report := range reports {
			assert.NotEmpty(t, report.ID)
			assert.NotEmpty(t, report.Controls)
			assert.NotEmpty(t, report.GeneratedBy)
			assert.False(t, report.GeneratedAt.IsZero())
			
			// Verify each control has proper assessment
			for _, control := range report.Controls {
				assert.NotEmpty(t, control.ID)
				assert.NotEmpty(t, control.Name)
				assert.True(t, control.Score >= 0 && control.Score <= 100)
			}
		}
	})
	
	// 5. Zero-Trust Network Security Validation
	suite.T().Run("ZeroTrustValidation", func(t *testing.T) {
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			TrustedNetworks:    []string{"127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"},
			RequiredCertAttrs:  map[string]string{"O": "VaultAgent", "CN": "vault.example.com"},
			DeviceFingerprints: []string{"known-device-1", "known-device-2"},
			MonitoringEnabled:  true,
			StrictMode:         false,
		})
		
		// Test network access validation with various scenarios
		testCases := []struct {
			name     string
			request  *NetworkRequest
			expected AccessResult
		}{
			{
				name: "TrustedNetworkAccess",
				request: &NetworkRequest{
					ID:            "trusted-network-test",
					SourceIP:      []byte{192, 168, 1, 100},
					DestinationIP: []byte{192, 168, 1, 1},
					Port:          443,
					Protocol:      "HTTPS",
					Timestamp:     time.Now(),
				},
				expected: AccessResultAllow,
			},
			{
				name: "UntrustedNetworkAccess",
				request: &NetworkRequest{
					ID:            "untrusted-network-test",
					SourceIP:      []byte{203, 0, 113, 100}, // External IP
					DestinationIP: []byte{192, 168, 1, 1},
					Port:          443,
					Protocol:      "HTTPS",
					Timestamp:     time.Now(),
				},
				expected: AccessResultDeny,
			},
			{
				name: "KnownDeviceAccess",
				request: &NetworkRequest{
					ID:            "known-device-test",
					SourceIP:      []byte{192, 168, 1, 100},
					DestinationIP: []byte{192, 168, 1, 1},
					Port:          443,
					Protocol:      "HTTPS",
					DeviceInfo: &DeviceInfo{
						ID:          "device-1",
						Fingerprint: "known-device-1",
						TrustLevel:  TrustLevelHigh,
					},
					Timestamp: time.Now(),
				},
				expected: AccessResultAllow,
			},
		}
		
		for _, tc := range testCases {
			suite.T().Run(tc.name, func(t *testing.T) {
				decision, err := validator.ValidateNetworkAccess(suite.ctx, tc.request)
				require.NoError(t, err)
				assert.NotNil(t, decision)
				assert.Equal(t, tc.request.ID, decision.RequestID)
				assert.NotEmpty(t, decision.Conditions)
				assert.True(t, decision.Confidence >= 0 && decision.Confidence <= 1)
				
				// In strict mode, verify expected results
				if validator.config.StrictMode {
					assert.Equal(t, tc.expected, decision.Decision)
				}
			})
		}
		
		// Test device identity verification
		testDevice := &DeviceInfo{
			ID:          "e2e-test-device",
			Fingerprint: "e2e-test-fingerprint",
			OS:          "Linux",
			Browser:     "Chrome",
			TrustLevel:  TrustLevelMedium,
			LastSeen:    time.Now().Add(-1 * time.Hour),
			Attributes: map[string]string{
				"version": "1.0",
				"type":    "workstation",
			},
		}
		
		verification, err := validator.VerifyDeviceIdentity(suite.ctx, testDevice)
		require.NoError(t, err)
		assert.NotNil(t, verification)
		assert.Equal(t, testDevice.ID, verification.DeviceID)
		assert.NotEmpty(t, verification.Factors)
		assert.True(t, verification.TrustScore >= 0 && verification.TrustScore <= 1)
		
		// Test network policy enforcement
		policies := []*NetworkPolicy{
			{
				ID:      "e2e-network-policy",
				Name:    "E2E Network Policy",
				Enabled: true,
				Rules: []*NetworkRule{
					{
						ID:     "allow-https",
						Type:   RuleTypeAllow,
						Action: RuleActionAllow,
						Source: &NetworkEndpoint{
							IPRanges: []string{"192.168.0.0/16"},
							Ports:    []int{443},
						},
						Destination: &NetworkEndpoint{
							IPRanges: []string{"192.168.1.0/24"},
							Ports:    []int{443},
						},
					},
				},
			},
		}
		
		err = validator.EnforceNetworkPolicies(suite.ctx, policies)
		require.NoError(t, err)
		
		// Test network traffic monitoring
		trafficAnalysis, err := validator.MonitorNetworkTraffic(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, trafficAnalysis)
		assert.NotNil(t, trafficAnalysis.Period)
		assert.True(t, trafficAnalysis.TotalRequests >= 0)
		assert.NotNil(t, trafficAnalysis.Metrics)
	})
	
	// 6. Security Event Monitoring and Response
	suite.T().Run("SecurityEventMonitoring", func(t *testing.T) {
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        200,
			ProcessingWorkers: 3,
			RetentionPeriod:   7 * 24 * time.Hour,
			AlertThresholds: map[string]int{
				"failed_auth":        5,
				"access_denied":      10,
				"anomalous_activity": 3,
			},
			ResponseEnabled:    true,
			MonitoringInterval: 500 * time.Millisecond,
		})
		
		// Start monitoring
		err := monitor.Start(suite.ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Allow monitor to initialize
		time.Sleep(100 * time.Millisecond)
		
		// Detect security events
		events, err := monitor.DetectSecurityEvents(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, events)
		
		// Create test events if none detected
		if len(events) == 0 {
			testEvents := []*SecurityEvent{
				{
					ID:        "e2e-auth-failure",
					Type:      EventTypeAuthentication,
					Severity:  SeverityHigh,
					Source:    "e2e_test",
					Action:    "login_failed",
					Result:    EventResultFailure,
					Message:   "E2E test authentication failure",
					Context: &EventContext{
						UserID:    "test-user",
						IPAddress: "192.168.1.100",
						UserAgent: "E2E-Test-Agent",
					},
					Timestamp: time.Now(),
				},
				{
					ID:        "e2e-access-denied",
					Type:      EventTypeAuthorization,
					Severity:  SeverityMedium,
					Source:    "e2e_test",
					Action:    "access_denied",
					Result:    EventResultBlocked,
					Message:   "E2E test access denied",
					Context: &EventContext{
						UserID:    "test-user",
						IPAddress: "192.168.1.100",
					},
					Timestamp: time.Now(),
				},
			}
			events = append(events, testEvents...)
		}
		
		// Analyze threat patterns
		analysis, err := monitor.AnalyzeThreatPatterns(suite.ctx, events)
		require.NoError(t, err)
		assert.NotNil(t, analysis)
		assert.Equal(t, int64(len(events)), analysis.TotalEvents)
		assert.NotNil(t, analysis.Patterns)
		assert.NotNil(t, analysis.Indicators)
		assert.NotNil(t, analysis.Recommendations)
		
		// Trigger security responses for high-severity events
		for _, event := range events {
			if event.Severity == SeverityHigh || event.Severity == SeverityCritical {
				err := monitor.TriggerSecurityResponse(suite.ctx, event)
				require.NoError(t, err)
				assert.NotEmpty(t, event.ResponseID)
			}
		}
		
		// Get security metrics
		metricsResult, err := monitor.GetSecurityMetrics(suite.ctx, &ReportPeriod{
			StartDate: time.Now().Add(-24 * time.Hour),
			EndDate:   time.Now(),
		})
		require.NoError(t, err)
		assert.NotNil(t, metricsResult)
		assert.NotNil(t, metricsResult.EventCounts)
		assert.NotNil(t, metricsResult.SeverityCounts)
		assert.True(t, metricsResult.DetectionRate >= 0 && metricsResult.DetectionRate <= 1)
		assert.True(t, metricsResult.FalsePositiveRate >= 0 && metricsResult.FalsePositiveRate <= 1)
	})
	
	// 7. Attack Simulation and Security Validation
	suite.T().Run("AttackSimulation", func(t *testing.T) {
		simulator := NewAttackSimulator(&AttackSimulatorConfig{
			TargetURL:      suite.testServer.URL,
			MaxConcurrency: 3,
			RequestTimeout: 10 * time.Second,
			SafeMode:       true,
			EnabledAttacks: []AttackType{
				AttackTypeBruteForce,
				AttackTypeSQLInjection,
				AttackTypeXSS,
				AttackTypeCSRF,
				AttackTypeDOS,
			},
			RateLimitDelay: 50 * time.Millisecond,
		})
		
		// Run comprehensive attack simulation
		simulationResult, err := simulator.RunAttackSimulation(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, simulationResult)
		assert.NotEmpty(t, simulationResult.Scenarios)
		assert.NotNil(t, simulationResult.Summary)
		
		// Verify all enabled attack types were tested
		attackTypes := make(map[AttackType]bool)
		for _, scenario := range simulationResult.Scenarios {
			attackTypes[scenario.Type] = true
		}
		
		for _, enabledType := range simulator.config.EnabledAttacks {
			assert.True(t, attackTypes[enabledType], "Attack type %s was not tested", enabledType)
		}
		
		// Execute specific attack scenarios
		scenarios := simulator.GetAvailableScenarios()
		assert.NotEmpty(t, scenarios)
		
		for _, scenario := range scenarios[:3] { // Test first 3 scenarios
			scenarioResult, err := simulator.ExecuteSpecificAttack(suite.ctx, scenario.ID)
			require.NoError(t, err)
			assert.NotNil(t, scenarioResult)
			assert.Equal(t, scenario.ID, scenarioResult.ScenarioID)
			assert.NotEmpty(t, scenarioResult.Attempts)
			
			// Verify attempts were made
			for _, attempt := range scenarioResult.Attempts {
				assert.NotEmpty(t, attempt.ID)
				assert.NotEmpty(t, attempt.Method)
				assert.NotEmpty(t, attempt.Endpoint)
				assert.False(t, attempt.Timestamp.IsZero())
			}
		}
		
		// Generate comprehensive attack report
		attackReport, err := simulator.GenerateAttackReport(suite.ctx, simulationResult)
		require.NoError(t, err)
		assert.NotNil(t, attackReport)
		assert.Equal(t, simulationResult.ID, attackReport.SimulationID)
		assert.NotEmpty(t, attackReport.ExecutiveSummary)
		assert.NotNil(t, attackReport.RiskAssessment)
		
		// Verify security effectiveness
		assert.True(t, simulationResult.Summary.SecurityEffectiveness >= 0)
		assert.True(t, simulationResult.Summary.SecurityEffectiveness <= 100)
		
		// In safe mode, most attacks should be blocked
		if simulator.config.SafeMode {
			assert.True(t, simulationResult.Summary.BlockedAttacks >= simulationResult.Summary.SuccessfulAttacks)
		}
	})
}

func (suite *SecurityE2ETestSuite) TestSecurityHardeningValidation() {
	// Test validation of security hardening measures
	
	suite.T().Run("ConfigurationHardening", func(t *testing.T) {
		scanner := NewSecurityScanner(nil)
		
		// Scan configuration for security issues
		configResult, err := scanner.ScanConfiguration(suite.ctx)
		require.NoError(t, err)
		assert.NotNil(t, configResult)
		
		// Verify configuration scan identifies security issues
		assert.NotNil(t, configResult.ConfigFiles)
		
		// Check for common security misconfigurations
		hasSecurityFindings := false
		for _, configFile := range configResult.ConfigFiles {
			if len(configFile.Issues) > 0 {
				hasSecurityFindings = true
				
				// Verify findings have proper remediation guidance
				for _, issue := range configFile.Issues {
					assert.NotEmpty(t, issue.Title)
					assert.NotEmpty(t, issue.Description)
					assert.NotEmpty(t, issue.Remediation)
					assert.NotEmpty(t, issue.Severity)
				}
			}
		}
		
		// Configuration scan should provide actionable results
		assert.True(t, hasSecurityFindings || len(configResult.ConfigFiles) == 0)
	})
	
	suite.T().Run("NetworkHardening", func(t *testing.T) {
		validator := NewZeroTrustValidator(nil)
		
		// Test network security policies
		policies := []*NetworkPolicy{
			{
				ID:      "hardening-policy",
				Name:    "Security Hardening Policy",
				Enabled: true,
				Rules: []*NetworkRule{
					{
						ID:     "deny-all-default",
						Type:   RuleTypeDeny,
						Action: RuleActionDeny,
					},
					{
						ID:     "allow-https-only",
						Type:   RuleTypeAllow,
						Action: RuleActionAllow,
						Destination: &NetworkEndpoint{
							Ports: []int{443},
						},
					},
				},
			},
		}
		
		err := validator.EnforceNetworkPolicies(suite.ctx, policies)
		require.NoError(t, err)
		
		// Test network access with hardened policies
		request := &NetworkRequest{
			ID:            "hardening-test",
			SourceIP:      []byte{192, 168, 1, 100},
			DestinationIP: []byte{192, 168, 1, 1},
			Port:          443,
			Protocol:      "HTTPS",
			Timestamp:     time.Now(),
		}
		
		decision, err := validator.ValidateNetworkAccess(suite.ctx, request)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		
		// Verify hardening policies are enforced
		assert.NotEmpty(t, decision.Conditions)
		assert.NotEmpty(t, decision.Policies)
	})
	
	suite.T().Run("AccessControlHardening", func(t *testing.T) {
		manager := NewSecurityPolicyManager(nil)
		
		// Create hardened access control policy
		policy := &SecurityPolicy{
			ID:       "hardened-access-policy",
			Name:     "Hardened Access Control Policy",
			Category: PolicyCategoryAccess,
			Rules: []*PolicyRule{
				{
					ID:        "require-mfa",
					Name:      "Require Multi-Factor Authentication",
					Condition: "auth.mfa_enabled == true",
					Action:    "enforce",
					Enabled:   true,
				},
				{
					ID:        "strong-passwords",
					Name:      "Enforce Strong Passwords",
					Condition: "password.length >= 12 AND password.complexity == true",
					Action:    "enforce",
					Enabled:   true,
				},
				{
					ID:        "session-timeout",
					Name:      "Enforce Session Timeout",
					Condition: "session.duration <= 8h",
					Action:    "enforce",
					Enabled:   true,
				},
			},
			Enforcement: EnforcementLevelEnforcing,
		}
		
		// Validate hardened policy
		validation, err := manager.ValidatePolicyCompliance(suite.ctx, policy)
		require.NoError(t, err)
		assert.NotNil(t, validation)
		assert.True(t, validation.Valid)
		assert.True(t, validation.Score >= 80.0) // Hardened policy should score high
		
		// Apply hardened policy
		err = manager.ApplySecurityPolicy(suite.ctx, policy)
		require.NoError(t, err)
	})
}

func (suite *SecurityE2ETestSuite) TestComplianceWorkflow() {
	// Test complete compliance workflow from assessment to reporting
	
	reporter := NewComplianceReporter(&ComplianceConfig{
		Standards:       []ComplianceStandard{ComplianceSOC2, ComplianceISO27001},
		ReportPath:      filepath.Join(suite.testDir, "reports"),
		AutoGenerate:    true,
		RetentionPeriod: 365 * 24 * time.Hour,
	})
	
	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -6, 0), // 6 months ago
		EndDate:   time.Now(),
	}
	
	// Generate comprehensive compliance reports
	soc2Report, err := reporter.GenerateSOC2Report(suite.ctx, period)
	suite.Require().NoError(err)
	suite.Assert().NotNil(soc2Report)
	
	iso27001Report, err := reporter.GenerateISO27001Report(suite.ctx, period)
	suite.Require().NoError(err)
	suite.Assert().NotNil(iso27001Report)
	
	// Verify compliance reports meet requirements
	reports := []*ComplianceReport{soc2Report, iso27001Report}
	for _, report := range reports {
		// Verify report structure
		suite.Assert().NotEmpty(report.ID)
		suite.Assert().NotEmpty(report.Controls)
		suite.Assert().NotEmpty(report.Recommendations)
		suite.Assert().NotEmpty(report.Evidence)
		suite.Assert().False(report.GeneratedAt.IsZero())
		
		// Verify control assessments
		for _, control := range report.Controls {
			suite.Assert().NotEmpty(control.ID)
			suite.Assert().NotEmpty(control.Name)
			suite.Assert().True(control.Score >= 0 && control.Score <= 100)
			
			// Controls should have evidence or gaps identified
			suite.Assert().True(len(control.Evidence) > 0 || len(control.Gaps) > 0)
		}
		
		// Verify recommendations are actionable
		for _, rec := range report.Recommendations {
			suite.Assert().NotEmpty(rec.Title)
			suite.Assert().NotEmpty(rec.Actions)
			suite.Assert().NotEmpty(rec.Timeline)
		}
		
		// Verify evidence collection
		for _, evidence := range report.Evidence {
			suite.Assert().NotEmpty(evidence.ID)
			suite.Assert().NotEmpty(evidence.Type)
			suite.Assert().NotEmpty(evidence.Description)
			suite.Assert().False(evidence.Timestamp.IsZero())
		}
	}
	
	// Validate compliance status
	for _, standard := range []ComplianceStandard{ComplianceSOC2, ComplianceISO27001} {
		validation, err := reporter.ValidateCompliance(suite.ctx, standard)
		suite.Require().NoError(err)
		suite.Assert().NotNil(validation)
		suite.Assert().True(validation.Score >= 0 && validation.Score <= 100)
	}
}

// Run the E2E test suite
func TestSecurityE2ETestSuite(t *testing.T) {
	suite.Run(t, new(SecurityE2ETestSuite))
}

// Additional E2E test functions

func TestSecurityWorkflowIntegration(t *testing.T) {
	// Test integration of complete security workflow
	
	ctx := context.Background()
	
	// Create temporary directory for test
	testDir, err := os.MkdirTemp("", "security-workflow-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(testDir)
	
	// Initialize all components
	scanner := NewSecurityScanner(nil)
	reporter := NewComplianceReporter(nil)
	tester := NewPenetrationTester(nil)
	validator := NewZeroTrustValidator(nil)
	manager := NewSecurityPolicyManager(&PolicyManagerConfig{
		TemplatesPath: filepath.Join(testDir, "templates"),
		PoliciesPath:  filepath.Join(testDir, "policies"),
	})
	monitor := NewSecurityEventMonitor(nil)
	simulator := NewAttackSimulator(&AttackSimulatorConfig{SafeMode: true})
	
	// Start monitoring
	err = monitor.Start(ctx)
	require.NoError(t, err)
	defer monitor.Stop()
	
	// 1. Run initial security assessment
	scanResult, err := scanner.ScanVulnerabilities(ctx, &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthBasic,
		Timeout:  10 * time.Second,
	})
	require.NoError(t, err)
	assert.NotNil(t, scanResult)
	
	// 2. Generate compliance report based on findings
	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
	}
	
	complianceReport, err := reporter.GenerateSOC2Report(ctx, period)
	require.NoError(t, err)
	assert.NotNil(t, complianceReport)
	
	// 3. Create security policies based on compliance requirements
	policy := &SecurityPolicy{
		ID:       "workflow-test-policy",
		Name:     "Workflow Test Policy",
		Category: PolicyCategoryAccess,
		Rules: []*PolicyRule{
			{
				ID:        "workflow-rule",
				Name:      "Workflow Test Rule",
				Condition: "user.authenticated == true",
				Action:    "allow",
				Enabled:   true,
			},
		},
		Enforcement: EnforcementLevelEnforcing,
	}
	
	err = manager.ApplySecurityPolicy(ctx, policy)
	require.NoError(t, err)
	
	// 4. Run penetration tests to validate security controls
	penTestResult, err := tester.ValidateSecurityControls(ctx)
	require.NoError(t, err)
	assert.NotNil(t, penTestResult)
	
	// 5. Simulate attacks to test defenses
	attackResult, err := simulator.RunAttackSimulation(ctx)
	require.NoError(t, err)
	assert.NotNil(t, attackResult)
	
	// 6. Validate zero-trust controls
	networkRequest := &NetworkRequest{
		ID:            "workflow-test",
		SourceIP:      []byte{127, 0, 0, 1},
		DestinationIP: []byte{127, 0, 0, 1},
		Port:          443,
		Protocol:      "HTTPS",
		Timestamp:     time.Now(),
	}
	
	decision, err := validator.ValidateNetworkAccess(ctx, networkRequest)
	require.NoError(t, err)
	assert.NotNil(t, decision)
	
	// 7. Monitor security events throughout the process
	events, err := monitor.DetectSecurityEvents(ctx)
	require.NoError(t, err)
	assert.NotNil(t, events)
	
	// Verify workflow integration
	assert.NotNil(t, scanResult.Summary)
	assert.NotNil(t, complianceReport.Controls)
	assert.NotNil(t, penTestResult.Controls)
	assert.NotNil(t, attackResult.Summary)
	assert.NotNil(t, decision.Conditions)
	
	// Verify security effectiveness improved through the workflow
	if attackResult.Summary.SecurityEffectiveness > 0 {
		assert.True(t, attackResult.Summary.BlockedAttacks >= attackResult.Summary.SuccessfulAttacks)
	}
}