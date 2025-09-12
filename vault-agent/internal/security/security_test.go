package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityScanner(t *testing.T) {
	config := &ScannerConfig{
		ScanTimeout:   5 * time.Minute,
		MaxConcurrent: 3,
		EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration},
	}
	scanner := NewSecurityScanner(config)

	t.Run("VulnerabilityScan", func(t *testing.T) {
		ctx := context.Background()
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  []string{"localhost"},
			Depth:    ScanDepthStandard,
			Timeout:  1 * time.Minute,
		}

		result, err := scanner.ScanVulnerabilities(ctx, scanConfig)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, ScanTypeVulnerability, result.ScanType)
		assert.Equal(t, ScanStatusCompleted, result.Status)
		assert.NotNil(t, result.Summary)
	})

	t.Run("ConfigurationScan", func(t *testing.T) {
		ctx := context.Background()

		result, err := scanner.ScanConfiguration(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, ScanTypeConfiguration, result.ScanType)
		assert.Equal(t, ScanStatusCompleted, result.Status)
	})

	t.Run("CertificateScan", func(t *testing.T) {
		ctx := context.Background()

		result, err := scanner.ScanCertificates(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, ScanTypeCertificate, result.ScanType)
		assert.Equal(t, ScanStatusCompleted, result.Status)
	})

	t.Run("DependencyScan", func(t *testing.T) {
		ctx := context.Background()

		result, err := scanner.ScanDependencies(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, ScanTypeDependency, result.ScanType)
		assert.Equal(t, ScanStatusCompleted, result.Status)
	})
}

func TestComplianceReporter(t *testing.T) {
	config := &ComplianceConfig{
		Standards:    []ComplianceStandard{ComplianceSOC2, ComplianceISO27001},
		AutoGenerate: true,
	}
	reporter := NewComplianceReporter(config)

	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
	}

	t.Run("SOC2Report", func(t *testing.T) {
		ctx := context.Background()

		report, err := reporter.GenerateSOC2Report(ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, ComplianceSOC2, report.Standard)
		assert.NotEmpty(t, report.Controls)
		assert.GreaterOrEqual(t, report.OverallScore, 0.0)
		assert.LessOrEqual(t, report.OverallScore, 100.0)
	})

	t.Run("ISO27001Report", func(t *testing.T) {
		ctx := context.Background()

		report, err := reporter.GenerateISO27001Report(ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, ComplianceISO27001, report.Standard)
		assert.NotEmpty(t, report.Controls)
		assert.GreaterOrEqual(t, report.OverallScore, 0.0)
		assert.LessOrEqual(t, report.OverallScore, 100.0)
	})

	t.Run("PCIDSSReport", func(t *testing.T) {
		ctx := context.Background()

		report, err := reporter.GeneratePCIDSSReport(ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, CompliancePCIDSS, report.Standard)
		assert.NotEmpty(t, report.Controls)
	})

	t.Run("HIPAAReport", func(t *testing.T) {
		ctx := context.Background()

		report, err := reporter.GenerateHIPAAReport(ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, ComplianceHIPAA, report.Standard)
		assert.NotEmpty(t, report.Controls)
	})

	t.Run("ValidateCompliance", func(t *testing.T) {
		ctx := context.Background()

		result, err := reporter.ValidateCompliance(ctx, ComplianceSOC2)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestPenetrationTester(t *testing.T) {
	config := &PenTestConfig{
		TargetHost:    "localhost",
		TargetPort:    8080,
		TestTimeout:   5 * time.Minute,
		MaxConcurrent: 2,
		EnabledTests:  []TestType{TestTypeSSLTLS, TestTypeAuthentication},
		SafeMode:      true,
	}
	tester := NewPenetrationTester(config)

	t.Run("RunSecurityTests", func(t *testing.T) {
		ctx := context.Background()

		result, err := tester.RunSecurityTests(ctx, config)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Tests)
		assert.NotNil(t, result.Summary)
		assert.GreaterOrEqual(t, result.RiskScore, 0.0)
	})

	t.Run("SimulateAttack", func(t *testing.T) {
		ctx := context.Background()
		attack := &AttackScenario{
			ID:       "test-attack-1",
			Name:     "Test Brute Force",
			Type:     AttackTypeBruteForce,
			Target:   "auth_endpoint",
			Payload:  "admin:password",
			Expected: AttackOutcomeBlocked,
		}

		result, err := tester.SimulateAttack(ctx, attack)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, attack.ID, result.ScenarioID)
		assert.NotEmpty(t, result.Evidence)
	})

	t.Run("ValidateSecurityControls", func(t *testing.T) {
		ctx := context.Background()

		validation, err := tester.ValidateSecurityControls(ctx)
		require.NoError(t, err)
		assert.NotNil(t, validation)
		assert.NotEmpty(t, validation.Controls)
		assert.GreaterOrEqual(t, validation.OverallScore, 0.0)
		assert.LessOrEqual(t, validation.OverallScore, 100.0)
	})

	t.Run("GenerateSecurityReport", func(t *testing.T) {
		ctx := context.Background()

		report, err := tester.GenerateSecurityReport(ctx)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.NotEmpty(t, report.ExecutiveSummary)
		assert.NotNil(t, report.RiskAssessment)
		assert.NotEmpty(t, report.TestResults)
		assert.NotEmpty(t, report.Compliance)
	})
}

func TestZeroTrustValidator(t *testing.T) {
	config := &ZeroTrustConfig{
		TrustedNetworks:   []string{"192.168.1.0/24", "10.0.0.0/8"},
		RequiredCertAttrs: map[string]string{"O": "VaultAgent"},
		MonitoringEnabled: true,
		StrictMode:        false,
	}
	validator := NewZeroTrustValidator(config)

	t.Run("ValidateNetworkAccess", func(t *testing.T) {
		ctx := context.Background()
		request := &NetworkRequest{
			ID:            "test-request-1",
			SourceIP:      net.ParseIP("192.168.1.100"),
			DestinationIP: net.ParseIP("192.168.1.1"),
			Port:          443,
			Protocol:      "HTTPS",
			UserAgent:     "VaultAgent/1.0",
			DeviceInfo: &DeviceInfo{
				ID:          "device-1",
				Fingerprint: "test-fingerprint",
				TrustLevel:  TrustLevelHigh,
			},
			Timestamp: time.Now(),
		}

		decision, err := validator.ValidateNetworkAccess(ctx, request)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, request.ID, decision.RequestID)
		assert.NotEmpty(t, decision.Conditions)
		assert.GreaterOrEqual(t, decision.Confidence, 0.0)
		assert.LessOrEqual(t, decision.Confidence, 1.0)
	})

	t.Run("VerifyDeviceIdentity", func(t *testing.T) {
		ctx := context.Background()
		device := &DeviceInfo{
			ID:          "device-1",
			Fingerprint: "test-fingerprint",
			OS:          "Linux",
			Browser:     "Chrome",
			TrustLevel:  TrustLevelMedium,
			LastSeen:    time.Now().Add(-1 * time.Hour),
		}

		verification, err := validator.VerifyDeviceIdentity(ctx, device)
		require.NoError(t, err)
		assert.NotNil(t, verification)
		assert.Equal(t, device.ID, verification.DeviceID)
		assert.NotEmpty(t, verification.Factors)
		assert.GreaterOrEqual(t, verification.TrustScore, 0.0)
		assert.LessOrEqual(t, verification.TrustScore, 1.0)
	})

	t.Run("EnforceNetworkPolicies", func(t *testing.T) {
		ctx := context.Background()
		policies := []*NetworkPolicy{
			{
				ID:      "policy-1",
				Name:    "Test Policy",
				Enabled: true,
				Rules: []*NetworkRule{
					{
						ID:     "rule-1",
						Type:   RuleTypeAllow,
						Action: RuleActionAllow,
						Source: &NetworkEndpoint{
							IPRanges: []string{"192.168.1.0/24"},
						},
					},
				},
			},
		}

		err := validator.EnforceNetworkPolicies(ctx, policies)
		require.NoError(t, err)
	})

	t.Run("MonitorNetworkTraffic", func(t *testing.T) {
		ctx := context.Background()

		analysis, err := validator.MonitorNetworkTraffic(ctx)
		require.NoError(t, err)
		assert.NotNil(t, analysis)
		assert.NotNil(t, analysis.Period)
		assert.GreaterOrEqual(t, analysis.TotalRequests, int64(0))
		assert.NotNil(t, analysis.Metrics)
	})
}

func TestSecurityPolicyManager(t *testing.T) {
	config := &PolicyManagerConfig{
		TemplatesPath:     "./test-templates/",
		PoliciesPath:      "./test-policies/",
		EnabledCategories: []string{"access", "encryption"},
		ValidationStrict:  true,
	}
	manager := NewSecurityPolicyManager(config)

	t.Run("CreatePolicyTemplate", func(t *testing.T) {
		ctx := context.Background()
		template := &PolicyTemplate{
			Name:        "Test Template",
			Category:    PolicyCategoryAccess,
			Description: "Test policy template",
			Version:     "1.0",
			Rules: []*PolicyRuleTemplate{
				{
					Name:        "Test Rule",
					Description: "Test rule description",
					Condition:   "user.role == 'admin'",
					Action:      "allow",
					Required:    true,
				},
			},
		}

		err := manager.CreatePolicyTemplate(ctx, template)
		require.NoError(t, err)
		assert.NotEmpty(t, template.ID)
	})

	t.Run("ValidatePolicyCompliance", func(t *testing.T) {
		ctx := context.Background()
		policy := &SecurityPolicy{
			ID:       "test-policy-1",
			Name:     "Test Policy",
			Category: PolicyCategoryAccess,
			Rules: []*PolicyRule{
				{
					ID:        "rule-1",
					Name:      "Test Rule",
					Condition: "user.authenticated == true",
					Action:    "allow",
					Enabled:   true,
				},
			},
			Enforcement: EnforcementLevelEnforcing,
		}

		validation, err := manager.ValidatePolicyCompliance(ctx, policy)
		require.NoError(t, err)
		assert.NotNil(t, validation)
		assert.Equal(t, policy.ID, validation.PolicyID)
		assert.GreaterOrEqual(t, validation.Score, 0.0)
		assert.LessOrEqual(t, validation.Score, 100.0)
	})

	t.Run("GetBestPracticeGuides", func(t *testing.T) {
		ctx := context.Background()

		guides, err := manager.GetBestPracticeGuides(ctx, "encryption")
		require.NoError(t, err)
		assert.NotEmpty(t, guides)
		
		for _, guide := range guides {
			assert.NotEmpty(t, guide.Title)
			assert.NotEmpty(t, guide.Practices)
		}
	})

	t.Run("GeneratePolicyRecommendations", func(t *testing.T) {
		ctx := context.Background()

		recommendations, err := manager.GeneratePolicyRecommendations(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, recommendations)
		
		for _, rec := range recommendations {
			assert.NotEmpty(t, rec.Title)
			assert.NotEmpty(t, rec.Actions)
		}
	})
}

func TestSecurityEventMonitor(t *testing.T) {
	config := &EventMonitorConfig{
		BufferSize:        100,
		ProcessingWorkers: 2,
		RetentionPeriod:   24 * time.Hour,
		AlertThresholds: map[string]int{
			"failed_auth": 5,
		},
		ResponseEnabled:    true,
		MonitoringInterval: 1 * time.Second,
	}
	monitor := NewSecurityEventMonitor(config)

	t.Run("StartStop", func(t *testing.T) {
		ctx := context.Background()

		err := monitor.Start(ctx)
		require.NoError(t, err)

		// Let it run briefly
		time.Sleep(100 * time.Millisecond)

		err = monitor.Stop()
		require.NoError(t, err)
	})

	t.Run("DetectSecurityEvents", func(t *testing.T) {
		ctx := context.Background()

		events, err := monitor.DetectSecurityEvents(ctx)
		require.NoError(t, err)
		assert.NotNil(t, events)
		
		for _, event := range events {
			assert.NotEmpty(t, event.ID)
			assert.NotEmpty(t, event.Type)
			assert.NotEmpty(t, event.Message)
		}
	})

	t.Run("AnalyzeThreatPatterns", func(t *testing.T) {
		ctx := context.Background()
		events := []*SecurityEvent{
			{
				ID:        "event-1",
				Type:      EventTypeAuthentication,
				Severity:  SeverityHigh,
				Source:    "auth_service",
				Action:    "login_failed",
				Result:    EventResultFailure,
				Message:   "Authentication failed",
				Timestamp: time.Now(),
			},
			{
				ID:        "event-2",
				Type:      EventTypeDataAccess,
				Severity:  SeverityMedium,
				Source:    "api_gateway",
				Action:    "secret_access",
				Result:    EventResultSuccess,
				Message:   "Secret accessed",
				Timestamp: time.Now(),
			},
		}

		analysis, err := monitor.AnalyzeThreatPatterns(ctx, events)
		require.NoError(t, err)
		assert.NotNil(t, analysis)
		assert.Equal(t, int64(len(events)), analysis.TotalEvents)
		assert.NotNil(t, analysis.Metrics)
	})

	t.Run("GetSecurityMetrics", func(t *testing.T) {
		ctx := context.Background()
		period := &ReportPeriod{
			StartDate: time.Now().Add(-24 * time.Hour),
			EndDate:   time.Now(),
		}

		metrics, err := monitor.GetSecurityMetrics(ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, metrics)
		assert.Equal(t, period, metrics.Period)
		assert.NotEmpty(t, metrics.EventCounts)
		assert.NotEmpty(t, metrics.SeverityCounts)
	})

	t.Run("RegisterResponseHandler", func(t *testing.T) {
		customHandler := func(ctx context.Context, event *SecurityEvent) error {
			return nil
		}

		monitor.RegisterResponseHandler("custom_event", customHandler)
		
		// Verify handler was registered (internal state check)
		assert.NotNil(t, monitor.responses["custom_event"])
	})
}

// Integration tests

func TestSecurityIntegration(t *testing.T) {
	t.Run("FullSecurityScan", func(t *testing.T) {
		ctx := context.Background()

		// Initialize components
		scanner := NewSecurityScanner(nil)
		reporter := NewComplianceReporter(nil)
		tester := NewPenetrationTester(nil)

		// Run vulnerability scan
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  []string{"localhost"},
			Depth:    ScanDepthBasic,
			Timeout:  30 * time.Second,
		}
		scanResult, err := scanner.ScanVulnerabilities(ctx, scanConfig)
		require.NoError(t, err)
		assert.NotNil(t, scanResult)

		// Generate compliance report
		period := &ReportPeriod{
			StartDate: time.Now().AddDate(0, -1, 0),
			EndDate:   time.Now(),
		}
		complianceReport, err := reporter.GenerateSOC2Report(ctx, period)
		require.NoError(t, err)
		assert.NotNil(t, complianceReport)

		// Run penetration tests
		penTestConfig := &PenTestConfig{
			TargetHost:   "localhost",
			TargetPort:   8080,
			TestTimeout:  30 * time.Second,
			EnabledTests: []TestType{TestTypeAuthentication},
			SafeMode:     true,
		}
		penTestResult, err := tester.RunSecurityTests(ctx, penTestConfig)
		require.NoError(t, err)
		assert.NotNil(t, penTestResult)

		// Verify integration
		assert.True(t, scanResult.Summary.TotalFindings >= 0)
		assert.True(t, complianceReport.OverallScore >= 0)
		assert.True(t, penTestResult.Summary.TotalTests > 0)
	})

	t.Run("SecurityEventFlow", func(t *testing.T) {
		ctx := context.Background()

		// Initialize event monitor
		monitor := NewSecurityEventMonitor(nil)
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer monitor.Stop()

		// Detect events
		events, err := monitor.DetectSecurityEvents(ctx)
		require.NoError(t, err)

		if len(events) > 0 {
			// Analyze threats
			analysis, err := monitor.AnalyzeThreatPatterns(ctx, events)
			require.NoError(t, err)
			assert.NotNil(t, analysis)

			// Trigger responses for high-severity events
			for _, event := range events {
				if event.Severity == SeverityHigh || event.Severity == SeverityCritical {
					err := monitor.TriggerSecurityResponse(ctx, event)
					require.NoError(t, err)
				}
			}
		}
	})
}

// Benchmark tests

func BenchmarkSecurityScanner(b *testing.B) {
	scanner := NewSecurityScanner(nil)
	ctx := context.Background()
	scanConfig := &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthBasic,
		Timeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZeroTrustValidation(b *testing.B) {
	validator := NewZeroTrustValidator(nil)
	ctx := context.Background()
	request := &NetworkRequest{
		ID:            "bench-request",
		SourceIP:      net.ParseIP("192.168.1.100"),
		DestinationIP: net.ParseIP("192.168.1.1"),
		Port:          443,
		Protocol:      "HTTPS",
		Timestamp:     time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.ValidateNetworkAccess(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEventProcessing(b *testing.B) {
	monitor := NewSecurityEventMonitor(nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := monitor.DetectSecurityEvents(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helper functions for tests

func createTestCertificate() *x509.Certificate {
	return &x509.Certificate{
		Subject: x509.Name{
			Organization: []string{"VaultAgent"},
			CommonName:   "test.example.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}
}

func createTestTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}