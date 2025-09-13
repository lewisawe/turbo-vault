package security

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// ChaosTestSuite provides chaos engineering tests for security components
type ChaosTestSuite struct {
	suite.Suite
	ctx           context.Context
	cancelFunc    context.CancelFunc
	testServer    *httptest.Server
	flakyServer   *httptest.Server
	slowServer    *httptest.Server
	errorServer   *httptest.Server
	networkFaults map[string]bool
	mutex         sync.RWMutex
}

func (suite *ChaosTestSuite) SetupSuite() {
	suite.ctx, suite.cancelFunc = context.WithCancel(context.Background())
	suite.networkFaults = make(map[string]bool)
	
	// Create test servers with different failure modes
	suite.setupTestServers()
}

func (suite *ChaosTestSuite) TearDownSuite() {
	if suite.cancelFunc != nil {
		suite.cancelFunc()
	}
	
	if suite.testServer != nil {
		suite.testServer.Close()
	}
	if suite.flakyServer != nil {
		suite.flakyServer.Close()
	}
	if suite.slowServer != nil {
		suite.slowServer.Close()
	}
	if suite.errorServer != nil {
		suite.errorServer.Close()
	}
}

func (suite *ChaosTestSuite) setupTestServers() {
	// Normal test server
	suite.testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	
	// Flaky server (randomly fails)
	suite.flakyServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rand.Float32() < 0.3 { // 30% failure rate
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"random_failure"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	
	// Slow server (introduces latency)
	suite.slowServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Random delay between 100ms and 2s
		delay := time.Duration(rand.Intn(1900)+100) * time.Millisecond
		time.Sleep(delay)
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"slow_ok"}`))
	}))
	
	// Error server (always fails)
	suite.errorServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"service_unavailable"}`))
	}))
}

func (suite *ChaosTestSuite) injectNetworkFault(target string) {
	suite.mutex.Lock()
	defer suite.mutex.Unlock()
	suite.networkFaults[target] = true
}

func (suite *ChaosTestSuite) removeNetworkFault(target string) {
	suite.mutex.Lock()
	defer suite.mutex.Unlock()
	delete(suite.networkFaults, target)
}

func (suite *ChaosTestSuite) hasNetworkFault(target string) bool {
	suite.mutex.RLock()
	defer suite.mutex.RUnlock()
	return suite.networkFaults[target]
}

func (suite *ChaosTestSuite) TestSecurityScannerChaos() {
	// Test security scanner resilience under various failure conditions
	
	suite.T().Run("NetworkFailures", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   30 * time.Second,
			MaxConcurrent: 2,
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration},
		})
		
		// Test with unreachable targets
		unreachableTargets := []string{
			"192.0.2.1",      // TEST-NET-1 (RFC 5737)
			"198.51.100.1",   // TEST-NET-2 (RFC 5737)
			"203.0.113.1",    // TEST-NET-3 (RFC 5737)
			"invalid.domain", // Invalid domain
		}
		
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  unreachableTargets,
			Depth:    ScanDepthBasic,
			Timeout:  5 * time.Second,
		}
		
		result, err := scanner.ScanVulnerabilities(suite.ctx, scanConfig)
		
		// Scanner should handle network failures gracefully
		if err != nil {
			// Error is acceptable for unreachable targets
			assert.Contains(t, err.Error(), "timeout")
		} else {
			// If no error, result should still be valid
			assert.NotNil(t, result)
			assert.Equal(t, ScanStatusCompleted, result.Status)
		}
	})
	
	suite.T().Run("TimeoutHandling", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   1 * time.Second, // Very short timeout
			MaxConcurrent: 1,
			EnabledScans:  []ScanType{ScanTypeVulnerability},
		})
		
		// Use slow server to trigger timeouts
		slowTarget := suite.slowServer.URL
		
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  []string{slowTarget},
			Depth:    ScanDepthBasic,
			Timeout:  500 * time.Millisecond, // Even shorter timeout
		}
		
		result, err := scanner.ScanVulnerabilities(suite.ctx, scanConfig)
		
		// Scanner should handle timeouts gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "timeout")
		} else {
			assert.NotNil(t, result)
			// May complete with partial results
		}
	})
	
	suite.T().Run("ConcurrentFailures", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   10 * time.Second,
			MaxConcurrent: 5,
			EnabledScans:  []ScanType{ScanTypeVulnerability},
		})
		
		// Mix of working and failing targets
		mixedTargets := []string{
			suite.testServer.URL,
			suite.flakyServer.URL,
			suite.errorServer.URL,
			"192.0.2.1", // Unreachable
		}
		
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  mixedTargets,
			Depth:    ScanDepthBasic,
			Timeout:  5 * time.Second,
		}
		
		result, err := scanner.ScanVulnerabilities(suite.ctx, scanConfig)
		
		// Scanner should handle mixed success/failure scenarios
		assert.NoError(t, err) // Should not fail completely
		assert.NotNil(t, result)
		assert.Equal(t, ScanStatusCompleted, result.Status)
		
		// Should have some findings even with partial failures
		assert.NotNil(t, result.Summary)
	})
	
	suite.T().Run("ResourceExhaustion", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   30 * time.Second,
			MaxConcurrent: 100, // High concurrency to stress test
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration, ScanTypeCertificate},
		})
		
		// Large number of targets
		manyTargets := make([]string, 50)
		for i := 0; i < 50; i++ {
			manyTargets[i] = fmt.Sprintf("192.0.2.%d", i+1)
		}
		
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  manyTargets,
			Depth:    ScanDepthBasic,
			Timeout:  2 * time.Second,
		}
		
		result, err := scanner.ScanVulnerabilities(suite.ctx, scanConfig)
		
		// Scanner should handle resource constraints gracefully
		if err != nil {
			// May fail due to resource limits
			assert.NotEmpty(t, err.Error())
		} else {
			assert.NotNil(t, result)
		}
	})
}

func (suite *ChaosTestSuite) TestComplianceReporterChaos() {
	// Test compliance reporter resilience under failure conditions
	
	suite.T().Run("DataCorruption", func(t *testing.T) {
		reporter := NewComplianceReporter(&ComplianceConfig{
			Standards:    []ComplianceStandard{ComplianceSOC2, ComplianceISO27001},
			AutoGenerate: true,
		})
		
		// Test with invalid period
		invalidPeriod := &ReportPeriod{
			StartDate: time.Now().Add(24 * time.Hour), // Future start date
			EndDate:   time.Now().Add(-24 * time.Hour), // Past end date
		}
		
		report, err := reporter.GenerateSOC2Report(suite.ctx, invalidPeriod)
		
		// Reporter should handle invalid data gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "invalid")
		} else {
			assert.NotNil(t, report)
			// Should generate report with corrected period or empty data
		}
	})
	
	suite.T().Run("ConcurrentReportGeneration", func(t *testing.T) {
		reporter := NewComplianceReporter(&ComplianceConfig{
			Standards:    []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, CompliancePCIDSS},
			AutoGenerate: true,
		})
		
		period := &ReportPeriod{
			StartDate: time.Now().AddDate(0, -1, 0),
			EndDate:   time.Now(),
		}
		
		// Generate multiple reports concurrently
		var wg sync.WaitGroup
		results := make(chan *ComplianceReport, 10)
		errors := make(chan error, 10)
		
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				var report *ComplianceReport
				var err error
				
				switch id % 3 {
				case 0:
					report, err = reporter.GenerateSOC2Report(suite.ctx, period)
				case 1:
					report, err = reporter.GenerateISO27001Report(suite.ctx, period)
				case 2:
					report, err = reporter.GeneratePCIDSSReport(suite.ctx, period)
				}
				
				if err != nil {
					errors <- err
				} else {
					results <- report
				}
			}(i)
		}
		
		wg.Wait()
		close(results)
		close(errors)
		
		// Collect results
		var successCount, errorCount int
		for report := range results {
			if report != nil {
				successCount++
				assert.NotEmpty(t, report.ID)
				assert.NotEmpty(t, report.Controls)
			}
		}
		
		for err := range errors {
			if err != nil {
				errorCount++
			}
		}
		
		// Should handle concurrent access gracefully
		assert.True(t, successCount > 0, "At least some reports should succeed")
		// Some errors are acceptable under high concurrency
	})
}

func (suite *ChaosTestSuite) TestPenetrationTesterChaos() {
	// Test penetration tester resilience under adverse conditions
	
	suite.T().Run("TargetUnavailability", func(t *testing.T) {
		tester := NewPenetrationTester(&PenTestConfig{
			TargetHost:    "192.0.2.1", // Unreachable target
			TargetPort:    80,
			TestTimeout:   5 * time.Second,
			MaxConcurrent: 2,
			EnabledTests:  []TestType{TestTypeAuthentication, TestTypeAuthorization},
			SafeMode:      true,
		})
		
		result, err := tester.RunSecurityTests(suite.ctx, tester.config)
		
		// Tester should handle unreachable targets gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "connection")
		} else {
			assert.NotNil(t, result)
			// May complete with limited results
		}
	})
	
	suite.T().Run("FlakyTargetBehavior", func(t *testing.T) {
		// Extract host and port from flaky server URL
		flakyURL := suite.flakyServer.URL
		host := "localhost"
		port := 80
		
		tester := NewPenetrationTester(&PenTestConfig{
			TargetHost:    host,
			TargetPort:    port,
			TestTimeout:   30 * time.Second,
			MaxConcurrent: 3,
			EnabledTests:  []TestType{TestTypeAuthentication, TestTypeRateLimit},
			SafeMode:      true,
		})
		
		// Run multiple test iterations to encounter flaky behavior
		var successCount, errorCount int
		
		for i := 0; i < 5; i++ {
			result, err := tester.RunSecurityTests(suite.ctx, tester.config)
			
			if err != nil {
				errorCount++
			} else if result != nil {
				successCount++
				assert.NotNil(t, result.Summary)
			}
		}
		
		// Should handle flaky behavior gracefully
		assert.True(t, successCount > 0, "At least some tests should succeed")
		// Some failures are expected with flaky targets
	})
	
	suite.T().Run("AttackSimulationFailures", func(t *testing.T) {
		tester := NewPenetrationTester(&PenTestConfig{
			TargetHost:    "localhost",
			TargetPort:    80,
			TestTimeout:   10 * time.Second,
			MaxConcurrent: 2,
			EnabledTests:  []TestType{TestTypeAuthentication},
			SafeMode:      true,
		})
		
		// Create attack scenarios that may fail
		failingAttacks := []*AttackScenario{
			{
				ID:       "chaos-attack-1",
				Name:     "Chaos Attack 1",
				Type:     AttackTypeBruteForce,
				Target:   "nonexistent-endpoint",
				Payload:  "invalid-payload",
				Expected: AttackOutcomeBlocked,
			},
			{
				ID:       "chaos-attack-2",
				Name:     "Chaos Attack 2",
				Type:     AttackTypeSQLInjection,
				Target:   "invalid-target",
				Payload:  "'; DROP TABLE chaos; --",
				Expected: AttackOutcomeBlocked,
			},
		}
		
		for _, attack := range failingAttacks {
			result, err := tester.SimulateAttack(suite.ctx, attack)
			
			// Should handle attack failures gracefully
			if err != nil {
				assert.NotEmpty(t, err.Error())
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, attack.ID, result.ScenarioID)
			}
		}
	})
}

func (suite *ChaosTestSuite) TestZeroTrustValidatorChaos() {
	// Test zero-trust validator resilience under chaotic conditions
	
	suite.T().Run("NetworkPartitioning", func(t *testing.T) {
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			TrustedNetworks:   []string{"192.168.0.0/16", "10.0.0.0/8"},
			MonitoringEnabled: true,
			StrictMode:        false,
		})
		
		// Simulate network partitioning with invalid IPs
		chaoticRequests := []*NetworkRequest{
			{
				ID:            "chaos-request-1",
				SourceIP:      nil, // Invalid IP
				DestinationIP: []byte{192, 168, 1, 1},
				Port:          443,
				Protocol:      "HTTPS",
				Timestamp:     time.Now(),
			},
			{
				ID:            "chaos-request-2",
				SourceIP:      []byte{192, 168, 1, 100},
				DestinationIP: nil, // Invalid IP
				Port:          443,
				Protocol:      "HTTPS",
				Timestamp:     time.Now(),
			},
			{
				ID:            "chaos-request-3",
				SourceIP:      []byte{300, 300, 300, 300}, // Invalid IP values
				DestinationIP: []byte{192, 168, 1, 1},
				Port:          65536, // Invalid port
				Protocol:      "",    // Empty protocol
				Timestamp:     time.Time{}, // Zero timestamp
			},
		}
		
		for _, request := range chaoticRequests {
			decision, err := validator.ValidateNetworkAccess(suite.ctx, request)
			
			// Validator should handle invalid requests gracefully
			if err != nil {
				assert.NotEmpty(t, err.Error())
			} else {
				assert.NotNil(t, decision)
				// Should default to deny for invalid requests
				assert.Equal(t, AccessResultDeny, decision.Decision)
			}
		}
	})
	
	suite.T().Run("DeviceIdentityCorruption", func(t *testing.T) {
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			DeviceFingerprints: []string{"known-device-1", "known-device-2"},
			MonitoringEnabled:  true,
		})
		
		// Test with corrupted device information
		corruptedDevices := []*DeviceInfo{
			{
				ID:          "", // Empty ID
				Fingerprint: "corrupted-fingerprint",
				OS:          strings.Repeat("A", 1000), // Extremely long OS string
				TrustLevel:  TrustLevel("invalid"),     // Invalid trust level
				LastSeen:    time.Time{},               // Zero timestamp
			},
			{
				ID:          "device-with-nil-location",
				Fingerprint: "test-fingerprint",
				Location:    nil, // Nil location
				TrustLevel:  TrustLevelHigh,
				LastSeen:    time.Now().Add(24 * time.Hour), // Future timestamp
			},
		}
		
		for _, device := range corruptedDevices {
			verification, err := validator.VerifyDeviceIdentity(suite.ctx, device)
			
			// Should handle corrupted device data gracefully
			if err != nil {
				assert.NotEmpty(t, err.Error())
			} else {
				assert.NotNil(t, verification)
				// Should have low trust score for corrupted data
				assert.True(t, verification.TrustScore <= 0.5)
			}
		}
	})
	
	suite.T().Run("PolicyEnforcementFailures", func(t *testing.T) {
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			MonitoringEnabled: true,
			StrictMode:        true,
		})
		
		// Create policies with potential issues
		problematicPolicies := []*NetworkPolicy{
			{
				ID:      "empty-policy",
				Name:    "Empty Policy",
				Enabled: true,
				Rules:   []*NetworkRule{}, // No rules
			},
			{
				ID:      "invalid-rule-policy",
				Name:    "Invalid Rule Policy",
				Enabled: true,
				Rules: []*NetworkRule{
					{
						ID:          "invalid-rule",
						Type:        RuleType("invalid"), // Invalid rule type
						Action:      RuleAction("invalid"), // Invalid action
						Source:      nil, // Nil source
						Destination: nil, // Nil destination
					},
				},
			},
		}
		
		for _, policy := range problematicPolicies {
			err := validator.EnforceNetworkPolicies(suite.ctx, []*NetworkPolicy{policy})
			
			// Should handle problematic policies gracefully
			if policy.ID == "empty-policy" {
				// Empty policy should be handled without error
				assert.NoError(t, err)
			} else {
				// Invalid rules should cause errors
				assert.Error(t, err)
			}
		}
	})
}

func (suite *ChaosTestSuite) TestSecurityEventMonitorChaos() {
	// Test security event monitor resilience under chaotic conditions
	
	suite.T().Run("EventFlood", func(t *testing.T) {
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        10, // Small buffer to trigger overflow
			ProcessingWorkers: 1,  // Single worker to create backlog
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		err := monitor.Start(suite.ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Generate flood of events
		var wg sync.WaitGroup
		eventCount := 100
		
		for i := 0; i < eventCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				// Create high-frequency events
				for j := 0; j < 10; j++ {
					event := &SecurityEvent{
						ID:        fmt.Sprintf("flood-event-%d-%d", id, j),
						Type:      EventTypeAuthentication,
						Severity:  SeverityMedium,
						Source:    "chaos_test",
						Action:    "flood_test",
						Result:    EventResultFailure,
						Message:   fmt.Sprintf("Flood event %d-%d", id, j),
						Timestamp: time.Now(),
					}
					
					// Try to trigger response (may fail due to overload)
					monitor.TriggerSecurityResponse(suite.ctx, event)
				}
			}(i)
		}
		
		wg.Wait()
		
		// Monitor should survive event flood
		events, err := monitor.DetectSecurityEvents(suite.ctx)
		assert.NoError(t, err)
		assert.NotNil(t, events)
	})
	
	suite.T().Run("CorruptedEvents", func(t *testing.T) {
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        50,
			ProcessingWorkers: 2,
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		err := monitor.Start(suite.ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Create corrupted events
		corruptedEvents := []*SecurityEvent{
			{
				ID:        "", // Empty ID
				Type:      SecurityEventType("invalid"), // Invalid type
				Severity:  SeverityLevel("invalid"),     // Invalid severity
				Source:    "",                           // Empty source
				Message:   strings.Repeat("X", 10000),   // Extremely long message
				Timestamp: time.Time{},                  // Zero timestamp
			},
			{
				ID:       "nil-context-event",
				Type:     EventTypeAuthentication,
				Severity: SeverityHigh,
				Source:   "chaos_test",
				Context:  nil, // Nil context
				Details:  map[string]interface{}{"key": make(chan int)}, // Unserializable data
			},
		}
		
		for _, event := range corruptedEvents {
			// Should handle corrupted events gracefully
			err := monitor.TriggerSecurityResponse(suite.ctx, event)
			// May error, but shouldn't crash
			if err != nil {
				assert.NotEmpty(t, err.Error())
			}
		}
		
		// Monitor should still function after processing corrupted events
		events, err := monitor.DetectSecurityEvents(suite.ctx)
		assert.NoError(t, err)
		assert.NotNil(t, events)
	})
	
	suite.T().Run("ResponseHandlerFailures", func(t *testing.T) {
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        50,
			ProcessingWorkers: 2,
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		// Register failing response handlers
		monitor.RegisterResponseHandler("always_fail", func(ctx context.Context, event *SecurityEvent) error {
			return errors.New("simulated handler failure")
		})
		
		monitor.RegisterResponseHandler("panic_handler", func(ctx context.Context, event *SecurityEvent) error {
			panic("simulated panic in handler")
		})
		
		err := monitor.Start(suite.ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Create events that will trigger failing handlers
		failingEvent := &SecurityEvent{
			ID:        "failing-event",
			Type:      SecurityEventType("always_fail"),
			Severity:  SeverityHigh,
			Source:    "chaos_test",
			Message:   "Event that triggers failing handler",
			Timestamp: time.Now(),
		}
		
		panicEvent := &SecurityEvent{
			ID:        "panic-event",
			Type:      SecurityEventType("panic_handler"),
			Severity:  SeverityHigh,
			Source:    "chaos_test",
			Message:   "Event that triggers panic handler",
			Timestamp: time.Now(),
		}
		
		// Should handle handler failures gracefully
		err1 := monitor.TriggerSecurityResponse(suite.ctx, failingEvent)
		assert.Error(t, err1) // Expected to fail
		
		err2 := monitor.TriggerSecurityResponse(suite.ctx, panicEvent)
		// Should recover from panic and return error
		assert.Error(t, err2)
		
		// Monitor should still be functional after handler failures
		events, err := monitor.DetectSecurityEvents(suite.ctx)
		assert.NoError(t, err)
		assert.NotNil(t, events)
	})
}

func (suite *ChaosTestSuite) TestAttackSimulatorChaos() {
	// Test attack simulator resilience under chaotic conditions
	
	suite.T().Run("TargetChaos", func(t *testing.T) {
		simulator := NewAttackSimulator(&AttackSimulatorConfig{
			TargetURL:      suite.flakyServer.URL, // Use flaky server
			MaxConcurrency: 5,
			RequestTimeout: 2 * time.Second,
			SafeMode:       true,
			EnabledAttacks: []AttackType{AttackTypeBruteForce, AttackTypeSQLInjection},
			RateLimitDelay: 10 * time.Millisecond,
		})
		
		// Run simulation against flaky target
		result, err := simulator.RunAttackSimulation(suite.ctx)
		
		// Should handle flaky targets gracefully
		if err != nil {
			assert.NotEmpty(t, err.Error())
		} else {
			assert.NotNil(t, result)
			assert.NotNil(t, result.Summary)
			
			// Some scenarios may fail due to target flakiness
			for _, scenario := range result.Scenarios {
				assert.NotEmpty(t, scenario.ID)
				// Status may be completed or failed
			}
		}
	})
	
	suite.T().Run("ConcurrentSimulations", func(t *testing.T) {
		simulator := NewAttackSimulator(&AttackSimulatorConfig{
			TargetURL:      suite.testServer.URL,
			MaxConcurrency: 2,
			RequestTimeout: 5 * time.Second,
			SafeMode:       true,
			EnabledAttacks: []AttackType{AttackTypeBruteForce},
			RateLimitDelay: 50 * time.Millisecond,
		})
		
		// Run multiple simulations concurrently
		var wg sync.WaitGroup
		results := make(chan *AttackSimulationResult, 5)
		errors := make(chan error, 5)
		
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				result, err := simulator.RunAttackSimulation(suite.ctx)
				if err != nil {
					errors <- err
				} else {
					results <- result
				}
			}(i)
		}
		
		wg.Wait()
		close(results)
		close(errors)
		
		// Collect results
		var successCount, errorCount int
		for result := range results {
			if result != nil {
				successCount++
				assert.NotNil(t, result.Summary)
			}
		}
		
		for err := range errors {
			if err != nil {
				errorCount++
			}
		}
		
		// Should handle concurrent simulations
		assert.True(t, successCount > 0, "At least some simulations should succeed")
	})
	
	suite.T().Run("InvalidScenarios", func(t *testing.T) {
		simulator := NewAttackSimulator(&AttackSimulatorConfig{
			TargetURL:      suite.testServer.URL,
			MaxConcurrency: 2,
			SafeMode:       true,
		})
		
		// Create invalid attack scenarios
		invalidScenarios := []*AttackScenario{
			{
				ID:       "", // Empty ID
				Name:     "Invalid Scenario 1",
				Type:     AttackType("invalid"), // Invalid type
				Target:   "",                    // Empty target
				Expected: AttackOutcome("invalid"), // Invalid outcome
			},
			{
				ID:   "nil-parameters",
				Name: "Nil Parameters Scenario",
				Type: AttackTypeBruteForce,
				Parameters: map[string]interface{}{
					"nil_value":    nil,
					"invalid_func": func() {}, // Unserializable function
				},
			},
		}
		
		for _, scenario := range invalidScenarios {
			// Load invalid scenario
			err := simulator.LoadCustomScenario(scenario)
			if err != nil {
				assert.NotEmpty(t, err.Error())
				continue
			}
			
			// Try to execute invalid scenario
			result, err := simulator.ExecuteSpecificAttack(suite.ctx, scenario.ID)
			
			// Should handle invalid scenarios gracefully
			if err != nil {
				assert.NotEmpty(t, err.Error())
			} else if result != nil {
				// May complete with error status
				assert.NotEmpty(t, result.ID)
			}
		}
	})
}

func (suite *ChaosTestSuite) TestIntegratedChaos() {
	// Test integrated chaos scenarios affecting multiple components
	
	suite.T().Run("CascadingFailures", func(t *testing.T) {
		// Initialize multiple components
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   5 * time.Second,
			MaxConcurrent: 2,
			EnabledScans:  []ScanType{ScanTypeVulnerability},
		})
		
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        20,
			ProcessingWorkers: 1,
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			TrustedNetworks:   []string{"192.168.0.0/16"},
			MonitoringEnabled: true,
		})
		
		// Start monitor
		err := monitor.Start(suite.ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Simulate cascading failures
		var wg sync.WaitGroup
		
		// Component 1: Scanner with failing targets
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			scanConfig := &ScanConfig{
				ScanType: ScanTypeVulnerability,
				Targets:  []string{suite.errorServer.URL, "192.0.2.1"},
				Depth:    ScanDepthBasic,
				Timeout:  2 * time.Second,
			}
			
			_, err := scanner.ScanVulnerabilities(suite.ctx, scanConfig)
			// May fail, but shouldn't crash
		}()
		
		// Component 2: Validator with invalid requests
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for i := 0; i < 10; i++ {
				request := &NetworkRequest{
					ID:            fmt.Sprintf("chaos-request-%d", i),
					SourceIP:      []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
					DestinationIP: []byte{192, 168, 1, 1},
					Port:          rand.Intn(65536),
					Protocol:      "CHAOS",
					Timestamp:     time.Now(),
				}
				
				_, err := validator.ValidateNetworkAccess(suite.ctx, request)
				// May fail for invalid requests
			}
		}()
		
		// Component 3: Monitor with event flood
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for i := 0; i < 50; i++ {
				event := &SecurityEvent{
					ID:        fmt.Sprintf("chaos-event-%d", i),
					Type:      EventTypeSecurityViolation,
					Severity:  SeverityLevel([]string{"critical", "high", "medium", "low"}[rand.Intn(4)]),
					Source:    "chaos_test",
					Message:   fmt.Sprintf("Chaos event %d", i),
					Timestamp: time.Now(),
				}
				
				monitor.TriggerSecurityResponse(suite.ctx, event)
			}
		}()
		
		wg.Wait()
		
		// Verify system stability after chaos
		// All components should still be responsive
		
		// Test scanner
		quickScan, err := scanner.ScanConfiguration(suite.ctx)
		assert.NoError(t, err)
		assert.NotNil(t, quickScan)
		
		// Test validator
		testRequest := &NetworkRequest{
			ID:            "post-chaos-test",
			SourceIP:      []byte{192, 168, 1, 100},
			DestinationIP: []byte{192, 168, 1, 1},
			Port:          443,
			Protocol:      "HTTPS",
			Timestamp:     time.Now(),
		}
		
		decision, err := validator.ValidateNetworkAccess(suite.ctx, testRequest)
		assert.NoError(t, err)
		assert.NotNil(t, decision)
		
		// Test monitor
		events, err := monitor.DetectSecurityEvents(suite.ctx)
		assert.NoError(t, err)
		assert.NotNil(t, events)
	})
	
	suite.T().Run("ResourceStarvation", func(t *testing.T) {
		// Test behavior under resource constraints
		
		// Create components with minimal resources
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   1 * time.Second, // Very short timeout
			MaxConcurrent: 1,               // Minimal concurrency
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration, ScanTypeCertificate},
		})
		
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        5,  // Very small buffer
			ProcessingWorkers: 1,  // Single worker
			RetentionPeriod:   1 * time.Minute, // Short retention
			ResponseEnabled:   true,
		})
		
		// Start monitor
		err := monitor.Start(suite.ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Stress test with high load
		var wg sync.WaitGroup
		
		// High-frequency scanning
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				scanConfig := &ScanConfig{
					ScanType: ScanTypeVulnerability,
					Targets:  []string{suite.testServer.URL},
					Depth:    ScanDepthBasic,
					Timeout:  500 * time.Millisecond,
				}
				
				_, err := scanner.ScanVulnerabilities(suite.ctx, scanConfig)
				// May timeout due to resource constraints
			}(i)
		}
		
		// High-frequency event generation
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				for j := 0; j < 20; j++ {
					event := &SecurityEvent{
						ID:        fmt.Sprintf("resource-event-%d-%d", id, j),
						Type:      EventTypeAuthentication,
						Severity:  SeverityMedium,
						Source:    "resource_test",
						Message:   fmt.Sprintf("Resource test event %d-%d", id, j),
						Timestamp: time.Now(),
					}
					
					monitor.TriggerSecurityResponse(suite.ctx, event)
					time.Sleep(10 * time.Millisecond)
				}
			}(i)
		}
		
		wg.Wait()
		
		// System should survive resource starvation
		// Components may have reduced performance but should remain functional
		
		// Verify basic functionality
		configScan, err := scanner.ScanConfiguration(suite.ctx)
		if err != nil {
			// Timeout errors are acceptable under resource constraints
			assert.Contains(t, err.Error(), "timeout")
		} else {
			assert.NotNil(t, configScan)
		}
		
		events, err := monitor.DetectSecurityEvents(suite.ctx)
		assert.NoError(t, err)
		assert.NotNil(t, events)
	})
}

// Run the chaos test suite
func TestChaosTestSuite(t *testing.T) {
	suite.Run(t, new(ChaosTestSuite))
}

// Additional chaos test functions

func TestNetworkChaos(t *testing.T) {
	// Test network-related chaos scenarios
	
	ctx := context.Background()
	
	// Test with various network conditions
	testCases := []struct {
		name        string
		target      string
		expectError bool
	}{
		{"UnreachableHost", "192.0.2.1", true},
		{"InvalidDomain", "invalid.domain.test", true},
		{"LocalhostValid", "127.0.0.1", false},
	}
	
	scanner := NewSecurityScanner(&ScannerConfig{
		ScanTimeout:   5 * time.Second,
		MaxConcurrent: 1,
		EnabledScans:  []ScanType{ScanTypeVulnerability},
	})
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanConfig := &ScanConfig{
				ScanType: ScanTypeVulnerability,
				Targets:  []string{tc.target},
				Depth:    ScanDepthBasic,
				Timeout:  2 * time.Second,
			}
			
			result, err := scanner.ScanVulnerabilities(ctx, scanConfig)
			
			if tc.expectError {
				// Error or partial results are acceptable
				if err != nil {
					assert.NotEmpty(t, err.Error())
				} else {
					assert.NotNil(t, result)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestMemoryPressure(t *testing.T) {
	// Test behavior under memory pressure
	
	ctx := context.Background()
	
	// Create large data structures to simulate memory pressure
	largeData := make([][]byte, 100)
	for i := range largeData {
		largeData[i] = make([]byte, 1024*1024) // 1MB each
	}
	
	// Test components under memory pressure
	scanner := NewSecurityScanner(nil)
	monitor := NewSecurityEventMonitor(nil)
	
	err := monitor.Start(ctx)
	require.NoError(t, err)
	defer monitor.Stop()
	
	// Run operations while memory is under pressure
	scanResult, err := scanner.ScanConfiguration(ctx)
	if err != nil {
		// May fail due to memory constraints
		assert.NotEmpty(t, err.Error())
	} else {
		assert.NotNil(t, scanResult)
	}
	
	events, err := monitor.DetectSecurityEvents(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, events)
	
	// Clean up large data
	largeData = nil
}

func TestTimeoutChaos(t *testing.T) {
	// Test various timeout scenarios
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Test with very short timeouts
	scanner := NewSecurityScanner(&ScannerConfig{
		ScanTimeout:   100 * time.Millisecond, // Very short
		MaxConcurrent: 1,
		EnabledScans:  []ScanType{ScanTypeVulnerability},
	})
	
	scanConfig := &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"httpbin.org"}, // External target that may be slow
		Depth:    ScanDepthBasic,
		Timeout:  50 * time.Millisecond, // Even shorter
	}
	
	result, err := scanner.ScanVulnerabilities(ctx, scanConfig)
	
	// Should handle timeouts gracefully
	if err != nil {
		assert.Contains(t, err.Error(), "timeout")
	} else {
		assert.NotNil(t, result)
	}
}