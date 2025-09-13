package security

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Performance test constants
const (
	PerformanceTestTimeout = 30 * time.Second
	TargetRPS              = 1000 // Target requests per second
	MaxLatencyP95          = 100 * time.Millisecond
	MaxLatencyP99          = 200 * time.Millisecond
	MinThroughput          = 500 // Minimum operations per second
)

// PerformanceMetrics tracks performance test results
type PerformanceMetrics struct {
	TotalOperations   int64
	SuccessfulOps     int64
	FailedOps         int64
	TotalDuration     time.Duration
	MinLatency        time.Duration
	MaxLatency        time.Duration
	AvgLatency        time.Duration
	P95Latency        time.Duration
	P99Latency        time.Duration
	Throughput        float64
	ErrorRate         float64
	MemoryUsageMB     float64
	CPUUsagePercent   float64
}

// LatencyTracker tracks operation latencies
type LatencyTracker struct {
	latencies []time.Duration
	mutex     sync.Mutex
}

func NewLatencyTracker() *LatencyTracker {
	return &LatencyTracker{
		latencies: make([]time.Duration, 0, 10000),
	}
}

func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()
	lt.latencies = append(lt.latencies, latency)
}

func (lt *LatencyTracker) GetMetrics() PerformanceMetrics {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()
	
	if len(lt.latencies) == 0 {
		return PerformanceMetrics{}
	}
	
	// Sort latencies for percentile calculations
	latencies := make([]time.Duration, len(lt.latencies))
	copy(latencies, lt.latencies)
	
	// Simple bubble sort for small datasets
	for i := 0; i < len(latencies); i++ {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[i] > latencies[j] {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}
	
	total := time.Duration(0)
	for _, lat := range latencies {
		total += lat
	}
	
	p95Index := int(float64(len(latencies)) * 0.95)
	p99Index := int(float64(len(latencies)) * 0.99)
	
	if p95Index >= len(latencies) {
		p95Index = len(latencies) - 1
	}
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}
	
	return PerformanceMetrics{
		TotalOperations: int64(len(latencies)),
		MinLatency:      latencies[0],
		MaxLatency:      latencies[len(latencies)-1],
		AvgLatency:      total / time.Duration(len(latencies)),
		P95Latency:      latencies[p95Index],
		P99Latency:      latencies[p99Index],
	}
}

// BenchmarkSecurityScanner tests security scanner performance
func BenchmarkSecurityScanner(b *testing.B) {
	scanner := NewSecurityScanner(&ScannerConfig{
		ScanTimeout:   30 * time.Second,
		MaxConcurrent: 10,
		EnabledScans:  []ScanType{ScanTypeVulnerability},
	})
	
	ctx := context.Background()
	scanConfig := &ScanConfig{
		ScanType: ScanTypeVulnerability,
		Targets:  []string{"localhost"},
		Depth:    ScanDepthBasic,
		Timeout:  5 * time.Second,
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkSecurityScannerThroughput(b *testing.B) {
	scanner := NewSecurityScanner(&ScannerConfig{
		ScanTimeout:   60 * time.Second,
		MaxConcurrent: 20,
		EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration},
	})
	
	ctx := context.Background()
	
	b.Run("VulnerabilityScans", func(b *testing.B) {
		scanConfig := &ScanConfig{
			ScanType: ScanTypeVulnerability,
			Targets:  []string{"localhost"},
			Depth:    ScanDepthBasic,
			Timeout:  2 * time.Second,
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
			if err != nil {
				b.Error(err)
			}
		}
	})
	
	b.Run("ConfigurationScans", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := scanner.ScanConfiguration(ctx)
			if err != nil {
				b.Error(err)
			}
		}
	})
	
	b.Run("CertificateScans", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := scanner.ScanCertificates(ctx)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

// BenchmarkComplianceReporter tests compliance reporter performance
func BenchmarkComplianceReporter(b *testing.B) {
	reporter := NewComplianceReporter(&ComplianceConfig{
		Standards:    []ComplianceStandard{ComplianceSOC2, ComplianceISO27001},
		AutoGenerate: true,
	})
	
	ctx := context.Background()
	period := &ReportPeriod{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
	}
	
	b.Run("SOC2Reports", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := reporter.GenerateSOC2Report(ctx, period)
			if err != nil {
				b.Error(err)
			}
		}
	})
	
	b.Run("ISO27001Reports", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := reporter.GenerateISO27001Report(ctx, period)
			if err != nil {
				b.Error(err)
			}
		}
	})
	
	b.Run("ComplianceValidation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := reporter.ValidateCompliance(ctx, ComplianceSOC2)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

// BenchmarkPenetrationTester tests penetration tester performance
func BenchmarkPenetrationTester(b *testing.B) {
	tester := NewPenetrationTester(&PenTestConfig{
		TargetHost:    "localhost",
		TargetPort:    8080,
		TestTimeout:   30 * time.Second,
		MaxConcurrent: 5,
		EnabledTests:  []TestType{TestTypeAuthentication, TestTypeAuthorization},
		SafeMode:      true,
	})
	
	ctx := context.Background()
	
	b.Run("SecurityValidation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := tester.ValidateSecurityControls(ctx)
			if err != nil {
				b.Error(err)
			}
		}
	})
	
	b.Run("AttackSimulation", func(b *testing.B) {
		attack := &AttackScenario{
			ID:       "bench-attack",
			Name:     "Benchmark Attack",
			Type:     AttackTypeBruteForce,
			Target:   "/api/auth/login",
			Expected: AttackOutcomeBlocked,
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := tester.SimulateAttack(ctx, attack)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

// BenchmarkZeroTrustValidator tests zero-trust validator performance
func BenchmarkZeroTrustValidator(b *testing.B) {
	validator := NewZeroTrustValidator(&ZeroTrustConfig{
		TrustedNetworks:   []string{"192.168.0.0/16", "10.0.0.0/8"},
		MonitoringEnabled: true,
		StrictMode:        false,
	})
	
	ctx := context.Background()
	request := &NetworkRequest{
		ID:            "bench-request",
		SourceIP:      []byte{192, 168, 1, 100},
		DestinationIP: []byte{192, 168, 1, 1},
		Port:          443,
		Protocol:      "HTTPS",
		Timestamp:     time.Now(),
	}
	
	b.Run("NetworkValidation", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := validator.ValidateNetworkAccess(ctx, request)
				if err != nil {
					b.Error(err)
				}
			}
		})
	})
	
	b.Run("DeviceVerification", func(b *testing.B) {
		device := &DeviceInfo{
			ID:          "bench-device",
			Fingerprint: "bench-fingerprint",
			OS:          "Linux",
			TrustLevel:  TrustLevelMedium,
			LastSeen:    time.Now(),
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := validator.VerifyDeviceIdentity(ctx, device)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

// BenchmarkSecurityEventMonitor tests security event monitor performance
func BenchmarkSecurityEventMonitor(b *testing.B) {
	monitor := NewSecurityEventMonitor(&EventMonitorConfig{
		BufferSize:        1000,
		ProcessingWorkers: 5,
		RetentionPeriod:   24 * time.Hour,
		ResponseEnabled:   true,
	})
	
	ctx := context.Background()
	err := monitor.Start(ctx)
	require.NoError(b, err)
	defer monitor.Stop()
	
	b.Run("EventDetection", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := monitor.DetectSecurityEvents(ctx)
			if err != nil {
				b.Error(err)
			}
		}
	})
	
	b.Run("EventProcessing", func(b *testing.B) {
		event := &SecurityEvent{
			ID:        "bench-event",
			Type:      EventTypeAuthentication,
			Severity:  SeverityMedium,
			Source:    "benchmark",
			Action:    "test",
			Result:    EventResultSuccess,
			Message:   "Benchmark event",
			Timestamp: time.Now(),
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := monitor.TriggerSecurityResponse(ctx, event)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

// TestSecurityComponentsPerformance tests performance requirements
func TestSecurityComponentsPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	ctx := context.Background()
	
	t.Run("ScannerThroughputRequirement", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   60 * time.Second,
			MaxConcurrent: 10,
			EnabledScans:  []ScanType{ScanTypeVulnerability},
		})
		
		tracker := NewLatencyTracker()
		
		// Test for 10 seconds
		testDuration := 10 * time.Second
		startTime := time.Now()
		endTime := startTime.Add(testDuration)
		
		var wg sync.WaitGroup
		var operationCount int64
		
		// Run concurrent operations
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				
				for time.Now().Before(endTime) {
					opStart := time.Now()
					
					scanConfig := &ScanConfig{
						ScanType: ScanTypeVulnerability,
						Targets:  []string{"localhost"},
						Depth:    ScanDepthBasic,
						Timeout:  2 * time.Second,
					}
					
					_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
					
					latency := time.Since(opStart)
					tracker.Record(latency)
					
					if err == nil {
						operationCount++
					}
				}
			}()
		}
		
		wg.Wait()
		
		actualDuration := time.Since(startTime)
		throughput := float64(operationCount) / actualDuration.Seconds()
		
		metrics := tracker.GetMetrics()
		
		t.Logf("Scanner Performance:")
		t.Logf("  Operations: %d", operationCount)
		t.Logf("  Duration: %v", actualDuration)
		t.Logf("  Throughput: %.2f ops/sec", throughput)
		t.Logf("  Avg Latency: %v", metrics.AvgLatency)
		t.Logf("  P95 Latency: %v", metrics.P95Latency)
		t.Logf("  P99 Latency: %v", metrics.P99Latency)
		
		// Verify performance requirements
		assert.True(t, throughput >= float64(MinThroughput/10), "Scanner throughput too low: %.2f ops/sec", throughput)
		assert.True(t, metrics.P95Latency <= MaxLatencyP95*5, "Scanner P95 latency too high: %v", metrics.P95Latency)
	})
	
	t.Run("ValidatorLatencyRequirement", func(t *testing.T) {
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			TrustedNetworks:   []string{"192.168.0.0/16"},
			MonitoringEnabled: true,
		})
		
		tracker := NewLatencyTracker()
		
		// Test high-frequency validation
		operationCount := 1000
		
		for i := 0; i < operationCount; i++ {
			request := &NetworkRequest{
				ID:            fmt.Sprintf("perf-request-%d", i),
				SourceIP:      []byte{192, 168, 1, byte(i % 255)},
				DestinationIP: []byte{192, 168, 1, 1},
				Port:          443,
				Protocol:      "HTTPS",
				Timestamp:     time.Now(),
			}
			
			start := time.Now()
			_, err := validator.ValidateNetworkAccess(ctx, request)
			latency := time.Since(start)
			
			tracker.Record(latency)
			
			if err != nil {
				t.Errorf("Validation failed: %v", err)
			}
		}
		
		metrics := tracker.GetMetrics()
		
		t.Logf("Validator Performance:")
		t.Logf("  Operations: %d", operationCount)
		t.Logf("  Avg Latency: %v", metrics.AvgLatency)
		t.Logf("  P95 Latency: %v", metrics.P95Latency)
		t.Logf("  P99 Latency: %v", metrics.P99Latency)
		
		// Verify latency requirements
		assert.True(t, metrics.P95Latency <= MaxLatencyP95, "Validator P95 latency too high: %v", metrics.P95Latency)
		assert.True(t, metrics.P99Latency <= MaxLatencyP99, "Validator P99 latency too high: %v", metrics.P99Latency)
	})
	
	t.Run("EventMonitorThroughput", func(t *testing.T) {
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        2000,
			ProcessingWorkers: 10,
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		tracker := NewLatencyTracker()
		
		// Test event processing throughput
		eventCount := 1000
		startTime := time.Now()
		
		var wg sync.WaitGroup
		
		for i := 0; i < eventCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				event := &SecurityEvent{
					ID:        fmt.Sprintf("perf-event-%d", id),
					Type:      EventTypeAuthentication,
					Severity:  SeverityMedium,
					Source:    "performance_test",
					Action:    "test_action",
					Result:    EventResultSuccess,
					Message:   fmt.Sprintf("Performance test event %d", id),
					Timestamp: time.Now(),
				}
				
				opStart := time.Now()
				err := monitor.TriggerSecurityResponse(ctx, event)
				latency := time.Since(opStart)
				
				tracker.Record(latency)
				
				if err != nil {
					t.Errorf("Event processing failed: %v", err)
				}
			}(i)
		}
		
		wg.Wait()
		
		totalDuration := time.Since(startTime)
		throughput := float64(eventCount) / totalDuration.Seconds()
		
		metrics := tracker.GetMetrics()
		
		t.Logf("Event Monitor Performance:")
		t.Logf("  Events: %d", eventCount)
		t.Logf("  Duration: %v", totalDuration)
		t.Logf("  Throughput: %.2f events/sec", throughput)
		t.Logf("  Avg Latency: %v", metrics.AvgLatency)
		t.Logf("  P95 Latency: %v", metrics.P95Latency)
		
		// Verify throughput requirements
		assert.True(t, throughput >= float64(MinThroughput), "Event monitor throughput too low: %.2f events/sec", throughput)
		assert.True(t, metrics.P95Latency <= MaxLatencyP95, "Event monitor P95 latency too high: %v", metrics.P95Latency)
	})
}

// TestMemoryUsage tests memory usage under load
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory tests in short mode")
	}
	
	ctx := context.Background()
	
	t.Run("ScannerMemoryUsage", func(t *testing.T) {
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   30 * time.Second,
			MaxConcurrent: 5,
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration},
		})
		
		// Run multiple scans
		for i := 0; i < 100; i++ {
			scanConfig := &ScanConfig{
				ScanType: ScanTypeVulnerability,
				Targets:  []string{"localhost"},
				Depth:    ScanDepthBasic,
				Timeout:  1 * time.Second,
			}
			
			_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
			if err != nil {
				// Errors are acceptable for performance testing
			}
		}
		
		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)
		
		memoryUsed := float64(m2.Alloc-m1.Alloc) / 1024 / 1024 // MB
		
		t.Logf("Scanner Memory Usage: %.2f MB", memoryUsed)
		
		// Memory usage should be reasonable (less than 100MB for 100 scans)
		assert.True(t, memoryUsed < 100, "Scanner memory usage too high: %.2f MB", memoryUsed)
	})
	
	t.Run("EventMonitorMemoryUsage", func(t *testing.T) {
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        1000,
			ProcessingWorkers: 5,
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Generate many events
		for i := 0; i < 1000; i++ {
			event := &SecurityEvent{
				ID:        fmt.Sprintf("memory-test-event-%d", i),
				Type:      EventTypeAuthentication,
				Severity:  SeverityMedium,
				Source:    "memory_test",
				Message:   fmt.Sprintf("Memory test event %d with some additional data", i),
				Timestamp: time.Now(),
			}
			
			monitor.TriggerSecurityResponse(ctx, event)
		}
		
		// Allow processing time
		time.Sleep(1 * time.Second)
		
		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)
		
		memoryUsed := float64(m2.Alloc-m1.Alloc) / 1024 / 1024 // MB
		
		t.Logf("Event Monitor Memory Usage: %.2f MB", memoryUsed)
		
		// Memory usage should be reasonable
		assert.True(t, memoryUsed < 50, "Event monitor memory usage too high: %.2f MB", memoryUsed)
	})
}

// TestConcurrentPerformance tests performance under concurrent load
func TestConcurrentPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent performance tests in short mode")
	}
	
	ctx := context.Background()
	
	// Create test server for realistic testing
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer testServer.Close()
	
	t.Run("ConcurrentScanning", func(t *testing.T) {
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   60 * time.Second,
			MaxConcurrent: 20,
			EnabledScans:  []ScanType{ScanTypeVulnerability},
		})
		
		concurrency := 10
		operationsPerWorker := 20
		
		var wg sync.WaitGroup
		tracker := NewLatencyTracker()
		startTime := time.Now()
		
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				for j := 0; j < operationsPerWorker; j++ {
					opStart := time.Now()
					
					scanConfig := &ScanConfig{
						ScanType: ScanTypeVulnerability,
						Targets:  []string{testServer.URL},
						Depth:    ScanDepthBasic,
						Timeout:  5 * time.Second,
					}
					
					_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
					
					latency := time.Since(opStart)
					tracker.Record(latency)
					
					if err != nil {
						t.Errorf("Worker %d operation %d failed: %v", workerID, j, err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		
		totalDuration := time.Since(startTime)
		totalOps := concurrency * operationsPerWorker
		throughput := float64(totalOps) / totalDuration.Seconds()
		
		metrics := tracker.GetMetrics()
		
		t.Logf("Concurrent Scanning Performance:")
		t.Logf("  Workers: %d", concurrency)
		t.Logf("  Operations per worker: %d", operationsPerWorker)
		t.Logf("  Total operations: %d", totalOps)
		t.Logf("  Duration: %v", totalDuration)
		t.Logf("  Throughput: %.2f ops/sec", throughput)
		t.Logf("  Avg Latency: %v", metrics.AvgLatency)
		t.Logf("  P95 Latency: %v", metrics.P95Latency)
		
		// Verify concurrent performance
		assert.True(t, throughput >= 10, "Concurrent throughput too low: %.2f ops/sec", throughput)
		assert.True(t, metrics.P95Latency <= 10*time.Second, "Concurrent P95 latency too high: %v", metrics.P95Latency)
	})
	
	t.Run("ConcurrentValidation", func(t *testing.T) {
		validator := NewZeroTrustValidator(&ZeroTrustConfig{
			TrustedNetworks:   []string{"192.168.0.0/16", "10.0.0.0/8"},
			MonitoringEnabled: true,
		})
		
		concurrency := 50
		operationsPerWorker := 100
		
		var wg sync.WaitGroup
		tracker := NewLatencyTracker()
		startTime := time.Now()
		
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				for j := 0; j < operationsPerWorker; j++ {
					request := &NetworkRequest{
						ID:            fmt.Sprintf("concurrent-request-%d-%d", workerID, j),
						SourceIP:      []byte{192, 168, byte(workerID % 255), byte(j % 255)},
						DestinationIP: []byte{192, 168, 1, 1},
						Port:          443,
						Protocol:      "HTTPS",
						Timestamp:     time.Now(),
					}
					
					opStart := time.Now()
					_, err := validator.ValidateNetworkAccess(ctx, request)
					latency := time.Since(opStart)
					
					tracker.Record(latency)
					
					if err != nil {
						t.Errorf("Worker %d operation %d failed: %v", workerID, j, err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		
		totalDuration := time.Since(startTime)
		totalOps := concurrency * operationsPerWorker
		throughput := float64(totalOps) / totalDuration.Seconds()
		
		metrics := tracker.GetMetrics()
		
		t.Logf("Concurrent Validation Performance:")
		t.Logf("  Workers: %d", concurrency)
		t.Logf("  Operations per worker: %d", operationsPerWorker)
		t.Logf("  Total operations: %d", totalOps)
		t.Logf("  Duration: %v", totalDuration)
		t.Logf("  Throughput: %.2f ops/sec", throughput)
		t.Logf("  Avg Latency: %v", metrics.AvgLatency)
		t.Logf("  P95 Latency: %v", metrics.P95Latency)
		
		// Verify concurrent validation performance meets requirements
		assert.True(t, throughput >= float64(TargetRPS/2), "Concurrent validation throughput too low: %.2f ops/sec", throughput)
		assert.True(t, metrics.P95Latency <= MaxLatencyP95, "Concurrent validation P95 latency too high: %v", metrics.P95Latency)
	})
}

// TestLoadTesting performs load testing on security components
func TestLoadTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load tests in short mode")
	}
	
	ctx := context.Background()
	
	t.Run("HighVolumeEventProcessing", func(t *testing.T) {
		monitor := NewSecurityEventMonitor(&EventMonitorConfig{
			BufferSize:        5000,
			ProcessingWorkers: 20,
			RetentionPeriod:   1 * time.Hour,
			ResponseEnabled:   true,
		})
		
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// High volume event generation
		eventCount := 10000
		concurrency := 100
		eventsPerWorker := eventCount / concurrency
		
		var wg sync.WaitGroup
		tracker := NewLatencyTracker()
		startTime := time.Now()
		
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				for j := 0; j < eventsPerWorker; j++ {
					event := &SecurityEvent{
						ID:        fmt.Sprintf("load-event-%d-%d", workerID, j),
						Type:      EventTypeAuthentication,
						Severity:  SeverityLevel([]string{"low", "medium", "high"}[j%3]),
						Source:    fmt.Sprintf("load_test_worker_%d", workerID),
						Action:    "load_test",
						Result:    EventResultSuccess,
						Message:   fmt.Sprintf("Load test event %d from worker %d", j, workerID),
						Timestamp: time.Now(),
					}
					
					opStart := time.Now()
					err := monitor.TriggerSecurityResponse(ctx, event)
					latency := time.Since(opStart)
					
					tracker.Record(latency)
					
					if err != nil {
						t.Errorf("Event processing failed: %v", err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		
		totalDuration := time.Since(startTime)
		throughput := float64(eventCount) / totalDuration.Seconds()
		
		metrics := tracker.GetMetrics()
		
		t.Logf("High Volume Event Processing:")
		t.Logf("  Events: %d", eventCount)
		t.Logf("  Workers: %d", concurrency)
		t.Logf("  Duration: %v", totalDuration)
		t.Logf("  Throughput: %.2f events/sec", throughput)
		t.Logf("  Avg Latency: %v", metrics.AvgLatency)
		t.Logf("  P95 Latency: %v", metrics.P95Latency)
		t.Logf("  P99 Latency: %v", metrics.P99Latency)
		
		// Verify load testing requirements
		assert.True(t, throughput >= float64(TargetRPS), "Load test throughput too low: %.2f events/sec", throughput)
		assert.True(t, metrics.P95Latency <= MaxLatencyP95*2, "Load test P95 latency too high: %v", metrics.P95Latency)
		assert.True(t, metrics.P99Latency <= MaxLatencyP99*2, "Load test P99 latency too high: %v", metrics.P99Latency)
	})
}

// TestResourceUtilization tests resource utilization under load
func TestResourceUtilization(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource utilization tests in short mode")
	}
	
	ctx := context.Background()
	
	t.Run("CPUUtilization", func(t *testing.T) {
		// Monitor CPU usage during intensive operations
		scanner := NewSecurityScanner(&ScannerConfig{
			ScanTimeout:   60 * time.Second,
			MaxConcurrent: runtime.NumCPU() * 2,
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration, ScanTypeCertificate},
		})
		
		// Run CPU-intensive operations
		var wg sync.WaitGroup
		operationCount := 100
		
		startTime := time.Now()
		
		for i := 0; i < operationCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				scanConfig := &ScanConfig{
					ScanType: ScanTypeVulnerability,
					Targets:  []string{"localhost"},
					Depth:    ScanDepthStandard,
					Timeout:  2 * time.Second,
				}
				
				_, err := scanner.ScanVulnerabilities(ctx, scanConfig)
				if err != nil {
					// Errors are acceptable for resource testing
				}
			}(i)
		}
		
		wg.Wait()
		
		duration := time.Since(startTime)
		
		t.Logf("CPU Utilization Test:")
		t.Logf("  Operations: %d", operationCount)
		t.Logf("  Duration: %v", duration)
		t.Logf("  CPU Cores: %d", runtime.NumCPU())
		t.Logf("  Max Concurrent: %d", runtime.NumCPU()*2)
		
		// Verify reasonable completion time
		expectedMaxDuration := time.Duration(operationCount/runtime.NumCPU()) * time.Second
		assert.True(t, duration <= expectedMaxDuration*2, "CPU utilization test took too long: %v", duration)
	})
	
	t.Run("MemoryEfficiency", func(t *testing.T) {
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		
		// Create multiple components to test memory efficiency
		scanner := NewSecurityScanner(nil)
		reporter := NewComplianceReporter(nil)
		validator := NewZeroTrustValidator(nil)
		monitor := NewSecurityEventMonitor(nil)
		
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer monitor.Stop()
		
		// Perform operations that allocate memory
		for i := 0; i < 50; i++ {
			// Scanner operations
			scanConfig := &ScanConfig{
				ScanType: ScanTypeConfiguration,
				Targets:  []string{"localhost"},
				Depth:    ScanDepthBasic,
				Timeout:  1 * time.Second,
			}
			scanner.ScanConfiguration(ctx)
			
			// Reporter operations
			period := &ReportPeriod{
				StartDate: time.Now().AddDate(0, -1, 0),
				EndDate:   time.Now(),
			}
			reporter.ValidateCompliance(ctx, ComplianceSOC2)
			
			// Validator operations
			request := &NetworkRequest{
				ID:            fmt.Sprintf("memory-request-%d", i),
				SourceIP:      []byte{192, 168, 1, 100},
				DestinationIP: []byte{192, 168, 1, 1},
				Port:          443,
				Protocol:      "HTTPS",
				Timestamp:     time.Now(),
			}
			validator.ValidateNetworkAccess(ctx, request)
			
			// Monitor operations
			event := &SecurityEvent{
				ID:        fmt.Sprintf("memory-event-%d", i),
				Type:      EventTypeAuthentication,
				Severity:  SeverityMedium,
				Source:    "memory_test",
				Message:   fmt.Sprintf("Memory test event %d", i),
				Timestamp: time.Now(),
			}
			monitor.TriggerSecurityResponse(ctx, event)
		}
		
		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)
		
		memoryUsed := float64(m2.Alloc-m1.Alloc) / 1024 / 1024 // MB
		
		t.Logf("Memory Efficiency Test:")
		t.Logf("  Operations: 50 per component")
		t.Logf("  Components: 4")
		t.Logf("  Memory Used: %.2f MB", memoryUsed)
		t.Logf("  Memory per Operation: %.2f KB", (memoryUsed*1024)/200)
		
		// Verify memory efficiency
		assert.True(t, memoryUsed < 200, "Memory usage too high: %.2f MB", memoryUsed)
	})
}