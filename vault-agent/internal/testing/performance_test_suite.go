package testing

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Performance test constants
	defaultMaxConcurrency     = 100
	defaultTargetLatencyP95   = 100 * time.Millisecond
	baselineRPS              = 100
	normalConcurrency        = 50
	peakConcurrency          = 100
	minProcessingTime        = 50
	maxProcessingTimeRange   = 100
	percentileMultiplier     = 100
	sleepMicroseconds        = 100
)

// PerformanceTestSuite manages performance testing and benchmarking
type PerformanceTestSuite struct {
	config  *PerformanceTestConfig
	results *PerformanceResults
}

// PerformanceTestConfig contains performance test configuration
type PerformanceTestConfig struct {
	BaseURL           string
	MaxConcurrency    int
	TestDuration      time.Duration
	RampUpDuration    time.Duration
	RampDownDuration  time.Duration
	RequestTimeout    time.Duration
	TargetRPS         int
	TargetLatencyP95  time.Duration
	TargetLatencyP99  time.Duration
	LoadPatterns      []LoadPattern
}

// LoadPattern defines a load testing pattern
type LoadPattern struct {
	Name        string
	Duration    time.Duration
	Concurrency int
	RPS         int
	Pattern     string // constant, ramp, spike, step
}

// PerformanceResults contains performance test results
type PerformanceResults struct {
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalBytes      int64
	AvgRPS          float64
	MaxRPS          float64
	MinRPS          float64
	Latencies       LatencyMetrics
	Throughput      ThroughputMetrics
	ErrorRate       float64
	LoadTests       []LoadTestResult
	Benchmarks      []BenchmarkResult
}

// LatencyMetrics contains latency statistics
type LatencyMetrics struct {
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	P50    time.Duration
	P90    time.Duration
	P95    time.Duration
	P99    time.Duration
	P999   time.Duration
	StdDev time.Duration
}

// ThroughputMetrics contains throughput statistics
type ThroughputMetrics struct {
	RequestsPerSecond float64
	BytesPerSecond    float64
	ConnectionsPerSec float64
}

// LoadTestResult contains results for a load test
type LoadTestResult struct {
	Name            string
	Pattern         LoadPattern
	Duration        time.Duration
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	AvgLatency      time.Duration
	MaxLatency      time.Duration
	MinLatency      time.Duration
	P95Latency      time.Duration
	P99Latency      time.Duration
	RPS             float64
	ErrorRate       float64
	Success         bool
}

// BenchmarkResult contains results for a benchmark test
type BenchmarkResult struct {
	Name           string
	Operations     int64
	Duration       time.Duration
	OpsPerSecond   float64
	AvgOpDuration  time.Duration
	MinOpDuration  time.Duration
	MaxOpDuration  time.Duration
	MemoryUsage    int64
	AllocationsOps int64
}

// NewPerformanceTestSuite creates a new performance test suite
func NewPerformanceTestSuite(config *PerformanceTestConfig) *PerformanceTestSuite {
	if config == nil {
		config = &PerformanceTestConfig{
			BaseURL:           "http://localhost:8080",
			MaxConcurrency:    defaultMaxConcurrency,
			TestDuration:      5 * time.Minute,
			RampUpDuration:    30 * time.Second,
			RampDownDuration:  30 * time.Second,
			RequestTimeout:    10 * time.Second,
			TargetRPS:         1000,
			TargetLatencyP95:  defaultTargetLatencyP95,
			TargetLatencyP99:  200 * time.Millisecond,
		}
	}

	return &PerformanceTestSuite{
		config:  config,
		results: &PerformanceResults{},
	}
}

// RunAllTests executes comprehensive performance tests
func (pts *PerformanceTestSuite) RunAllTests(ctx context.Context) (*PerformanceResults, error) {
	pts.results.StartTime = time.Now()
	defer func() {
		pts.results.EndTime = time.Now()
		pts.results.Duration = pts.results.EndTime.Sub(pts.results.StartTime)
	}()

	// Run load tests
	if err := pts.runLoadTests(ctx); err != nil {
		return nil, fmt.Errorf("load tests failed: %w", err)
	}

	// Run benchmark tests
	if err := pts.runBenchmarkTests(ctx); err != nil {
		return nil, fmt.Errorf("benchmark tests failed: %w", err)
	}

	// Calculate overall metrics
	pts.calculateOverallMetrics()

	return pts.results, nil
}

// runLoadTests executes load testing scenarios
func (pts *PerformanceTestSuite) runLoadTests(ctx context.Context) error {
	loadPatterns := []LoadPattern{
		{Name: "Baseline Load", Duration: 2 * time.Minute, Concurrency: 10, RPS: baselineRPS, Pattern: "constant"},
		{Name: "Normal Load", Duration: 3 * time.Minute, Concurrency: normalConcurrency, RPS: 500, Pattern: "constant"},
		{Name: "Peak Load", Duration: 2 * time.Minute, Concurrency: peakConcurrency, RPS: 1000, Pattern: "constant"},
		{Name: "Spike Load", Duration: 1 * time.Minute, Concurrency: 200, RPS: 2000, Pattern: "spike"},
		{Name: "Ramp Up Load", Duration: 5 * time.Minute, Concurrency: peakConcurrency, RPS: 1000, Pattern: "ramp"},
	}

	for _, pattern := range loadPatterns {
		result, err := pts.executeLoadTest(ctx, pattern)
		if err != nil {
			return fmt.Errorf("load test %s failed: %w", pattern.Name, err)
		}
		pts.results.LoadTests = append(pts.results.LoadTests, *result)
	}

	return nil
}

// executeLoadTest executes a single load test
func (pts *PerformanceTestSuite) executeLoadTest(ctx context.Context, pattern LoadPattern) (*LoadTestResult, error) {
	result := &LoadTestResult{
		Name:    pattern.Name,
		Pattern: pattern,
	}
	startTime := time.Now()

	// Create worker pool
	var wg sync.WaitGroup
	var totalRequests, successRequests, failedRequests int64
	var totalLatency, minLatency, maxLatency int64
	latencies := make([]time.Duration, 0, pattern.RPS*int(pattern.Duration.Seconds()))
	latencyMutex := sync.Mutex{}

	// Initialize min latency to max value
	atomic.StoreInt64(&minLatency, int64(time.Hour))

	// Calculate request interval
	requestInterval := time.Second / time.Duration(pattern.RPS/pattern.Concurrency)

	// Start workers
	for i := 0; i < pattern.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			ticker := time.NewTicker(requestInterval)
			defer ticker.Stop()
			
			endTime := startTime.Add(pattern.Duration)
			
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if time.Now().After(endTime) {
						return
					}
					
					// Execute request
					reqStart := time.Now()
					success := pts.executeRequest(ctx)
					reqDuration := time.Since(reqStart)
					
					atomic.AddInt64(&totalRequests, 1)
					if success {
						atomic.AddInt64(&successRequests, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}
					
					// Update latency metrics
					latencyNs := reqDuration.Nanoseconds()
					atomic.AddInt64(&totalLatency, latencyNs)
					
					// Update min latency
					for {
						current := atomic.LoadInt64(&minLatency)
						if latencyNs >= current || atomic.CompareAndSwapInt64(&minLatency, current, latencyNs) {
							break
						}
					}
					
					// Update max latency
					for {
						current := atomic.LoadInt64(&maxLatency)
						if latencyNs <= current || atomic.CompareAndSwapInt64(&maxLatency, current, latencyNs) {
							break
						}
					}
					
					// Store latency for percentile calculation
					latencyMutex.Lock()
					latencies = append(latencies, reqDuration)
					latencyMutex.Unlock()
				}
			}
		}(i)
	}

	// Wait for all workers to complete
	wg.Wait()

	// Calculate results
	result.Duration = time.Since(startTime)
	result.TotalRequests = atomic.LoadInt64(&totalRequests)
	result.SuccessRequests = atomic.LoadInt64(&successRequests)
	result.FailedRequests = atomic.LoadInt64(&failedRequests)
	
	if result.TotalRequests > 0 {
		result.AvgLatency = time.Duration(atomic.LoadInt64(&totalLatency) / result.TotalRequests)
		result.ErrorRate = float64(result.FailedRequests) / float64(result.TotalRequests) * percentileMultiplier
	}
	
	result.MinLatency = time.Duration(atomic.LoadInt64(&minLatency))
	result.MaxLatency = time.Duration(atomic.LoadInt64(&maxLatency))
	result.RPS = float64(result.TotalRequests) / result.Duration.Seconds()
	
	// Calculate percentiles
	if len(latencies) > 0 {
		result.P95Latency = pts.calculatePercentile(latencies, 95)
		result.P99Latency = pts.calculatePercentile(latencies, 99)
	}
	
	// Determine success based on targets
	result.Success = result.RPS >= float64(pts.config.TargetRPS)*0.8 && 
		result.P95Latency <= pts.config.TargetLatencyP95 &&
		result.ErrorRate < 1.0

	return result, nil
}

// executeRequest executes a single HTTP request
func (pts *PerformanceTestSuite) executeRequest(ctx context.Context) bool {
	// Simulate HTTP request execution
	// In real implementation, this would make actual HTTP requests
	
	// Simulate request processing time
	processingTime := time.Duration(minProcessingTime+rand.Intn(maxProcessingTimeRange)) * time.Millisecond
	time.Sleep(processingTime)
	
	// Simulate 95% success rate
	return rand.Float64() < 0.95
}

// runBenchmarkTests executes benchmark tests
func (pts *PerformanceTestSuite) runBenchmarkTests(ctx context.Context) error {
	benchmarks := []struct {
		name string
		fn   func(context.Context) *BenchmarkResult
	}{
		{"Secret Creation", pts.benchmarkSecretCreation},
		{"Secret Retrieval", pts.benchmarkSecretRetrieval},
		{"Secret Update", pts.benchmarkSecretUpdate},
		{"Secret Deletion", pts.benchmarkSecretDeletion},
		{"Encryption Operations", pts.benchmarkEncryption},
		{"Database Operations", pts.benchmarkDatabase},
		{"Authentication", pts.benchmarkAuthentication},
		{"Policy Evaluation", pts.benchmarkPolicyEvaluation},
	}

	for _, benchmark := range benchmarks {
		result := benchmark.fn(ctx)
		pts.results.Benchmarks = append(pts.results.Benchmarks, *result)
	}

	return nil
}

// benchmarkSecretCreation benchmarks secret creation operations
func (pts *PerformanceTestSuite) benchmarkSecretCreation(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Secret Creation", func() {
		// Simulate secret creation
		time.Sleep(time.Microsecond * 500)
	})
}

// benchmarkSecretRetrieval benchmarks secret retrieval operations
func (pts *PerformanceTestSuite) benchmarkSecretRetrieval(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Secret Retrieval", func() {
		// Simulate secret retrieval
		time.Sleep(time.Microsecond * 200)
	})
}

// benchmarkSecretUpdate benchmarks secret update operations
func (pts *PerformanceTestSuite) benchmarkSecretUpdate(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Secret Update", func() {
		// Simulate secret update
		time.Sleep(time.Microsecond * 600)
	})
}

// benchmarkSecretDeletion benchmarks secret deletion operations
func (pts *PerformanceTestSuite) benchmarkSecretDeletion(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Secret Deletion", func() {
		// Simulate secret deletion
		time.Sleep(time.Microsecond * 300)
	})
}

// benchmarkEncryption benchmarks encryption operations
func (pts *PerformanceTestSuite) benchmarkEncryption(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Encryption Operations", func() {
		// Simulate encryption
		time.Sleep(time.Microsecond * sleepMicroseconds)
	})
}

// benchmarkDatabase benchmarks database operations
func (pts *PerformanceTestSuite) benchmarkDatabase(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Database Operations", func() {
		// Simulate database operation
		time.Sleep(time.Microsecond * 800)
	})
}

// benchmarkAuthentication benchmarks authentication operations
func (pts *PerformanceTestSuite) benchmarkAuthentication(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Authentication", func() {
		// Simulate authentication
		time.Sleep(time.Microsecond * 1000)
	})
}

// benchmarkPolicyEvaluation benchmarks policy evaluation operations
func (pts *PerformanceTestSuite) benchmarkPolicyEvaluation(ctx context.Context) *BenchmarkResult {
	return pts.runBenchmark("Policy Evaluation", func() {
		// Simulate policy evaluation
		time.Sleep(time.Microsecond * 150)
	})
}

// runBenchmark runs a benchmark function
func (pts *PerformanceTestSuite) runBenchmark(name string, fn func()) *BenchmarkResult {
	const iterations = 10000
	const duration = 10 * time.Second
	
	result := &BenchmarkResult{Name: name}
	
	startTime := time.Now()
	endTime := startTime.Add(duration)
	
	var operations int64
	var totalDuration time.Duration
	var minDuration = time.Hour
	var maxDuration time.Duration
	
	for time.Now().Before(endTime) {
		opStart := time.Now()
		fn()
		opDuration := time.Since(opStart)
		
		operations++
		totalDuration += opDuration
		
		if opDuration < minDuration {
			minDuration = opDuration
		}
		if opDuration > maxDuration {
			maxDuration = opDuration
		}
	}
	
	actualDuration := time.Since(startTime)
	
	result.Operations = operations
	result.Duration = actualDuration
	result.OpsPerSecond = float64(operations) / actualDuration.Seconds()
	result.AvgOpDuration = totalDuration / time.Duration(operations)
	result.MinOpDuration = minDuration
	result.MaxOpDuration = maxDuration
	result.MemoryUsage = 1024 * 1024 // Simulate memory usage
	result.AllocationsOps = operations * 2 // Simulate allocations
	
	return result
}

// calculatePercentile calculates the specified percentile from latency data
func (pts *PerformanceTestSuite) calculatePercentile(latencies []time.Duration, percentile float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	
	// Sort latencies (simplified - in real implementation would use more efficient algorithm)
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	
	// Simple bubble sort for demonstration
	for i := 0; i < len(sorted); i++ {
		for j := 0; j < len(sorted)-1-i; j++ {
			if sorted[j] > sorted[j+1] {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}
	
	index := int(float64(len(sorted)) * percentile / percentileMultiplier)
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	
	return sorted[index]
}

// calculateOverallMetrics calculates overall performance metrics
func (pts *PerformanceTestSuite) calculateOverallMetrics() {
	var totalRequests, successRequests, failedRequests int64
	var totalLatency time.Duration
	var minLatency = time.Hour
	var maxLatency time.Duration
	var totalRPS float64
	
	for _, test := range pts.results.LoadTests {
		totalRequests += test.TotalRequests
		successRequests += test.SuccessRequests
		failedRequests += test.FailedRequests
		totalLatency += test.AvgLatency
		totalRPS += test.RPS
		
		if test.MinLatency < minLatency {
			minLatency = test.MinLatency
		}
		if test.MaxLatency > maxLatency {
			maxLatency = test.MaxLatency
		}
	}
	
	pts.results.TotalRequests = totalRequests
	pts.results.SuccessRequests = successRequests
	pts.results.FailedRequests = failedRequests
	
	if len(pts.results.LoadTests) > 0 {
		pts.results.AvgRPS = totalRPS / float64(len(pts.results.LoadTests))
		pts.results.Latencies.Min = minLatency
		pts.results.Latencies.Max = maxLatency
		pts.results.Latencies.Mean = totalLatency / time.Duration(len(pts.results.LoadTests))
	}
	
	if totalRequests > 0 {
		pts.results.ErrorRate = float64(failedRequests) / float64(totalRequests) * percentileMultiplier
	}
	
	pts.results.Throughput.RequestsPerSecond = pts.results.AvgRPS
	pts.results.Throughput.BytesPerSecond = pts.results.AvgRPS * 1024 // Assume 1KB per request
}

// GeneratePerformanceReport generates comprehensive performance report
func (pts *PerformanceTestSuite) GeneratePerformanceReport() *PerformanceTestReport {
	return &PerformanceTestReport{
		Summary: PerformanceTestSummary{
			Duration:        pts.results.Duration,
			TotalRequests:   pts.results.TotalRequests,
			SuccessRequests: pts.results.SuccessRequests,
			FailedRequests:  pts.results.FailedRequests,
			AvgRPS:          pts.results.AvgRPS,
			ErrorRate:       pts.results.ErrorRate,
			TargetsMet:      pts.evaluateTargets(),
		},
		LoadTests:  pts.results.LoadTests,
		Benchmarks: pts.results.Benchmarks,
		Metrics:    pts.results,
		Timestamp:  time.Now(),
	}
}

// evaluateTargets evaluates if performance targets were met
func (pts *PerformanceTestSuite) evaluateTargets() bool {
	return pts.results.AvgRPS >= float64(pts.config.TargetRPS)*0.8 &&
		pts.results.Latencies.P95 <= pts.config.TargetLatencyP95 &&
		pts.results.ErrorRate < 1.0
}

// PerformanceTestReport contains comprehensive performance test report
type PerformanceTestReport struct {
	Summary    PerformanceTestSummary `json:"summary"`
	LoadTests  []LoadTestResult       `json:"load_tests"`
	Benchmarks []BenchmarkResult      `json:"benchmarks"`
	Metrics    *PerformanceResults    `json:"metrics"`
	Timestamp  time.Time              `json:"timestamp"`
}

// PerformanceTestSummary contains performance test summary
type PerformanceTestSummary struct {
	Duration        time.Duration `json:"duration"`
	TotalRequests   int64         `json:"total_requests"`
	SuccessRequests int64         `json:"success_requests"`
	FailedRequests  int64         `json:"failed_requests"`
	AvgRPS          float64       `json:"avg_rps"`
	ErrorRate       float64       `json:"error_rate"`
	TargetsMet      bool          `json:"targets_met"`
}

// Simple random number generator for simulation
var rand = struct {
	seed int64
}{seed: time.Now().UnixNano()}

func (r *struct{ seed int64 }) Intn(n int) int {
	r.seed = r.seed*1103515245 + 12345
	return int((r.seed / 65536) % int64(n))
}

func (r *struct{ seed int64 }) Float64() float64 {
	r.seed = r.seed*1103515245 + 12345
	return float64((r.seed/65536)%1000000) / 1000000.0
}
