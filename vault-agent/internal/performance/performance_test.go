package performance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/keyvault/agent/internal/cache"
	"github.com/keyvault/agent/internal/metrics"
	"github.com/keyvault/agent/internal/ratelimit"
)

// PerformanceTestSuite contains performance test configuration
type PerformanceTestSuite struct {
	server         *httptest.Server
	router         *gin.Engine
	monitor        *Monitor
	cache          cache.Cache
	rateLimiter    *ratelimit.MultiKeyRateLimiter
	prometheusMetrics *metrics.PrometheusMetrics
}

// setupPerformanceTest sets up the test environment
func setupPerformanceTest(t *testing.T) *PerformanceTestSuite {
	gin.SetMode(gin.TestMode)
	
	// Create Prometheus metrics
	prometheusMetrics := metrics.NewPrometheusMetrics("vault_agent", "test")
	
	// Create performance monitor
	monitorConfig := &MonitorConfig{
		Enabled:        true,
		SampleInterval: time.Second,
		WindowSize:     time.Minute,
		MetricsEnabled: true,
	}
	monitor := NewMonitor(monitorConfig, prometheusMetrics)
	
	// Create cache
	cacheConfig := &cache.CacheConfig{
		Type:    "memory",
		TTL:     time.Minute,
		MaxSize: 1000,
	}
	testCache := cache.NewMemoryCache(cacheConfig)
	
	// Create rate limiter
	rateLimiterConfig := &ratelimit.RateLimiterConfig{
		RequestsPerSecond: 2000, // Allow high throughput for testing
		BurstSize:         500,
		Algorithm:         "token_bucket",
	}
	rateLimiter := ratelimit.NewMultiKeyRateLimiter(rateLimiterConfig)
	
	// Create router with performance middleware
	router := gin.New()
	router.Use(prometheusMetrics.PrometheusMiddleware())
	
	// Add test endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	
	router.GET("/cached/:key", func(c *gin.Context) {
		key := c.Param("key")
		
		// Try cache first
		if value, found := testCache.Get(c.Request.Context(), key); found {
			c.JSON(http.StatusOK, gin.H{"value": value, "cached": true})
			return
		}
		
		// Simulate work
		time.Sleep(time.Millisecond * 10)
		
		// Store in cache
		testCache.Set(c.Request.Context(), key, "test-value", time.Minute)
		
		c.JSON(http.StatusOK, gin.H{"value": "test-value", "cached": false})
	})
	
	router.GET("/ratelimited", func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		if !rateLimiter.Allow(clientIP, 1) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	server := httptest.NewServer(router)
	
	// Start monitor
	monitor.Start(context.Background())
	
	return &PerformanceTestSuite{
		server:            server,
		router:            router,
		monitor:           monitor,
		cache:             testCache,
		rateLimiter:       rateLimiter,
		prometheusMetrics: prometheusMetrics,
	}
}

// teardownPerformanceTest cleans up the test environment
func (pts *PerformanceTestSuite) teardown() {
	pts.server.Close()
	pts.monitor.Stop()
	pts.cache.Close()
	pts.rateLimiter.Close()
}

// TestThroughputRequirement tests that the system can handle 1000+ RPS
func TestThroughputRequirement(t *testing.T) {
	suite := setupPerformanceTest(t)
	defer suite.teardown()
	
	// Test parameters
	targetRPS := 1000
	testDuration := 10 * time.Second
	totalRequests := int(testDuration.Seconds()) * targetRPS
	
	// Channels for coordination
	startCh := make(chan struct{})
	doneCh := make(chan struct{})
	
	// Counters
	var successCount int64
	var errorCount int64
	var responseTimes []time.Duration
	var responseTimesMu sync.Mutex
	
	// Worker function
	worker := func() {
		defer func() { doneCh <- struct{}{} }()
		
		<-startCh // Wait for start signal
		
		client := &http.Client{
			Timeout: time.Second * 5,
		}
		
		for i := 0; i < totalRequests/100; i++ { // Each worker handles 1% of requests
			start := time.Now()
			
			resp, err := client.Get(suite.server.URL + "/health")
			duration := time.Since(start)
			
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt64(&successCount, 1)
				
				responseTimesMu.Lock()
				responseTimes = append(responseTimes, duration)
				responseTimesMu.Unlock()
			} else {
				atomic.AddInt64(&errorCount, 1)
			}
			
			// Rate limiting to achieve target RPS
			time.Sleep(time.Duration(1000000/targetRPS) * time.Microsecond)
		}
	}
	
	// Start workers
	numWorkers := 100
	for i := 0; i < numWorkers; i++ {
		go worker()
	}
	
	// Start the test
	testStart := time.Now()
	close(startCh)
	
	// Wait for all workers to complete
	for i := 0; i < numWorkers; i++ {
		<-doneCh
	}
	
	testEnd := time.Now()
	actualDuration := testEnd.Sub(testStart)
	
	// Calculate results
	actualRPS := float64(successCount) / actualDuration.Seconds()
	
	// Validate throughput requirement
	assert.GreaterOrEqual(t, actualRPS, float64(targetRPS)*0.9, 
		"Actual RPS (%.2f) should be at least 90%% of target (%d)", actualRPS, targetRPS)
	
	// Calculate response time percentiles
	if len(responseTimes) > 0 {
		p95 := calculatePercentile(responseTimes, 0.95)
		p99 := calculatePercentile(responseTimes, 0.99)
		
		t.Logf("Performance Results:")
		t.Logf("  Target RPS: %d", targetRPS)
		t.Logf("  Actual RPS: %.2f", actualRPS)
		t.Logf("  Success Rate: %.2f%%", float64(successCount)/float64(successCount+errorCount)*100)
		t.Logf("  P95 Response Time: %v", p95)
		t.Logf("  P99 Response Time: %v", p99)
		
		// Validate latency requirement (p95 < 100ms)
		assert.Less(t, p95, 100*time.Millisecond, 
			"P95 response time (%v) should be less than 100ms", p95)
	}
}

// TestCachePerformance tests cache performance under load
func TestCachePerformance(t *testing.T) {
	suite := setupPerformanceTest(t)
	defer suite.teardown()
	
	// Test parameters
	numRequests := 10000
	numWorkers := 50
	
	var wg sync.WaitGroup
	var hitCount int64
	var missCount int64
	
	worker := func(workerID int) {
		defer wg.Done()
		
		client := &http.Client{Timeout: time.Second * 5}
		
		for i := 0; i < numRequests/numWorkers; i++ {
			// Use limited set of keys to test cache effectiveness
			key := fmt.Sprintf("key-%d", i%100)
			
			resp, err := client.Get(suite.server.URL + "/cached/" + key)
			require.NoError(t, err)
			resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				// In a real test, you'd parse the response to check if it was cached
				atomic.AddInt64(&hitCount, 1)
			} else {
				atomic.AddInt64(&missCount, 1)
			}
		}
	}
	
	// Start workers
	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	rps := float64(numRequests) / duration.Seconds()
	
	t.Logf("Cache Performance Results:")
	t.Logf("  Requests: %d", numRequests)
	t.Logf("  Duration: %v", duration)
	t.Logf("  RPS: %.2f", rps)
	t.Logf("  Success Rate: %.2f%%", float64(hitCount)/float64(hitCount+missCount)*100)
	
	// Validate cache performance
	assert.Greater(t, rps, 500.0, "Cache-enabled endpoint should handle >500 RPS")
}

// TestRateLimiterPerformance tests rate limiter performance
func TestRateLimiterPerformance(t *testing.T) {
	suite := setupPerformanceTest(t)
	defer suite.teardown()
	
	// Test parameters
	numRequests := 5000
	numWorkers := 20
	
	var wg sync.WaitGroup
	var allowedCount int64
	var blockedCount int64
	
	worker := func() {
		defer wg.Done()
		
		client := &http.Client{Timeout: time.Second * 5}
		
		for i := 0; i < numRequests/numWorkers; i++ {
			resp, err := client.Get(suite.server.URL + "/ratelimited")
			require.NoError(t, err)
			resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt64(&allowedCount, 1)
			} else if resp.StatusCode == http.StatusTooManyRequests {
				atomic.AddInt64(&blockedCount, 1)
			}
		}
	}
	
	// Start workers
	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	t.Logf("Rate Limiter Performance Results:")
	t.Logf("  Total Requests: %d", numRequests)
	t.Logf("  Allowed: %d", allowedCount)
	t.Logf("  Blocked: %d", blockedCount)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Processing Rate: %.2f RPS", float64(numRequests)/duration.Seconds())
	
	// Validate that rate limiter is working (some requests should be blocked)
	assert.Greater(t, blockedCount, int64(0), "Rate limiter should block some requests under high load")
	assert.Greater(t, allowedCount, int64(0), "Rate limiter should allow some requests")
}

// TestMemoryUsage tests memory usage under load
func TestMemoryUsage(t *testing.T) {
	suite := setupPerformanceTest(t)
	defer suite.teardown()
	
	// Get initial memory usage
	initialStats := suite.monitor.GetStats()
	initialMemory := initialStats.MemoryUsage
	
	// Generate load
	numRequests := 1000
	var wg sync.WaitGroup
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			client := &http.Client{Timeout: time.Second * 5}
			resp, err := client.Get(suite.server.URL + "/health")
			if err == nil {
				resp.Body.Close()
			}
		}(i)
	}
	
	wg.Wait()
	
	// Get final memory usage
	finalStats := suite.monitor.GetStats()
	finalMemory := finalStats.MemoryUsage
	
	memoryIncrease := finalMemory - initialMemory
	
	t.Logf("Memory Usage Results:")
	t.Logf("  Initial Memory: %d bytes", initialMemory)
	t.Logf("  Final Memory: %d bytes", finalMemory)
	t.Logf("  Memory Increase: %d bytes", memoryIncrease)
	t.Logf("  Memory per Request: %.2f bytes", float64(memoryIncrease)/float64(numRequests))
	
	// Validate memory usage is reasonable (less than 1MB increase for 1000 requests)
	assert.Less(t, memoryIncrease, int64(1024*1024), 
		"Memory increase should be less than 1MB for %d requests", numRequests)
}

// BenchmarkAPIEndpoint benchmarks API endpoint performance
func BenchmarkAPIEndpoint(b *testing.B) {
	suite := setupPerformanceTest(&testing.T{})
	defer suite.teardown()
	
	client := &http.Client{Timeout: time.Second * 5}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(suite.server.URL + "/health")
			if err != nil {
				b.Error(err)
				continue
			}
			resp.Body.Close()
		}
	})
}

// calculatePercentile calculates the specified percentile from a slice of durations
func calculatePercentile(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	// Simple sort for demonstration (use a proper sorting algorithm in production)
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	
	for i := 0; i < len(sorted); i++ {
		for j := 0; j < len(sorted)-1-i; j++ {
			if sorted[j] > sorted[j+1] {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}
	
	index := int(float64(len(sorted)-1) * percentile)
	return sorted[index]
}