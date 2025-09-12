package performance

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/keyvault/agent/internal/metrics"
)

// Monitor tracks system performance and provides real-time metrics
type Monitor struct {
	metrics         *metrics.PrometheusMetrics
	requestTimes    []time.Duration
	requestCounts   []int64
	mu              sync.RWMutex
	ticker          *time.Ticker
	stopCh          chan struct{}
	windowSize      time.Duration
	sampleInterval  time.Duration
}

// MonitorConfig contains performance monitor configuration
type MonitorConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	SampleInterval time.Duration `yaml:"sample_interval" json:"sample_interval"`
	WindowSize     time.Duration `yaml:"window_size" json:"window_size"`
	MetricsEnabled bool          `yaml:"metrics_enabled" json:"metrics_enabled"`
}

// NewMonitor creates a new performance monitor
func NewMonitor(config *MonitorConfig, prometheusMetrics *metrics.PrometheusMetrics) *Monitor {
	return &Monitor{
		metrics:        prometheusMetrics,
		requestTimes:   make([]time.Duration, 0),
		requestCounts:  make([]int64, 0),
		windowSize:     config.WindowSize,
		sampleInterval: config.SampleInterval,
		stopCh:         make(chan struct{}),
	}
}

// Start begins performance monitoring
func (m *Monitor) Start(ctx context.Context) error {
	m.ticker = time.NewTicker(m.sampleInterval)
	
	go m.monitorLoop(ctx)
	return nil
}

// Stop stops performance monitoring
func (m *Monitor) Stop() {
	if m.ticker != nil {
		m.ticker.Stop()
	}
	close(m.stopCh)
}

// RecordRequest records a request for performance tracking
func (m *Monitor) RecordRequest(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	
	// Add request time
	m.requestTimes = append(m.requestTimes, duration)
	
	// Clean old entries outside the window
	cutoff := now.Add(-m.windowSize)
	m.cleanOldEntries(cutoff)
}

// GetStats returns current performance statistics
func (m *Monitor) GetStats() *PerformanceStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if len(m.requestTimes) == 0 {
		return &PerformanceStats{
			Timestamp: time.Now(),
		}
	}
	
	// Calculate statistics
	stats := &PerformanceStats{
		Timestamp:       time.Now(),
		RequestCount:    int64(len(m.requestTimes)),
		ThroughputRPS:   m.calculateThroughput(),
		AvgResponseTime: m.calculateAverage(),
		P50ResponseTime: m.calculatePercentile(0.50),
		P95ResponseTime: m.calculatePercentile(0.95),
		P99ResponseTime: m.calculatePercentile(0.99),
		MinResponseTime: m.calculateMin(),
		MaxResponseTime: m.calculateMax(),
	}
	
	// Add system metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	stats.MemoryUsage = int64(memStats.Alloc)
	stats.GoroutineCount = int64(runtime.NumGoroutine())
	
	return stats
}

// monitorLoop runs the monitoring loop
func (m *Monitor) monitorLoop(ctx context.Context) {
	for {
		select {
		case <-m.ticker.C:
			m.updateMetrics()
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// updateMetrics updates Prometheus metrics with current performance data
func (m *Monitor) updateMetrics() {
	if m.metrics == nil {
		return
	}
	
	stats := m.GetStats()
	
	// Update Prometheus metrics
	m.metrics.UpdatePerformanceMetrics(
		stats.ThroughputRPS,
		stats.P95ResponseTime.Seconds(),
		stats.P99ResponseTime.Seconds(),
	)
	
	m.metrics.UpdateSystemMetrics(
		float64(stats.MemoryUsage),
		0, // CPU usage would need additional implementation
		float64(stats.GoroutineCount),
	)
}

// calculateThroughput calculates requests per second
func (m *Monitor) calculateThroughput() float64 {
	if len(m.requestTimes) == 0 {
		return 0
	}
	
	return float64(len(m.requestTimes)) / m.windowSize.Seconds()
}

// calculateAverage calculates average response time
func (m *Monitor) calculateAverage() time.Duration {
	if len(m.requestTimes) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, duration := range m.requestTimes {
		total += duration
	}
	
	return total / time.Duration(len(m.requestTimes))
}

// calculatePercentile calculates the specified percentile
func (m *Monitor) calculatePercentile(percentile float64) time.Duration {
	if len(m.requestTimes) == 0 {
		return 0
	}
	
	// Simple percentile calculation (in production, use a proper algorithm)
	sorted := make([]time.Duration, len(m.requestTimes))
	copy(sorted, m.requestTimes)
	
	// Simple bubble sort for demonstration
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

// calculateMin calculates minimum response time
func (m *Monitor) calculateMin() time.Duration {
	if len(m.requestTimes) == 0 {
		return 0
	}
	
	min := m.requestTimes[0]
	for _, duration := range m.requestTimes[1:] {
		if duration < min {
			min = duration
		}
	}
	
	return min
}

// calculateMax calculates maximum response time
func (m *Monitor) calculateMax() time.Duration {
	if len(m.requestTimes) == 0 {
		return 0
	}
	
	max := m.requestTimes[0]
	for _, duration := range m.requestTimes[1:] {
		if duration > max {
			max = duration
		}
	}
	
	return max
}

// cleanOldEntries removes entries older than the cutoff time
func (m *Monitor) cleanOldEntries(cutoff time.Time) {
	// This is a simplified implementation
	// In production, you'd store timestamps with each entry
	// For now, we'll just limit the slice size
	maxEntries := int(m.windowSize.Seconds() * 1000) // Assume max 1000 RPS
	if len(m.requestTimes) > maxEntries {
		m.requestTimes = m.requestTimes[len(m.requestTimes)-maxEntries:]
	}
}

// PerformanceStats contains performance statistics
type PerformanceStats struct {
	Timestamp       time.Time     `json:"timestamp"`
	RequestCount    int64         `json:"request_count"`
	ThroughputRPS   float64       `json:"throughput_rps"`
	AvgResponseTime time.Duration `json:"avg_response_time"`
	P50ResponseTime time.Duration `json:"p50_response_time"`
	P95ResponseTime time.Duration `json:"p95_response_time"`
	P99ResponseTime time.Duration `json:"p99_response_time"`
	MinResponseTime time.Duration `json:"min_response_time"`
	MaxResponseTime time.Duration `json:"max_response_time"`
	MemoryUsage     int64         `json:"memory_usage"`
	GoroutineCount  int64         `json:"goroutine_count"`
}

// PerformanceMiddleware creates middleware for performance monitoring
func (m *Monitor) PerformanceMiddleware() func(next func()) func() {
	return func(next func()) func() {
		return func() {
			start := time.Now()
			next()
			duration := time.Since(start)
			m.RecordRequest(duration)
		}
	}
}