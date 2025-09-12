package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusMetrics contains all Prometheus metrics for the vault agent
type PrometheusMetrics struct {
	// Request metrics
	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
	RequestsInFlight  prometheus.Gauge
	
	// Secret metrics
	SecretsTotal      prometheus.Gauge
	SecretOperations  *prometheus.CounterVec
	SecretAccessCount *prometheus.CounterVec
	
	// Cache metrics
	CacheHits         *prometheus.CounterVec
	CacheMisses       *prometheus.CounterVec
	CacheSize         *prometheus.GaugeVec
	CacheEvictions    *prometheus.CounterVec
	
	// Database metrics
	DatabaseConnections     prometheus.Gauge
	DatabaseQueries         *prometheus.CounterVec
	DatabaseQueryDuration   *prometheus.HistogramVec
	
	// System metrics
	MemoryUsage       prometheus.Gauge
	CPUUsage          prometheus.Gauge
	GoroutineCount    prometheus.Gauge
	
	// Error metrics
	ErrorsTotal       *prometheus.CounterVec
	
	// Performance metrics
	ThroughputRPS     prometheus.Gauge
	ResponseTimeP95   prometheus.Gauge
	ResponseTimeP99   prometheus.Gauge
	
	registry *prometheus.Registry
}

// NewPrometheusMetrics creates a new Prometheus metrics instance
func NewPrometheusMetrics(namespace, subsystem string) *PrometheusMetrics {
	registry := prometheus.NewRegistry()
	
	metrics := &PrometheusMetrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		
		RequestsInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "requests_in_flight",
				Help:      "Number of HTTP requests currently being processed",
			},
		),
		
		SecretsTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "secrets_total",
				Help:      "Total number of secrets stored",
			},
		),
		
		SecretOperations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "secret_operations_total",
				Help:      "Total number of secret operations",
			},
			[]string{"operation", "status"},
		),
		
		SecretAccessCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "secret_access_total",
				Help:      "Total number of secret accesses",
			},
			[]string{"secret_name"},
		),
		
		CacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"cache_name", "cache_level"},
		),
		
		CacheMisses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"cache_name", "cache_level"},
		),
		
		CacheSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_size",
				Help:      "Current cache size",
			},
			[]string{"cache_name", "cache_level"},
		),
		
		CacheEvictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_evictions_total",
				Help:      "Total number of cache evictions",
			},
			[]string{"cache_name", "cache_level"},
		),
		
		DatabaseConnections: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "database_connections",
				Help:      "Number of active database connections",
			},
		),
		
		DatabaseQueries: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "database_queries_total",
				Help:      "Total number of database queries",
			},
			[]string{"operation", "status"},
		),
		
		DatabaseQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "database_query_duration_seconds",
				Help:      "Database query duration in seconds",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
			},
			[]string{"operation"},
		),
		
		MemoryUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "memory_usage_bytes",
				Help:      "Current memory usage in bytes",
			},
		),
		
		CPUUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cpu_usage_percent",
				Help:      "Current CPU usage percentage",
			},
		),
		
		GoroutineCount: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "goroutines",
				Help:      "Number of goroutines",
			},
		),
		
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "errors_total",
				Help:      "Total number of errors",
			},
			[]string{"type", "component"},
		),
		
		ThroughputRPS: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "throughput_requests_per_second",
				Help:      "Current throughput in requests per second",
			},
		),
		
		ResponseTimeP95: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "response_time_p95_seconds",
				Help:      "95th percentile response time in seconds",
			},
		),
		
		ResponseTimeP99: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "response_time_p99_seconds",
				Help:      "99th percentile response time in seconds",
			},
		),
		
		registry: registry,
	}
	
	// Register all metrics
	registry.MustRegister(
		metrics.RequestsTotal,
		metrics.RequestDuration,
		metrics.RequestsInFlight,
		metrics.SecretsTotal,
		metrics.SecretOperations,
		metrics.SecretAccessCount,
		metrics.CacheHits,
		metrics.CacheMisses,
		metrics.CacheSize,
		metrics.CacheEvictions,
		metrics.DatabaseConnections,
		metrics.DatabaseQueries,
		metrics.DatabaseQueryDuration,
		metrics.MemoryUsage,
		metrics.CPUUsage,
		metrics.GoroutineCount,
		metrics.ErrorsTotal,
		metrics.ThroughputRPS,
		metrics.ResponseTimeP95,
		metrics.ResponseTimeP99,
	)
	
	return metrics
}

// GetRegistry returns the Prometheus registry
func (m *PrometheusMetrics) GetRegistry() *prometheus.Registry {
	return m.registry
}

// Handler returns the Prometheus HTTP handler
func (m *PrometheusMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RecordRequest records HTTP request metrics
func (m *PrometheusMetrics) RecordRequest(method, endpoint string, statusCode int, duration time.Duration) {
	m.RequestsTotal.WithLabelValues(method, endpoint, strconv.Itoa(statusCode)).Inc()
	m.RequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordSecretOperation records secret operation metrics
func (m *PrometheusMetrics) RecordSecretOperation(operation, status string) {
	m.SecretOperations.WithLabelValues(operation, status).Inc()
}

// RecordSecretAccess records secret access metrics
func (m *PrometheusMetrics) RecordSecretAccess(secretName string) {
	m.SecretAccessCount.WithLabelValues(secretName).Inc()
}

// RecordCacheHit records cache hit metrics
func (m *PrometheusMetrics) RecordCacheHit(cacheName, cacheLevel string) {
	m.CacheHits.WithLabelValues(cacheName, cacheLevel).Inc()
}

// RecordCacheMiss records cache miss metrics
func (m *PrometheusMetrics) RecordCacheMiss(cacheName, cacheLevel string) {
	m.CacheMisses.WithLabelValues(cacheName, cacheLevel).Inc()
}

// UpdateCacheSize updates cache size metrics
func (m *PrometheusMetrics) UpdateCacheSize(cacheName, cacheLevel string, size float64) {
	m.CacheSize.WithLabelValues(cacheName, cacheLevel).Set(size)
}

// RecordCacheEviction records cache eviction metrics
func (m *PrometheusMetrics) RecordCacheEviction(cacheName, cacheLevel string) {
	m.CacheEvictions.WithLabelValues(cacheName, cacheLevel).Inc()
}

// RecordDatabaseQuery records database query metrics
func (m *PrometheusMetrics) RecordDatabaseQuery(operation, status string, duration time.Duration) {
	m.DatabaseQueries.WithLabelValues(operation, status).Inc()
	m.DatabaseQueryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// UpdateDatabaseConnections updates database connection count
func (m *PrometheusMetrics) UpdateDatabaseConnections(count float64) {
	m.DatabaseConnections.Set(count)
}

// UpdateSystemMetrics updates system resource metrics
func (m *PrometheusMetrics) UpdateSystemMetrics(memoryBytes, cpuPercent, goroutines float64) {
	m.MemoryUsage.Set(memoryBytes)
	m.CPUUsage.Set(cpuPercent)
	m.GoroutineCount.Set(goroutines)
}

// RecordError records error metrics
func (m *PrometheusMetrics) RecordError(errorType, component string) {
	m.ErrorsTotal.WithLabelValues(errorType, component).Inc()
}

// UpdatePerformanceMetrics updates performance metrics
func (m *PrometheusMetrics) UpdatePerformanceMetrics(rps, p95, p99 float64) {
	m.ThroughputRPS.Set(rps)
	m.ResponseTimeP95.Set(p95)
	m.ResponseTimeP99.Set(p99)
}

// IncrementRequestsInFlight increments the in-flight requests counter
func (m *PrometheusMetrics) IncrementRequestsInFlight() {
	m.RequestsInFlight.Inc()
}

// DecrementRequestsInFlight decrements the in-flight requests counter
func (m *PrometheusMetrics) DecrementRequestsInFlight() {
	m.RequestsInFlight.Dec()
}

// UpdateSecretsTotal updates the total number of secrets
func (m *PrometheusMetrics) UpdateSecretsTotal(count float64) {
	m.SecretsTotal.Set(count)
}

// PrometheusMiddleware creates a Gin middleware for Prometheus metrics
func (m *PrometheusMetrics) PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		m.IncrementRequestsInFlight()
		
		c.Next()
		
		duration := time.Since(start)
		m.DecrementRequestsInFlight()
		m.RecordRequest(c.Request.Method, c.FullPath(), c.Writer.Status(), duration)
	}
}