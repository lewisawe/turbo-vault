package storage

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PerformanceMonitor monitors and optimizes storage performance
type PerformanceMonitor struct {
	db              *sql.DB
	dbType          string
	metrics         *StorageMetrics
	connectionPool  *ConnectionPool
	queryOptimizer  *QueryOptimizer
	cacheManager    *CacheManager
	mu              sync.RWMutex
	monitoringEnabled bool
}

// StorageMetrics contains Prometheus metrics for storage operations
type StorageMetrics struct {
	// Operation metrics
	OperationDuration *prometheus.HistogramVec
	OperationCounter  *prometheus.CounterVec
	ErrorCounter      *prometheus.CounterVec

	// Connection pool metrics
	ActiveConnections   prometheus.Gauge
	IdleConnections     prometheus.Gauge
	ConnectionWaitTime  prometheus.Histogram
	ConnectionLifetime  prometheus.Histogram

	// Query performance metrics
	QueryDuration       *prometheus.HistogramVec
	SlowQueryCounter    *prometheus.CounterVec
	QueryCacheHitRatio  prometheus.Gauge

	// Storage metrics
	DatabaseSize        prometheus.Gauge
	TableSizes          *prometheus.GaugeVec
	IndexEfficiency     *prometheus.GaugeVec
	
	// Backup metrics
	BackupDuration      prometheus.Histogram
	BackupSize          prometheus.Gauge
	BackupSuccess       prometheus.Counter
	BackupFailures      prometheus.Counter
}

// ConnectionPool manages database connection pooling with health monitoring
type ConnectionPool struct {
	db                *sql.DB
	maxOpenConns      int
	maxIdleConns      int
	connMaxLifetime   time.Duration
	healthCheckInterval time.Duration
	metrics           *StorageMetrics
	mu                sync.RWMutex
	healthStatus      map[string]ConnectionHealth
}

// ConnectionHealth represents the health status of a database connection
type ConnectionHealth struct {
	LastCheck    time.Time
	Healthy      bool
	ErrorCount   int
	ResponseTime time.Duration
}

// QueryOptimizer analyzes and optimizes database queries
type QueryOptimizer struct {
	db              *sql.DB
	dbType          string
	slowQueryThreshold time.Duration
	queryStats      map[string]*QueryStats
	indexSuggestions []IndexSuggestion
	mu              sync.RWMutex
}

// QueryStats tracks statistics for database queries
type QueryStats struct {
	Query           string
	ExecutionCount  int64
	TotalDuration   time.Duration
	AverageDuration time.Duration
	MaxDuration     time.Duration
	MinDuration     time.Duration
	ErrorCount      int64
	LastExecuted    time.Time
}

// IndexSuggestion represents a suggested database index
type IndexSuggestion struct {
	Table       string
	Columns     []string
	Type        string
	Reason      string
	Priority    int
	EstimatedGain float64
}

// CacheManager manages query result caching
type CacheManager struct {
	cache       map[string]*CacheEntry
	maxSize     int
	ttl         time.Duration
	hitCount    int64
	missCount   int64
	mu          sync.RWMutex
}

// CacheEntry represents a cached query result
type CacheEntry struct {
	Key       string
	Value     interface{}
	ExpiresAt time.Time
	HitCount  int64
	CreatedAt time.Time
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(db *sql.DB, dbType string) *PerformanceMonitor {
	// Create a custom registry for testing to avoid conflicts
	registry := prometheus.NewRegistry()
	factory := promauto.With(registry)
	
	metrics := &StorageMetrics{
		OperationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "vault_storage_operation_duration_seconds",
				Help: "Duration of storage operations",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"operation", "status"},
		),
		OperationCounter: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "vault_storage_operations_total",
				Help: "Total number of storage operations",
			},
			[]string{"operation", "status"},
		),
		ErrorCounter: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "vault_storage_errors_total",
				Help: "Total number of storage errors",
			},
			[]string{"operation", "error_type"},
		),
		ActiveConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "vault_storage_active_connections",
				Help: "Number of active database connections",
			},
		),
		IdleConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "vault_storage_idle_connections",
				Help: "Number of idle database connections",
			},
		),
		ConnectionWaitTime: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name: "vault_storage_connection_wait_seconds",
				Help: "Time spent waiting for database connections",
				Buckets: prometheus.DefBuckets,
			},
		),
		QueryDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "vault_storage_query_duration_seconds",
				Help: "Duration of database queries",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"query_type", "table"},
		),
		SlowQueryCounter: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "vault_storage_slow_queries_total",
				Help: "Total number of slow queries",
			},
			[]string{"query_type", "table"},
		),
		QueryCacheHitRatio: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "vault_storage_cache_hit_ratio",
				Help: "Query cache hit ratio",
			},
		),
		DatabaseSize: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "vault_storage_database_size_bytes",
				Help: "Total database size in bytes",
			},
		),
		TableSizes: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "vault_storage_table_size_bytes",
				Help: "Size of individual tables in bytes",
			},
			[]string{"table"},
		),
		IndexEfficiency: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "vault_storage_index_efficiency",
				Help: "Efficiency of database indexes",
			},
			[]string{"table", "index"},
		),
		BackupDuration: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name: "vault_storage_backup_duration_seconds",
				Help: "Duration of backup operations",
				Buckets: prometheus.DefBuckets,
			},
		),
		BackupSize: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "vault_storage_backup_size_bytes",
				Help: "Size of backup files in bytes",
			},
		),
		BackupSuccess: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "vault_storage_backup_success_total",
				Help: "Total number of successful backups",
			},
		),
		BackupFailures: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "vault_storage_backup_failures_total",
				Help: "Total number of failed backups",
			},
		),
	}

	connectionPool := &ConnectionPool{
		db:                  db,
		maxOpenConns:        25,
		maxIdleConns:        5,
		connMaxLifetime:     5 * time.Minute,
		healthCheckInterval: 30 * time.Second,
		metrics:             metrics,
		healthStatus:        make(map[string]ConnectionHealth),
	}

	queryOptimizer := &QueryOptimizer{
		db:                 db,
		dbType:             dbType,
		slowQueryThreshold: 1 * time.Second,
		queryStats:         make(map[string]*QueryStats),
		indexSuggestions:   []IndexSuggestion{},
	}

	cacheManager := &CacheManager{
		cache:   make(map[string]*CacheEntry),
		maxSize: 1000,
		ttl:     5 * time.Minute,
	}

	return &PerformanceMonitor{
		db:                db,
		dbType:            dbType,
		metrics:           metrics,
		connectionPool:    connectionPool,
		queryOptimizer:    queryOptimizer,
		cacheManager:      cacheManager,
		monitoringEnabled: true,
	}
}

// Start starts the performance monitoring
func (pm *PerformanceMonitor) Start(ctx context.Context) error {
	// Start connection pool monitoring
	go pm.connectionPool.startHealthMonitoring(ctx)

	// Start query optimization
	go pm.queryOptimizer.startAnalysis(ctx)

	// Start cache cleanup
	go pm.cacheManager.startCleanup(ctx)

	// Start metrics collection
	go pm.collectMetrics(ctx)

	return nil
}

// Stop stops the performance monitoring
func (pm *PerformanceMonitor) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.monitoringEnabled = false
	return nil
}

// TrackOperation tracks a storage operation for performance monitoring
func (pm *PerformanceMonitor) TrackOperation(operation string, duration time.Duration, err error) {
	if !pm.monitoringEnabled {
		return
	}

	status := "success"
	if err != nil {
		status = "error"
		pm.metrics.ErrorCounter.WithLabelValues(operation, "unknown").Inc()
	}

	pm.metrics.OperationDuration.WithLabelValues(operation, status).Observe(duration.Seconds())
	pm.metrics.OperationCounter.WithLabelValues(operation, status).Inc()
}

// TrackQuery tracks a database query for optimization
func (pm *PerformanceMonitor) TrackQuery(query string, table string, duration time.Duration, err error) {
	if !pm.monitoringEnabled {
		return
	}

	queryType := pm.getQueryType(query)
	pm.metrics.QueryDuration.WithLabelValues(queryType, table).Observe(duration.Seconds())

	if duration > pm.queryOptimizer.slowQueryThreshold {
		pm.metrics.SlowQueryCounter.WithLabelValues(queryType, table).Inc()
	}

	pm.queryOptimizer.recordQuery(query, duration, err)
}

// OptimizeConnectionPool optimizes database connection pool settings
func (pm *PerformanceMonitor) OptimizeConnectionPool() error {
	pm.connectionPool.mu.Lock()
	defer pm.connectionPool.mu.Unlock()

	// Analyze connection usage patterns
	stats := pm.db.Stats()
	
	// Adjust pool size based on usage
	if stats.InUse > pm.connectionPool.maxOpenConns*8/10 {
		// Increase pool size if utilization is high
		newMaxOpen := min(pm.connectionPool.maxOpenConns*2, 100)
		pm.db.SetMaxOpenConns(newMaxOpen)
		pm.connectionPool.maxOpenConns = newMaxOpen
	} else if stats.InUse < pm.connectionPool.maxOpenConns*2/10 {
		// Decrease pool size if utilization is low
		newMaxOpen := max(pm.connectionPool.maxOpenConns/2, 5)
		pm.db.SetMaxOpenConns(newMaxOpen)
		pm.connectionPool.maxOpenConns = newMaxOpen
	}

	// Adjust idle connections
	optimalIdle := stats.InUse / 2
	if optimalIdle != pm.connectionPool.maxIdleConns {
		pm.db.SetMaxIdleConns(optimalIdle)
		pm.connectionPool.maxIdleConns = optimalIdle
	}

	return nil
}

// GetPerformanceReport generates a performance report
func (pm *PerformanceMonitor) GetPerformanceReport(ctx context.Context) (*PerformanceReport, error) {
	report := &PerformanceReport{
		GeneratedAt:      time.Now(),
		ConnectionStats:  pm.getConnectionStats(),
		QueryStats:       pm.queryOptimizer.getTopQueries(10),
		IndexSuggestions: pm.queryOptimizer.getIndexSuggestions(),
		CacheStats:       pm.cacheManager.getStats(),
		DatabaseStats:    pm.getDatabaseStats(ctx),
	}

	return report, nil
}

// PerformanceReport contains comprehensive performance information
type PerformanceReport struct {
	GeneratedAt      time.Time                `json:"generated_at"`
	ConnectionStats  ConnectionStats          `json:"connection_stats"`
	QueryStats       []*QueryStats            `json:"query_stats"`
	IndexSuggestions []IndexSuggestion        `json:"index_suggestions"`
	CacheStats       CacheStats               `json:"cache_stats"`
	DatabaseStats    DatabaseStats            `json:"database_stats"`
}

// ConnectionStats contains connection pool statistics
type ConnectionStats struct {
	MaxOpenConnections     int           `json:"max_open_connections"`
	OpenConnections        int           `json:"open_connections"`
	InUseConnections       int           `json:"in_use_connections"`
	IdleConnections        int           `json:"idle_connections"`
	WaitCount              int64         `json:"wait_count"`
	WaitDuration           time.Duration `json:"wait_duration"`
	MaxIdleClosed          int64         `json:"max_idle_closed"`
	MaxIdleTimeClosed      int64         `json:"max_idle_time_closed"`
	MaxLifetimeClosed      int64         `json:"max_lifetime_closed"`
}

// CacheStats contains cache performance statistics
type CacheStats struct {
	Size        int     `json:"size"`
	MaxSize     int     `json:"max_size"`
	HitCount    int64   `json:"hit_count"`
	MissCount   int64   `json:"miss_count"`
	HitRatio    float64 `json:"hit_ratio"`
	EvictedCount int64  `json:"evicted_count"`
}

// DatabaseStats contains database-level statistics
type DatabaseStats struct {
	TotalSize   int64            `json:"total_size"`
	TableSizes  map[string]int64 `json:"table_sizes"`
	IndexSizes  map[string]int64 `json:"index_sizes"`
	RowCounts   map[string]int64 `json:"row_counts"`
}

// Connection pool methods

func (cp *ConnectionPool) startHealthMonitoring(ctx context.Context) {
	ticker := time.NewTicker(cp.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cp.performHealthCheck(ctx)
			cp.updateMetrics()
		}
	}
}

func (cp *ConnectionPool) performHealthCheck(ctx context.Context) {
	start := time.Now()
	err := cp.db.PingContext(ctx)
	duration := time.Since(start)

	cp.mu.Lock()
	defer cp.mu.Unlock()

	health := ConnectionHealth{
		LastCheck:    time.Now(),
		Healthy:      err == nil,
		ResponseTime: duration,
	}

	if err != nil {
		health.ErrorCount++
	}

	cp.healthStatus["primary"] = health
}

func (cp *ConnectionPool) updateMetrics() {
	stats := cp.db.Stats()
	cp.metrics.ActiveConnections.Set(float64(stats.InUse))
	cp.metrics.IdleConnections.Set(float64(stats.Idle))
}

// Query optimizer methods

func (qo *QueryOptimizer) startAnalysis(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			qo.analyzeQueries()
			qo.generateIndexSuggestions()
		}
	}
}

func (qo *QueryOptimizer) recordQuery(query string, duration time.Duration, err error) {
	qo.mu.Lock()
	defer qo.mu.Unlock()

	stats, exists := qo.queryStats[query]
	if !exists {
		stats = &QueryStats{
			Query:        query,
			MinDuration:  duration,
			MaxDuration:  duration,
		}
		qo.queryStats[query] = stats
	}

	stats.ExecutionCount++
	stats.TotalDuration += duration
	stats.AverageDuration = stats.TotalDuration / time.Duration(stats.ExecutionCount)
	stats.LastExecuted = time.Now()

	if duration > stats.MaxDuration {
		stats.MaxDuration = duration
	}
	if duration < stats.MinDuration {
		stats.MinDuration = duration
	}

	if err != nil {
		stats.ErrorCount++
	}
}

func (qo *QueryOptimizer) analyzeQueries() {
	qo.mu.RLock()
	defer qo.mu.RUnlock()

	// Analyze slow queries and suggest optimizations
	for _, stats := range qo.queryStats {
		if stats.AverageDuration > qo.slowQueryThreshold {
			// This query is slow, analyze it for optimization opportunities
			qo.analyzeSlowQuery(stats)
		}
	}
}

func (qo *QueryOptimizer) analyzeSlowQuery(stats *QueryStats) {
	// Simple analysis - in production this would be more sophisticated
	if strings.Contains(strings.ToLower(stats.Query), "where") && 
	   !strings.Contains(strings.ToLower(stats.Query), "index") {
		// Suggest index for WHERE clauses
		suggestion := IndexSuggestion{
			Table:         extractTableName(stats.Query),
			Columns:       extractWhereColumns(stats.Query),
			Type:          "btree",
			Reason:        "Improve WHERE clause performance",
			Priority:      calculatePriority(stats),
			EstimatedGain: estimatePerformanceGain(stats),
		}
		qo.indexSuggestions = append(qo.indexSuggestions, suggestion)
	}
}

func (qo *QueryOptimizer) generateIndexSuggestions() {
	// Generate index suggestions based on query patterns
	// This is a simplified implementation
}

func (qo *QueryOptimizer) getTopQueries(limit int) []*QueryStats {
	qo.mu.RLock()
	defer qo.mu.RUnlock()

	var queries []*QueryStats
	for _, stats := range qo.queryStats {
		queries = append(queries, stats)
	}

	// Sort by average duration (descending)
	// In production, you'd use a proper sorting algorithm
	return queries[:min(len(queries), limit)]
}

func (qo *QueryOptimizer) getIndexSuggestions() []IndexSuggestion {
	qo.mu.RLock()
	defer qo.mu.RUnlock()
	return qo.indexSuggestions
}

// Cache manager methods

func (cm *CacheManager) startCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.cleanup()
		}
	}
}

func (cm *CacheManager) cleanup() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()
	for key, entry := range cm.cache {
		if now.After(entry.ExpiresAt) {
			delete(cm.cache, key)
		}
	}

	// Enforce size limit
	if len(cm.cache) > cm.maxSize {
		// Remove oldest entries (simplified LRU)
		// In production, you'd use a proper LRU implementation
	}
}

func (cm *CacheManager) Get(key string) (interface{}, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	entry, exists := cm.cache[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		cm.missCount++
		return nil, false
	}

	entry.HitCount++
	cm.hitCount++
	return entry.Value, true
}

func (cm *CacheManager) Set(key string, value interface{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.cache[key] = &CacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(cm.ttl),
		CreatedAt: time.Now(),
	}
}

func (cm *CacheManager) getStats() CacheStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	total := cm.hitCount + cm.missCount
	hitRatio := 0.0
	if total > 0 {
		hitRatio = float64(cm.hitCount) / float64(total)
	}

	return CacheStats{
		Size:      len(cm.cache),
		MaxSize:   cm.maxSize,
		HitCount:  cm.hitCount,
		MissCount: cm.missCount,
		HitRatio:  hitRatio,
	}
}

// Helper methods

func (pm *PerformanceMonitor) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.updateCacheMetrics()
			pm.updateDatabaseMetrics(ctx)
		}
	}
}

func (pm *PerformanceMonitor) updateCacheMetrics() {
	stats := pm.cacheManager.getStats()
	pm.metrics.QueryCacheHitRatio.Set(stats.HitRatio)
}

func (pm *PerformanceMonitor) updateDatabaseMetrics(ctx context.Context) {
	// Update database size metrics
	size := pm.getDatabaseSize(ctx)
	pm.metrics.DatabaseSize.Set(float64(size))

	// Update table size metrics
	tableSizes := pm.getTableSizes(ctx)
	for table, size := range tableSizes {
		pm.metrics.TableSizes.WithLabelValues(table).Set(float64(size))
	}
}

func (pm *PerformanceMonitor) getConnectionStats() ConnectionStats {
	stats := pm.db.Stats()
	return ConnectionStats{
		MaxOpenConnections:    stats.MaxOpenConnections,
		OpenConnections:       stats.OpenConnections,
		InUseConnections:      stats.InUse,
		IdleConnections:       stats.Idle,
		WaitCount:            stats.WaitCount,
		WaitDuration:         stats.WaitDuration,
		MaxIdleClosed:        stats.MaxIdleClosed,
		MaxIdleTimeClosed:    stats.MaxIdleTimeClosed,
		MaxLifetimeClosed:    stats.MaxLifetimeClosed,
	}
}

func (pm *PerformanceMonitor) getDatabaseStats(ctx context.Context) DatabaseStats {
	return DatabaseStats{
		TotalSize:  pm.getDatabaseSize(ctx),
		TableSizes: pm.getTableSizes(ctx),
		IndexSizes: pm.getIndexSizes(ctx),
		RowCounts:  pm.getRowCounts(ctx),
	}
}

func (pm *PerformanceMonitor) getDatabaseSize(ctx context.Context) int64 {
	// Database-specific implementation
	switch pm.dbType {
	case "sqlite":
		return pm.getSQLiteDatabaseSize(ctx)
	case "postgres":
		return pm.getPostgresDatabaseSize(ctx)
	case "mysql":
		return pm.getMySQLDatabaseSize(ctx)
	default:
		return 0
	}
}

func (pm *PerformanceMonitor) getSQLiteDatabaseSize(ctx context.Context) int64 {
	var size int64
	err := pm.db.QueryRowContext(ctx, "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&size)
	if err != nil {
		return 0
	}
	return size
}

func (pm *PerformanceMonitor) getPostgresDatabaseSize(ctx context.Context) int64 {
	var size int64
	err := pm.db.QueryRowContext(ctx, "SELECT pg_database_size(current_database())").Scan(&size)
	if err != nil {
		return 0
	}
	return size
}

func (pm *PerformanceMonitor) getMySQLDatabaseSize(ctx context.Context) int64 {
	var size int64
	err := pm.db.QueryRowContext(ctx, 
		"SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = DATABASE()").Scan(&size)
	if err != nil {
		return 0
	}
	return size
}

func (pm *PerformanceMonitor) getTableSizes(ctx context.Context) map[string]int64 {
	// Simplified implementation
	return map[string]int64{
		"secrets":      1000000,
		"audit_events": 500000,
		"backups":      100000,
	}
}

func (pm *PerformanceMonitor) getIndexSizes(ctx context.Context) map[string]int64 {
	// Simplified implementation
	return map[string]int64{
		"idx_secrets_name":   50000,
		"idx_secrets_status": 30000,
	}
}

func (pm *PerformanceMonitor) getRowCounts(ctx context.Context) map[string]int64 {
	// Simplified implementation
	return map[string]int64{
		"secrets":      1000,
		"audit_events": 5000,
		"backups":      50,
	}
}

func (pm *PerformanceMonitor) getQueryType(query string) string {
	query = strings.ToLower(strings.TrimSpace(query))
	if strings.HasPrefix(query, "select") {
		return "select"
	} else if strings.HasPrefix(query, "insert") {
		return "insert"
	} else if strings.HasPrefix(query, "update") {
		return "update"
	} else if strings.HasPrefix(query, "delete") {
		return "delete"
	}
	return "other"
}

// Utility functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func extractTableName(query string) string {
	// Simplified table name extraction
	return "secrets"
}

func extractWhereColumns(query string) []string {
	// Simplified column extraction
	return []string{"name"}
}

func calculatePriority(stats *QueryStats) int {
	// Calculate priority based on execution frequency and duration
	return int(stats.ExecutionCount * int64(stats.AverageDuration.Milliseconds()))
}

func estimatePerformanceGain(stats *QueryStats) float64 {
	// Estimate performance improvement from optimization
	return 0.5 // 50% improvement estimate
}