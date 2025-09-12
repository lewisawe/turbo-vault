package analytics

import (
	"time"
)

// UsageMetrics represents usage metrics for a vault agent
type UsageMetrics struct {
	VaultID           string    `json:"vault_id"`
	OrganizationID    string    `json:"organization_id"`
	Timestamp         time.Time `json:"timestamp"`
	RequestCount      int64     `json:"request_count"`
	SecretCount       int64     `json:"secret_count"`
	StorageUsageBytes int64     `json:"storage_usage_bytes"`
	ErrorCount        int64     `json:"error_count"`
	AverageLatencyMs  float64   `json:"average_latency_ms"`
	CPUUsagePercent   float64   `json:"cpu_usage_percent"`
	MemoryUsageBytes  int64     `json:"memory_usage_bytes"`
}

// PerformanceMetrics represents performance metrics aggregation
type PerformanceMetrics struct {
	OrganizationID      string    `json:"organization_id"`
	Period              string    `json:"period"` // hourly, daily, weekly, monthly
	StartTime           time.Time `json:"start_time"`
	EndTime             time.Time `json:"end_time"`
	TotalRequests       int64     `json:"total_requests"`
	AverageLatency      float64   `json:"average_latency"`
	P95Latency          float64   `json:"p95_latency"`
	P99Latency          float64   `json:"p99_latency"`
	ErrorRate           float64   `json:"error_rate"`
	ThroughputRPS       float64   `json:"throughput_rps"`
	ActiveVaults        int       `json:"active_vaults"`
	TotalSecrets        int64     `json:"total_secrets"`
	StorageUsageBytes   int64     `json:"storage_usage_bytes"`
}

// CapacityMetrics represents capacity planning metrics
type CapacityMetrics struct {
	OrganizationID        string    `json:"organization_id"`
	Timestamp             time.Time `json:"timestamp"`
	TotalVaults           int       `json:"total_vaults"`
	ActiveVaults          int       `json:"active_vaults"`
	TotalSecrets          int64     `json:"total_secrets"`
	StorageUsageBytes     int64     `json:"storage_usage_bytes"`
	StorageCapacityBytes  int64     `json:"storage_capacity_bytes"`
	StorageUtilization    float64   `json:"storage_utilization"`
	AverageCPUUsage       float64   `json:"average_cpu_usage"`
	AverageMemoryUsage    float64   `json:"average_memory_usage"`
	PeakRequestsPerSecond float64   `json:"peak_requests_per_second"`
	GrowthRate            float64   `json:"growth_rate"`
}

// UsageReport represents a comprehensive usage report
type UsageReport struct {
	OrganizationID   string             `json:"organization_id"`
	ReportPeriod     string             `json:"report_period"`
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
	GeneratedAt      time.Time          `json:"generated_at"`
	Summary          UsageSummary       `json:"summary"`
	VaultMetrics     []VaultUsage       `json:"vault_metrics"`
	PerformanceData  PerformanceMetrics `json:"performance_data"`
	CapacityData     CapacityMetrics    `json:"capacity_data"`
	Recommendations  []string           `json:"recommendations"`
}

// UsageSummary represents a summary of usage across all vaults
type UsageSummary struct {
	TotalVaults       int     `json:"total_vaults"`
	TotalRequests     int64   `json:"total_requests"`
	TotalSecrets      int64   `json:"total_secrets"`
	TotalStorageGB    float64 `json:"total_storage_gb"`
	AverageLatency    float64 `json:"average_latency"`
	OverallErrorRate  float64 `json:"overall_error_rate"`
	UptimePercentage  float64 `json:"uptime_percentage"`
}

// VaultUsage represents usage metrics for a specific vault
type VaultUsage struct {
	VaultID          string  `json:"vault_id"`
	VaultName        string  `json:"vault_name"`
	RequestCount     int64   `json:"request_count"`
	SecretCount      int64   `json:"secret_count"`
	StorageUsageGB   float64 `json:"storage_usage_gb"`
	AverageLatency   float64 `json:"average_latency"`
	ErrorRate        float64 `json:"error_rate"`
	UptimePercentage float64 `json:"uptime_percentage"`
}

// AlertThreshold represents thresholds for generating alerts
type AlertThreshold struct {
	ID               string  `json:"id"`
	OrganizationID   string  `json:"organization_id"`
	MetricType       string  `json:"metric_type"`
	ThresholdValue   float64 `json:"threshold_value"`
	ComparisonType   string  `json:"comparison_type"` // greater_than, less_than, equals
	Enabled          bool    `json:"enabled"`
	NotificationChannels []string `json:"notification_channels"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// MetricsFilter represents filtering options for metrics queries
type MetricsFilter struct {
	OrganizationID string     `json:"organization_id"`
	VaultIDs       []string   `json:"vault_ids"`
	StartTime      *time.Time `json:"start_time"`
	EndTime        *time.Time `json:"end_time"`
	Granularity    string     `json:"granularity"` // minute, hour, day, week, month
	MetricTypes    []string   `json:"metric_types"`
	Limit          int        `json:"limit"`
	Offset         int        `json:"offset"`
}

// TimeSeriesData represents time-series metrics data
type TimeSeriesData struct {
	MetricName string                 `json:"metric_name"`
	VaultID    string                 `json:"vault_id"`
	DataPoints []TimeSeriesDataPoint  `json:"data_points"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// TimeSeriesDataPoint represents a single data point in time series
type TimeSeriesDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// AnalyticsEvent represents an event for analytics tracking
type AnalyticsEvent struct {
	ID             string                 `json:"id"`
	VaultID        string                 `json:"vault_id"`
	OrganizationID string                 `json:"organization_id"`
	EventType      string                 `json:"event_type"`
	EventData      map[string]interface{} `json:"event_data"`
	Timestamp      time.Time              `json:"timestamp"`
	UserID         string                 `json:"user_id,omitempty"`
	SessionID      string                 `json:"session_id,omitempty"`
}

// DashboardData represents data for analytics dashboard
type DashboardData struct {
	OrganizationID    string               `json:"organization_id"`
	GeneratedAt       time.Time            `json:"generated_at"`
	TimeRange         string               `json:"time_range"`
	OverviewMetrics   OverviewMetrics      `json:"overview_metrics"`
	VaultStatuses     []VaultStatusSummary `json:"vault_statuses"`
	PerformanceTrends []TimeSeriesData     `json:"performance_trends"`
	TopVaultsByUsage  []VaultUsage         `json:"top_vaults_by_usage"`
	RecentAlerts      []AlertSummary       `json:"recent_alerts"`
}

// OverviewMetrics represents high-level overview metrics
type OverviewMetrics struct {
	TotalVaults      int     `json:"total_vaults"`
	OnlineVaults     int     `json:"online_vaults"`
	TotalRequests24h int64   `json:"total_requests_24h"`
	AverageLatency   float64 `json:"average_latency"`
	ErrorRate        float64 `json:"error_rate"`
	StorageUsageGB   float64 `json:"storage_usage_gb"`
}

// VaultStatusSummary represents vault status summary
type VaultStatusSummary struct {
	VaultID   string `json:"vault_id"`
	VaultName string `json:"vault_name"`
	Status    string `json:"status"`
	Health    string `json:"health"`
}

// AlertSummary represents alert summary for dashboard
type AlertSummary struct {
	ID        string    `json:"id"`
	VaultID   string    `json:"vault_id"`
	VaultName string    `json:"vault_name"`
	AlertType string    `json:"alert_type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}