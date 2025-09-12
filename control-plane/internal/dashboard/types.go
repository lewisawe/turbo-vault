package dashboard

import (
	"context"
	"time"
)

// DashboardService provides unified view of all vault agents
type DashboardService interface {
	// GetOverview returns high-level overview of the system
	GetOverview(ctx context.Context, orgID string) (*SystemOverview, error)
	
	// GetVaultSummary returns summary of all vaults for an organization
	GetVaultSummary(ctx context.Context, orgID string) (*VaultSummary, error)
	
	// GetPerformanceMetrics returns performance metrics dashboard data
	GetPerformanceMetrics(ctx context.Context, orgID string, timeRange string) (*PerformanceMetrics, error)
	
	// GetSecurityDashboard returns security-related dashboard data
	GetSecurityDashboard(ctx context.Context, orgID string) (*SecurityDashboard, error)
	
	// GetAlerts returns active alerts and notifications
	GetAlerts(ctx context.Context, orgID string) (*AlertsDashboard, error)
	
	// GetUsageAnalytics returns usage analytics dashboard
	GetUsageAnalytics(ctx context.Context, orgID string, period string) (*UsageAnalytics, error)
	
	// GetCapacityPlanning returns capacity planning dashboard
	GetCapacityPlanning(ctx context.Context, orgID string) (*CapacityPlanning, error)
	
	// GetComplianceStatus returns compliance status dashboard
	GetComplianceStatus(ctx context.Context, orgID string) (*ComplianceStatus, error)
}

// SystemOverview represents high-level system overview
type SystemOverview struct {
	OrganizationID    string                `json:"organization_id"`
	GeneratedAt       time.Time             `json:"generated_at"`
	TotalVaults       int                   `json:"total_vaults"`
	OnlineVaults      int                   `json:"online_vaults"`
	OfflineVaults     int                   `json:"offline_vaults"`
	DegradedVaults    int                   `json:"degraded_vaults"`
	TotalSecrets      int64                 `json:"total_secrets"`
	TotalUsers        int                   `json:"total_users"`
	ActiveSessions    int                   `json:"active_sessions"`
	SystemHealth      SystemHealthStatus    `json:"system_health"`
	RecentActivity    []ActivitySummary     `json:"recent_activity"`
	CriticalAlerts    int                   `json:"critical_alerts"`
	WarningAlerts     int                   `json:"warning_alerts"`
	StorageUsageGB    float64               `json:"storage_usage_gb"`
	RequestsLast24h   int64                 `json:"requests_last_24h"`
}

// SystemHealthStatus represents overall system health
type SystemHealthStatus struct {
	Status      string  `json:"status"` // healthy, degraded, critical
	Score       float64 `json:"score"`  // 0-100
	Issues      []string `json:"issues"`
	LastChecked time.Time `json:"last_checked"`
}

// ActivitySummary represents recent system activity
type ActivitySummary struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	VaultID     string    `json:"vault_id,omitempty"`
	VaultName   string    `json:"vault_name,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	Username    string    `json:"username,omitempty"`
}

// VaultSummary represents summary of all vaults
type VaultSummary struct {
	OrganizationID string        `json:"organization_id"`
	GeneratedAt    time.Time     `json:"generated_at"`
	Vaults         []VaultStatus `json:"vaults"`
	StatusCounts   StatusCounts  `json:"status_counts"`
	VersionCounts  map[string]int `json:"version_counts"`
	RegionCounts   map[string]int `json:"region_counts"`
}

// VaultStatus represents status of a single vault
type VaultStatus struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Status          string            `json:"status"`
	Health          string            `json:"health"`
	Version         string            `json:"version"`
	LastHeartbeat   time.Time         `json:"last_heartbeat"`
	SecretCount     int64             `json:"secret_count"`
	RequestsPerHour float64           `json:"requests_per_hour"`
	ErrorRate       float64           `json:"error_rate"`
	Latency         float64           `json:"latency"`
	StorageUsageGB  float64           `json:"storage_usage_gb"`
	Tags            map[string]string `json:"tags"`
	Alerts          int               `json:"alerts"`
}

// StatusCounts represents counts by status
type StatusCounts struct {
	Online   int `json:"online"`
	Offline  int `json:"offline"`
	Degraded int `json:"degraded"`
	Unknown  int `json:"unknown"`
}

// PerformanceMetrics represents performance dashboard data
type PerformanceMetrics struct {
	OrganizationID   string                 `json:"organization_id"`
	TimeRange        string                 `json:"time_range"`
	GeneratedAt      time.Time              `json:"generated_at"`
	OverallMetrics   OverallPerformance     `json:"overall_metrics"`
	VaultMetrics     []VaultPerformance     `json:"vault_metrics"`
	TrendData        []PerformanceTrend     `json:"trend_data"`
	TopPerformers    []VaultPerformance     `json:"top_performers"`
	BottomPerformers []VaultPerformance     `json:"bottom_performers"`
	Thresholds       PerformanceThresholds  `json:"thresholds"`
}

// OverallPerformance represents overall system performance
type OverallPerformance struct {
	AverageLatency    float64 `json:"average_latency"`
	P95Latency        float64 `json:"p95_latency"`
	P99Latency        float64 `json:"p99_latency"`
	TotalRequests     int64   `json:"total_requests"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	ErrorRate         float64 `json:"error_rate"`
	Availability      float64 `json:"availability"`
}

// VaultPerformance represents performance metrics for a single vault
type VaultPerformance struct {
	VaultID           string  `json:"vault_id"`
	VaultName         string  `json:"vault_name"`
	AverageLatency    float64 `json:"average_latency"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	ErrorRate         float64 `json:"error_rate"`
	Availability      float64 `json:"availability"`
	HealthScore       float64 `json:"health_score"`
}

// PerformanceTrend represents performance trend data
type PerformanceTrend struct {
	Timestamp         time.Time `json:"timestamp"`
	AverageLatency    float64   `json:"average_latency"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	ErrorRate         float64   `json:"error_rate"`
}

// PerformanceThresholds represents performance alert thresholds
type PerformanceThresholds struct {
	LatencyWarning  float64 `json:"latency_warning"`
	LatencyCritical float64 `json:"latency_critical"`
	ErrorRateWarning float64 `json:"error_rate_warning"`
	ErrorRateCritical float64 `json:"error_rate_critical"`
}

// SecurityDashboard represents security dashboard data
type SecurityDashboard struct {
	OrganizationID     string              `json:"organization_id"`
	GeneratedAt        time.Time           `json:"generated_at"`
	SecurityScore      float64             `json:"security_score"`
	SecurityEvents     []SecurityEvent     `json:"security_events"`
	PolicyViolations   []PolicyViolation   `json:"policy_violations"`
	AccessPatterns     []AccessPattern     `json:"access_patterns"`
	CertificateStatus  []CertificateStatus `json:"certificate_status"`
	ComplianceStatus   ComplianceOverview  `json:"compliance_status"`
	Recommendations    []SecurityRecommendation `json:"recommendations"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	VaultID     string                 `json:"vault_id"`
	VaultName   string                 `json:"vault_name"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	Status      string                 `json:"status"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	ID          string    `json:"id"`
	PolicyName  string    `json:"policy_name"`
	VaultID     string    `json:"vault_id"`
	VaultName   string    `json:"vault_name"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Resolved    bool      `json:"resolved"`
}

// AccessPattern represents access pattern analysis
type AccessPattern struct {
	Pattern     string    `json:"pattern"`
	Count       int       `json:"count"`
	Risk        string    `json:"risk"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// CertificateStatus represents certificate status
type CertificateStatus struct {
	VaultID     string    `json:"vault_id"`
	VaultName   string    `json:"vault_name"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	DaysToExpiry int      `json:"days_to_expiry"`
	Issuer      string    `json:"issuer"`
}

// ComplianceOverview represents compliance status overview
type ComplianceOverview struct {
	OverallScore    float64            `json:"overall_score"`
	Standards       map[string]float64 `json:"standards"`
	LastAssessment  time.Time          `json:"last_assessment"`
	NextAssessment  time.Time          `json:"next_assessment"`
	CriticalIssues  int                `json:"critical_issues"`
	ResolvedIssues  int                `json:"resolved_issues"`
}

// SecurityRecommendation represents a security recommendation
type SecurityRecommendation struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Category    string    `json:"category"`
	Impact      string    `json:"impact"`
	Effort      string    `json:"effort"`
	CreatedAt   time.Time `json:"created_at"`
}

// AlertsDashboard represents alerts dashboard data
type AlertsDashboard struct {
	OrganizationID  string         `json:"organization_id"`
	GeneratedAt     time.Time      `json:"generated_at"`
	ActiveAlerts    []Alert        `json:"active_alerts"`
	RecentAlerts    []Alert        `json:"recent_alerts"`
	AlertSummary    AlertSummary   `json:"alert_summary"`
	AlertTrends     []AlertTrend   `json:"alert_trends"`
	NotificationStatus NotificationStatus `json:"notification_status"`
}

// Alert represents an alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	VaultID     string                 `json:"vault_id"`
	VaultName   string                 `json:"vault_name"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Status      string                 `json:"status"`
	Details     map[string]interface{} `json:"details"`
	Acknowledged bool                  `json:"acknowledged"`
	AcknowledgedBy string              `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time          `json:"acknowledged_at,omitempty"`
}

// AlertSummary represents alert summary statistics
type AlertSummary struct {
	Total        int            `json:"total"`
	Critical     int            `json:"critical"`
	Warning      int            `json:"warning"`
	Info         int            `json:"info"`
	Acknowledged int            `json:"acknowledged"`
	ByType       map[string]int `json:"by_type"`
	ByVault      map[string]int `json:"by_vault"`
}

// AlertTrend represents alert trend data
type AlertTrend struct {
	Timestamp time.Time      `json:"timestamp"`
	Counts    map[string]int `json:"counts"`
}

// NotificationStatus represents notification delivery status
type NotificationStatus struct {
	EmailEnabled     bool      `json:"email_enabled"`
	SlackEnabled     bool      `json:"slack_enabled"`
	WebhookEnabled   bool      `json:"webhook_enabled"`
	LastNotification time.Time `json:"last_notification"`
	FailedDeliveries int       `json:"failed_deliveries"`
}

// UsageAnalytics represents usage analytics dashboard
type UsageAnalytics struct {
	OrganizationID   string              `json:"organization_id"`
	Period           string              `json:"period"`
	GeneratedAt      time.Time           `json:"generated_at"`
	OverallUsage     OverallUsage        `json:"overall_usage"`
	VaultUsage       []VaultUsageMetrics `json:"vault_usage"`
	UserActivity     []UserActivity      `json:"user_activity"`
	APIUsage         []APIUsageMetrics   `json:"api_usage"`
	TrendAnalysis    TrendAnalysis       `json:"trend_analysis"`
	TopSecrets       []SecretUsage       `json:"top_secrets"`
}

// OverallUsage represents overall usage statistics
type OverallUsage struct {
	TotalRequests    int64   `json:"total_requests"`
	UniqueUsers      int     `json:"unique_users"`
	ActiveVaults     int     `json:"active_vaults"`
	SecretsAccessed  int64   `json:"secrets_accessed"`
	DataTransferred  int64   `json:"data_transferred"`
	AverageLatency   float64 `json:"average_latency"`
	PeakRPS          float64 `json:"peak_rps"`
}

// VaultUsageMetrics represents usage metrics for a vault
type VaultUsageMetrics struct {
	VaultID         string  `json:"vault_id"`
	VaultName       string  `json:"vault_name"`
	RequestCount    int64   `json:"request_count"`
	UniqueUsers     int     `json:"unique_users"`
	SecretsAccessed int64   `json:"secrets_accessed"`
	DataTransferred int64   `json:"data_transferred"`
	AverageLatency  float64 `json:"average_latency"`
	ErrorRate       float64 `json:"error_rate"`
}

// UserActivity represents user activity metrics
type UserActivity struct {
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	RequestCount    int64     `json:"request_count"`
	SecretsAccessed int64     `json:"secrets_accessed"`
	LastActivity    time.Time `json:"last_activity"`
	VaultsAccessed  []string  `json:"vaults_accessed"`
}

// APIUsageMetrics represents API usage metrics
type APIUsageMetrics struct {
	Endpoint        string  `json:"endpoint"`
	Method          string  `json:"method"`
	RequestCount    int64   `json:"request_count"`
	AverageLatency  float64 `json:"average_latency"`
	ErrorRate       float64 `json:"error_rate"`
	DataTransferred int64   `json:"data_transferred"`
}

// TrendAnalysis represents trend analysis data
type TrendAnalysis struct {
	RequestTrend    []TrendPoint `json:"request_trend"`
	LatencyTrend    []TrendPoint `json:"latency_trend"`
	ErrorTrend      []TrendPoint `json:"error_trend"`
	UserGrowth      []TrendPoint `json:"user_growth"`
	StorageGrowth   []TrendPoint `json:"storage_growth"`
}

// TrendPoint represents a single trend data point
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// SecretUsage represents secret usage statistics
type SecretUsage struct {
	SecretName   string    `json:"secret_name"`
	VaultID      string    `json:"vault_id"`
	VaultName    string    `json:"vault_name"`
	AccessCount  int64     `json:"access_count"`
	UniqueUsers  int       `json:"unique_users"`
	LastAccessed time.Time `json:"last_accessed"`
}

// CapacityPlanning represents capacity planning dashboard
type CapacityPlanning struct {
	OrganizationID      string                `json:"organization_id"`
	GeneratedAt         time.Time             `json:"generated_at"`
	CurrentCapacity     CurrentCapacity       `json:"current_capacity"`
	CapacityForecasts   []CapacityForecast    `json:"capacity_forecasts"`
	ResourceUtilization ResourceUtilization   `json:"resource_utilization"`
	ScalingRecommendations []ScalingRecommendation `json:"scaling_recommendations"`
	CostAnalysis        CostAnalysis          `json:"cost_analysis"`
}

// CurrentCapacity represents current system capacity
type CurrentCapacity struct {
	TotalVaults       int     `json:"total_vaults"`
	MaxVaults         int     `json:"max_vaults"`
	TotalStorage      int64   `json:"total_storage"`
	MaxStorage        int64   `json:"max_storage"`
	TotalUsers        int     `json:"total_users"`
	MaxUsers          int     `json:"max_users"`
	StorageUtilization float64 `json:"storage_utilization"`
	VaultUtilization  float64 `json:"vault_utilization"`
	UserUtilization   float64 `json:"user_utilization"`
}

// CapacityForecast represents capacity forecast data
type CapacityForecast struct {
	Metric      string    `json:"metric"`
	CurrentValue float64  `json:"current_value"`
	ForecastValue float64 `json:"forecast_value"`
	ForecastDate time.Time `json:"forecast_date"`
	Confidence   float64   `json:"confidence"`
	Trend        string    `json:"trend"`
}

// ResourceUtilization represents resource utilization metrics
type ResourceUtilization struct {
	CPU     UtilizationMetric `json:"cpu"`
	Memory  UtilizationMetric `json:"memory"`
	Storage UtilizationMetric `json:"storage"`
	Network UtilizationMetric `json:"network"`
}

// UtilizationMetric represents utilization for a specific resource
type UtilizationMetric struct {
	Current   float64 `json:"current"`
	Average   float64 `json:"average"`
	Peak      float64 `json:"peak"`
	Threshold float64 `json:"threshold"`
	Status    string  `json:"status"`
}

// ScalingRecommendation represents a scaling recommendation
type ScalingRecommendation struct {
	Type        string    `json:"type"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Reason      string    `json:"reason"`
	Impact      string    `json:"impact"`
	Timeline    string    `json:"timeline"`
	Priority    string    `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
}

// CostAnalysis represents cost analysis data
type CostAnalysis struct {
	CurrentMonthlyCost   float64            `json:"current_monthly_cost"`
	ProjectedMonthlyCost float64            `json:"projected_monthly_cost"`
	CostByResource       map[string]float64 `json:"cost_by_resource"`
	CostTrend            []CostTrendPoint   `json:"cost_trend"`
	OptimizationSavings  float64            `json:"optimization_savings"`
}

// CostTrendPoint represents a cost trend data point
type CostTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Cost      float64   `json:"cost"`
}

// ComplianceStatus represents compliance status dashboard
type ComplianceStatus struct {
	OrganizationID     string                `json:"organization_id"`
	GeneratedAt        time.Time             `json:"generated_at"`
	OverallCompliance  ComplianceScore       `json:"overall_compliance"`
	StandardCompliance []StandardCompliance  `json:"standard_compliance"`
	ComplianceIssues   []ComplianceIssue     `json:"compliance_issues"`
	AuditTrail         []AuditEntry          `json:"audit_trail"`
	Certifications     []Certification       `json:"certifications"`
	RemediationPlan    []RemediationAction   `json:"remediation_plan"`
}

// ComplianceScore represents compliance scoring
type ComplianceScore struct {
	Score           float64   `json:"score"`
	Grade           string    `json:"grade"`
	LastAssessment  time.Time `json:"last_assessment"`
	NextAssessment  time.Time `json:"next_assessment"`
	TotalControls   int       `json:"total_controls"`
	PassingControls int       `json:"passing_controls"`
	FailingControls int       `json:"failing_controls"`
}

// StandardCompliance represents compliance with a specific standard
type StandardCompliance struct {
	Standard        string    `json:"standard"`
	Score           float64   `json:"score"`
	Status          string    `json:"status"`
	LastAssessment  time.Time `json:"last_assessment"`
	RequiredControls int      `json:"required_controls"`
	ImplementedControls int   `json:"implemented_controls"`
	CriticalIssues  int       `json:"critical_issues"`
}

// ComplianceIssue represents a compliance issue
type ComplianceIssue struct {
	ID          string    `json:"id"`
	Standard    string    `json:"standard"`
	Control     string    `json:"control"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	VaultID     string    `json:"vault_id"`
	VaultName   string    `json:"vault_name"`
	DetectedAt  time.Time `json:"detected_at"`
	Status      string    `json:"status"`
	DueDate     time.Time `json:"due_date"`
}

// AuditEntry represents an audit trail entry
type AuditEntry struct {
	ID          string                 `json:"id"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	Result      string                 `json:"result"`
	IPAddress   string                 `json:"ip_address"`
}

// Certification represents a compliance certification
type Certification struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Issuer      string    `json:"issuer"`
	CertificateID string  `json:"certificate_id"`
}

// RemediationAction represents a remediation action
type RemediationAction struct {
	ID          string    `json:"id"`
	IssueID     string    `json:"issue_id"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	AssignedTo  string    `json:"assigned_to"`
	DueDate     time.Time `json:"due_date"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}