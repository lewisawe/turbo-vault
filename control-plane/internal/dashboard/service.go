package dashboard

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Service implements the DashboardService interface
type Service struct {
	vaultRegistry   VaultRegistry
	analyticsService AnalyticsService
	monitoringService MonitoringService
	userService     UserService
}

// NewService creates a new dashboard service
func NewService(
	vaultRegistry VaultRegistry,
	analyticsService AnalyticsService,
	monitoringService MonitoringService,
	userService UserService,
) *Service {
	return &Service{
		vaultRegistry:     vaultRegistry,
		analyticsService:  analyticsService,
		monitoringService: monitoringService,
		userService:       userService,
	}
}

// GetOverview returns high-level overview of the system
func (s *Service) GetOverview(ctx context.Context, orgID string) (*SystemOverview, error) {
	// Get vault summary
	vaultSummary, err := s.GetVaultSummary(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault summary: %w", err)
	}

	// Get user count
	userFilter := &UserFilter{OrganizationID: orgID}
	users, err := s.userService.ListUsers(ctx, userFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get user count: %w", err)
	}

	// Get analytics data
	analyticsData, err := s.analyticsService.GetDashboardData(ctx, orgID, "24h")
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics data: %w", err)
	}

	// Get monitoring stats
	monitoringStats, err := s.monitoringService.GetMonitoringStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get monitoring stats: %w", err)
	}

	// Calculate system health
	systemHealth := s.calculateSystemHealth(vaultSummary, monitoringStats)

	// Get recent activity
	recentActivity := s.getRecentActivity(ctx, orgID, 10)

	// Count total secrets across all vaults
	var totalSecrets int64
	for _, vault := range vaultSummary.Vaults {
		totalSecrets += vault.SecretCount
	}

	overview := &SystemOverview{
		OrganizationID:  orgID,
		GeneratedAt:     time.Now(),
		TotalVaults:     vaultSummary.StatusCounts.Online + vaultSummary.StatusCounts.Offline + vaultSummary.StatusCounts.Degraded + vaultSummary.StatusCounts.Unknown,
		OnlineVaults:    vaultSummary.StatusCounts.Online,
		OfflineVaults:   vaultSummary.StatusCounts.Offline,
		DegradedVaults:  vaultSummary.StatusCounts.Degraded,
		TotalSecrets:    totalSecrets,
		TotalUsers:      users.Total,
		ActiveSessions:  0, // Would be calculated from session service
		SystemHealth:    systemHealth,
		RecentActivity:  recentActivity,
		CriticalAlerts:  monitoringStats.EventsBySeverity["critical"],
		WarningAlerts:   monitoringStats.EventsBySeverity["warning"],
		StorageUsageGB:  analyticsData.OverviewMetrics.StorageUsageGB,
		RequestsLast24h: analyticsData.OverviewMetrics.TotalRequests24h,
	}

	return overview, nil
}

// GetVaultSummary returns summary of all vaults for an organization
func (s *Service) GetVaultSummary(ctx context.Context, orgID string) (*VaultSummary, error) {
	vaults, err := s.vaultRegistry.ListVaults(ctx, &VaultFilter{OrganizationID: orgID})
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}

	summary := &VaultSummary{
		OrganizationID: orgID,
		GeneratedAt:    time.Now(),
		Vaults:         make([]VaultStatus, len(vaults.Vaults)),
		StatusCounts:   StatusCounts{},
		VersionCounts:  make(map[string]int),
		RegionCounts:   make(map[string]int),
	}

	for i, vault := range vaults.Vaults {
		// Convert vault to VaultStatus
		vaultStatus := VaultStatus{
			ID:              vault.ID,
			Name:            vault.Name,
			Status:          string(vault.Status),
			Health:          s.calculateVaultHealth(vault),
			Version:         vault.Version,
			LastHeartbeat:   vault.LastHeartbeat,
			SecretCount:     vault.Metrics.SecretCount,
			RequestsPerHour: vault.Metrics.RequestsPerSecond * 3600, // Convert to per hour
			ErrorRate:       vault.Metrics.ErrorRate,
			Latency:         vault.Metrics.AverageLatency,
			StorageUsageGB:  float64(vault.Metrics.StorageUsage) / (1024 * 1024 * 1024),
			Tags:            vault.Tags,
			Alerts:          0, // Would be calculated from monitoring service
		}

		summary.Vaults[i] = vaultStatus

		// Update counts
		switch vault.Status {
		case "online":
			summary.StatusCounts.Online++
		case "offline":
			summary.StatusCounts.Offline++
		case "degraded":
			summary.StatusCounts.Degraded++
		default:
			summary.StatusCounts.Unknown++
		}

		// Update version counts
		summary.VersionCounts[vault.Version]++

		// Update region counts (from tags)
		if region, ok := vault.Tags["region"]; ok {
			summary.RegionCounts[region]++
		}
	}

	return summary, nil
}

// GetPerformanceMetrics returns performance metrics dashboard data
func (s *Service) GetPerformanceMetrics(ctx context.Context, orgID string, timeRange string) (*PerformanceMetrics, error) {
	// Get analytics data
	analyticsData, err := s.analyticsService.GetDashboardData(ctx, orgID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics data: %w", err)
	}

	// Get vault summary for individual vault metrics
	vaultSummary, err := s.GetVaultSummary(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault summary: %w", err)
	}

	// Convert vault statuses to vault performance metrics
	vaultMetrics := make([]VaultPerformance, len(vaultSummary.Vaults))
	for i, vault := range vaultSummary.Vaults {
		vaultMetrics[i] = VaultPerformance{
			VaultID:           vault.ID,
			VaultName:         vault.Name,
			AverageLatency:    vault.Latency,
			RequestsPerSecond: vault.RequestsPerHour / 3600,
			ErrorRate:         vault.ErrorRate,
			Availability:      s.calculateAvailability(vault),
			HealthScore:       s.parseHealthScore(vault.Health),
		}
	}

	// Sort for top and bottom performers
	sortedMetrics := make([]VaultPerformance, len(vaultMetrics))
	copy(sortedMetrics, vaultMetrics)
	
	// Sort by health score for top/bottom performers
	sort.Slice(sortedMetrics, func(i, j int) bool {
		return sortedMetrics[i].HealthScore > sortedMetrics[j].HealthScore
	})

	topPerformers := sortedMetrics[:min(5, len(sortedMetrics))]
	bottomPerformers := make([]VaultPerformance, 0)
	if len(sortedMetrics) > 5 {
		bottomPerformers = sortedMetrics[len(sortedMetrics)-5:]
	}

	// Convert performance trends
	trendData := make([]PerformanceTrend, len(analyticsData.PerformanceTrends))
	for i, trend := range analyticsData.PerformanceTrends {
		if len(trend.DataPoints) > 0 {
			// Use the latest data point for trend
			latest := trend.DataPoints[len(trend.DataPoints)-1]
			trendData[i] = PerformanceTrend{
				Timestamp:         latest.Timestamp,
				AverageLatency:    latest.Value, // Assuming this is latency data
				RequestsPerSecond: 0,           // Would need separate trend data
				ErrorRate:         0,           // Would need separate trend data
			}
		}
	}

	metrics := &PerformanceMetrics{
		OrganizationID: orgID,
		TimeRange:      timeRange,
		GeneratedAt:    time.Now(),
		OverallMetrics: OverallPerformance{
			AverageLatency:    analyticsData.OverviewMetrics.AverageLatency,
			P95Latency:        0, // Would need to calculate from detailed metrics
			P99Latency:        0, // Would need to calculate from detailed metrics
			TotalRequests:     analyticsData.OverviewMetrics.TotalRequests24h,
			RequestsPerSecond: float64(analyticsData.OverviewMetrics.TotalRequests24h) / (24 * 3600),
			ErrorRate:         analyticsData.OverviewMetrics.ErrorRate,
			Availability:      99.9, // Would be calculated from uptime data
		},
		VaultMetrics:     vaultMetrics,
		TrendData:        trendData,
		TopPerformers:    topPerformers,
		BottomPerformers: bottomPerformers,
		Thresholds: PerformanceThresholds{
			LatencyWarning:    500,  // 500ms
			LatencyCritical:   1000, // 1s
			ErrorRateWarning:  0.05, // 5%
			ErrorRateCritical: 0.10, // 10%
		},
	}

	return metrics, nil
}

// GetSecurityDashboard returns security-related dashboard data
func (s *Service) GetSecurityDashboard(ctx context.Context, orgID string) (*SecurityDashboard, error) {
	// Get monitoring events for security analysis
	eventFilter := &EventFilter{
		OrganizationID: orgID,
		Limit:          100,
	}
	
	events, err := s.monitoringService.GetEvents(ctx, eventFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get monitoring events: %w", err)
	}

	// Convert monitoring events to security events
	securityEvents := make([]SecurityEvent, 0)
	policyViolations := make([]PolicyViolation, 0)
	
	for _, event := range events {
		if s.isSecurityEvent(event.EventType) {
			securityEvent := SecurityEvent{
				ID:          event.ID,
				Type:        string(event.EventType),
				Severity:    string(event.Severity),
				Description: event.Message,
				VaultID:     event.VaultID,
				Timestamp:   event.Timestamp,
				Details:     event.Details,
				Status:      "active",
			}
			
			if !event.Resolved {
				securityEvents = append(securityEvents, securityEvent)
			}
		}
	}

	// Calculate security score
	securityScore := s.calculateSecurityScore(securityEvents, policyViolations)

	dashboard := &SecurityDashboard{
		OrganizationID:   orgID,
		GeneratedAt:      time.Now(),
		SecurityScore:    securityScore,
		SecurityEvents:   securityEvents,
		PolicyViolations: policyViolations,
		AccessPatterns:   []AccessPattern{}, // Would be populated from audit logs
		CertificateStatus: []CertificateStatus{}, // Would be populated from vault certificates
		ComplianceStatus: ComplianceOverview{
			OverallScore:   85.0, // Would be calculated from compliance data
			Standards:      map[string]float64{"SOC2": 90.0, "ISO27001": 80.0},
			LastAssessment: time.Now().AddDate(0, -1, 0),
			NextAssessment: time.Now().AddDate(0, 2, 0),
		},
		Recommendations: s.generateSecurityRecommendations(securityEvents),
	}

	return dashboard, nil
}

// GetAlerts returns active alerts and notifications
func (s *Service) GetAlerts(ctx context.Context, orgID string) (*AlertsDashboard, error) {
	// Get monitoring events
	eventFilter := &EventFilter{
		OrganizationID: orgID,
		Resolved:       &[]bool{false}[0], // Only unresolved events
		Limit:          100,
	}
	
	events, err := s.monitoringService.GetEvents(ctx, eventFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get monitoring events: %w", err)
	}

	// Convert to alerts
	activeAlerts := make([]Alert, len(events))
	for i, event := range events {
		activeAlerts[i] = Alert{
			ID:          event.ID,
			Type:        string(event.EventType),
			Severity:    string(event.Severity),
			Title:       string(event.EventType),
			Description: event.Message,
			VaultID:     event.VaultID,
			CreatedAt:   event.Timestamp,
			UpdatedAt:   event.Timestamp,
			Status:      "active",
			Details:     event.Details,
			Acknowledged: false,
		}
	}

	// Get recent alerts (last 24 hours)
	since := time.Now().Add(-24 * time.Hour)
	recentFilter := &EventFilter{
		OrganizationID: orgID,
		StartTime:      &since,
		Limit:          50,
	}
	
	recentEvents, err := s.monitoringService.GetEvents(ctx, recentFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent events: %w", err)
	}

	recentAlerts := make([]Alert, len(recentEvents))
	for i, event := range recentEvents {
		recentAlerts[i] = Alert{
			ID:          event.ID,
			Type:        string(event.EventType),
			Severity:    string(event.Severity),
			Title:       string(event.EventType),
			Description: event.Message,
			VaultID:     event.VaultID,
			CreatedAt:   event.Timestamp,
			UpdatedAt:   event.Timestamp,
			Status:      "active",
			Details:     event.Details,
			Acknowledged: false,
		}
	}

	// Calculate alert summary
	alertSummary := s.calculateAlertSummary(activeAlerts)

	dashboard := &AlertsDashboard{
		OrganizationID: orgID,
		GeneratedAt:    time.Now(),
		ActiveAlerts:   activeAlerts,
		RecentAlerts:   recentAlerts,
		AlertSummary:   alertSummary,
		AlertTrends:    []AlertTrend{}, // Would be calculated from historical data
		NotificationStatus: NotificationStatus{
			EmailEnabled:     true,
			SlackEnabled:     false,
			WebhookEnabled:   true,
			LastNotification: time.Now().Add(-1 * time.Hour),
			FailedDeliveries: 0,
		},
	}

	return dashboard, nil
}

// GetUsageAnalytics returns usage analytics dashboard
func (s *Service) GetUsageAnalytics(ctx context.Context, orgID string, period string) (*UsageAnalytics, error) {
	// Get analytics data
	analyticsData, err := s.analyticsService.GetDashboardData(ctx, orgID, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics data: %w", err)
	}

	analytics := &UsageAnalytics{
		OrganizationID: orgID,
		Period:         period,
		GeneratedAt:    time.Now(),
		OverallUsage: OverallUsage{
			TotalRequests:   analyticsData.OverviewMetrics.TotalRequests24h,
			UniqueUsers:     0, // Would be calculated from user activity
			ActiveVaults:    analyticsData.OverviewMetrics.OnlineVaults,
			SecretsAccessed: 0, // Would be calculated from audit logs
			DataTransferred: 0, // Would be calculated from metrics
			AverageLatency:  analyticsData.OverviewMetrics.AverageLatency,
			PeakRPS:         0, // Would be calculated from time series data
		},
		VaultUsage:    []VaultUsageMetrics{}, // Would be populated from detailed metrics
		UserActivity:  []UserActivity{},      // Would be populated from audit logs
		APIUsage:      []APIUsageMetrics{},   // Would be populated from API metrics
		TrendAnalysis: TrendAnalysis{},       // Would be calculated from time series data
		TopSecrets:    []SecretUsage{},       // Would be populated from audit logs
	}

	return analytics, nil
}

// GetCapacityPlanning returns capacity planning dashboard
func (s *Service) GetCapacityPlanning(ctx context.Context, orgID string) (*CapacityPlanning, error) {
	// Get current capacity metrics
	capacityMetrics, err := s.analyticsService.GetCapacityMetrics(ctx, orgID, "monthly")
	if err != nil {
		return nil, fmt.Errorf("failed to get capacity metrics: %w", err)
	}

	// Get vault summary for current usage
	vaultSummary, err := s.GetVaultSummary(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault summary: %w", err)
	}

	planning := &CapacityPlanning{
		OrganizationID: orgID,
		GeneratedAt:    time.Now(),
		CurrentCapacity: CurrentCapacity{
			TotalVaults:        len(vaultSummary.Vaults),
			MaxVaults:          100, // Would come from organization settings
			TotalStorage:       capacityMetrics.StorageUsageBytes,
			MaxStorage:         capacityMetrics.StorageCapacityBytes,
			TotalUsers:         0, // Would be calculated
			MaxUsers:           1000, // Would come from organization settings
			StorageUtilization: capacityMetrics.StorageUtilization,
			VaultUtilization:   float64(len(vaultSummary.Vaults)) / 100.0,
			UserUtilization:    0, // Would be calculated
		},
		CapacityForecasts:      []CapacityForecast{}, // Would be calculated from trends
		ResourceUtilization:    ResourceUtilization{}, // Would be populated from metrics
		ScalingRecommendations: []ScalingRecommendation{}, // Would be generated based on utilization
		CostAnalysis:          CostAnalysis{}, // Would be calculated from usage and pricing
	}

	return planning, nil
}

// GetComplianceStatus returns compliance status dashboard
func (s *Service) GetComplianceStatus(ctx context.Context, orgID string) (*ComplianceStatus, error) {
	// This would integrate with compliance monitoring systems
	status := &ComplianceStatus{
		OrganizationID: orgID,
		GeneratedAt:    time.Now(),
		OverallCompliance: ComplianceScore{
			Score:           85.0,
			Grade:           "B+",
			LastAssessment:  time.Now().AddDate(0, -1, 0),
			NextAssessment:  time.Now().AddDate(0, 2, 0),
			TotalControls:   150,
			PassingControls: 128,
			FailingControls: 22,
		},
		StandardCompliance: []StandardCompliance{
			{
				Standard:            "SOC2",
				Score:               90.0,
				Status:              "compliant",
				LastAssessment:      time.Now().AddDate(0, -1, 0),
				RequiredControls:    75,
				ImplementedControls: 68,
				CriticalIssues:      2,
			},
		},
		ComplianceIssues: []ComplianceIssue{}, // Would be populated from compliance monitoring
		AuditTrail:       []AuditEntry{},      // Would be populated from audit logs
		Certifications:   []Certification{},   // Would be populated from certification data
		RemediationPlan:  []RemediationAction{}, // Would be generated from issues
	}

	return status, nil
}

// Helper methods

func (s *Service) calculateSystemHealth(vaultSummary *VaultSummary, monitoringStats *MonitoringStats) SystemHealthStatus {
	totalVaults := len(vaultSummary.Vaults)
	if totalVaults == 0 {
		return SystemHealthStatus{
			Status:      "unknown",
			Score:       0,
			Issues:      []string{"No vaults registered"},
			LastChecked: time.Now(),
		}
	}

	onlineRatio := float64(vaultSummary.StatusCounts.Online) / float64(totalVaults)
	score := onlineRatio * 100

	var status string
	var issues []string

	if score >= 95 {
		status = "healthy"
	} else if score >= 80 {
		status = "degraded"
		issues = append(issues, "Some vaults are offline or degraded")
	} else {
		status = "critical"
		issues = append(issues, "Many vaults are offline")
	}

	if monitoringStats.ActiveAlerts > 10 {
		issues = append(issues, "High number of active alerts")
		if score > 70 {
			score = 70
		}
	}

	return SystemHealthStatus{
		Status:      status,
		Score:       score,
		Issues:      issues,
		LastChecked: time.Now(),
	}
}

func (s *Service) calculateVaultHealth(vault VaultAgent) string {
	if vault.Status != "online" {
		return "unhealthy"
	}

	if time.Since(vault.LastHeartbeat) > 5*time.Minute {
		return "degraded"
	}

	if vault.Metrics.ErrorRate > 0.1 {
		return "degraded"
	}

	return "healthy"
}

func (s *Service) calculateAvailability(vault VaultStatus) float64 {
	// Simplified calculation - would be based on actual uptime data
	if vault.Status == "online" {
		return 99.9
	} else if vault.Status == "degraded" {
		return 95.0
	}
	return 0.0
}

func (s *Service) parseHealthScore(health string) float64 {
	switch health {
	case "healthy":
		return 100.0
	case "degraded":
		return 70.0
	case "unhealthy":
		return 30.0
	default:
		return 0.0
	}
}

func (s *Service) isSecurityEvent(eventType MonitoringEventType) bool {
	securityEvents := map[MonitoringEventType]bool{
		"certificate_expiring": true,
		"vault_offline":        true,
		"high_error_rate":      true,
	}
	return securityEvents[eventType]
}

func (s *Service) calculateSecurityScore(events []SecurityEvent, violations []PolicyViolation) float64 {
	baseScore := 100.0
	
	// Deduct points for security events
	for _, event := range events {
		switch event.Severity {
		case "critical":
			baseScore -= 10
		case "warning":
			baseScore -= 5
		case "info":
			baseScore -= 1
		}
	}

	// Deduct points for policy violations
	for _, violation := range violations {
		switch violation.Severity {
		case "critical":
			baseScore -= 15
		case "warning":
			baseScore -= 8
		}
	}

	if baseScore < 0 {
		baseScore = 0
	}

	return baseScore
}

func (s *Service) generateSecurityRecommendations(events []SecurityEvent) []SecurityRecommendation {
	recommendations := []SecurityRecommendation{}
	
	if len(events) > 10 {
		recommendations = append(recommendations, SecurityRecommendation{
			ID:          "rec-1",
			Title:       "High Number of Security Events",
			Description: "Consider reviewing security policies and vault configurations",
			Priority:    "high",
			Category:    "security",
			Impact:      "high",
			Effort:      "medium",
			CreatedAt:   time.Now(),
		})
	}

	return recommendations
}

func (s *Service) calculateAlertSummary(alerts []Alert) AlertSummary {
	summary := AlertSummary{
		Total:        len(alerts),
		ByType:       make(map[string]int),
		ByVault:      make(map[string]int),
	}

	for _, alert := range alerts {
		switch alert.Severity {
		case "critical":
			summary.Critical++
		case "warning":
			summary.Warning++
		case "info":
			summary.Info++
		}

		if alert.Acknowledged {
			summary.Acknowledged++
		}

		summary.ByType[alert.Type]++
		summary.ByVault[alert.VaultID]++
	}

	return summary
}

func (s *Service) getRecentActivity(ctx context.Context, orgID string, limit int) []ActivitySummary {
	// This would be populated from audit logs and system events
	return []ActivitySummary{
		{
			Type:        "vault_registered",
			Description: "New vault agent registered",
			Timestamp:   time.Now().Add(-1 * time.Hour),
		},
		{
			Type:        "user_login",
			Description: "User logged in",
			Timestamp:   time.Now().Add(-2 * time.Hour),
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Interface definitions for dependencies
type VaultRegistry interface {
	ListVaults(ctx context.Context, filter *VaultFilter) (*VaultListResponse, error)
}

type AnalyticsService interface {
	GetDashboardData(ctx context.Context, orgID string, timeRange string) (*DashboardData, error)
	GetCapacityMetrics(ctx context.Context, orgID string, period string) (*CapacityMetrics, error)
}

type MonitoringService interface {
	GetMonitoringStats(ctx context.Context) (*MonitoringStats, error)
	GetEvents(ctx context.Context, filter *EventFilter) ([]MonitoringEvent, error)
}

type UserService interface {
	ListUsers(ctx context.Context, filter *UserFilter) (*UserListResponse, error)
}

// Simplified types for interface compatibility
type VaultAgent struct {
	ID            string
	Name          string
	Status        VaultStatus
	Version       string
	LastHeartbeat time.Time
	Metrics       VaultMetrics
	Tags          map[string]string
}

type VaultStatus string
type VaultMetrics struct {
	SecretCount        int64
	RequestsPerSecond  float64
	ErrorRate          float64
	AverageLatency     float64
	StorageUsage       int64
}

type VaultFilter struct {
	OrganizationID string
}

type VaultListResponse struct {
	Vaults []VaultAgent
}

type MonitoringStats struct {
	EventsBySeverity map[Severity]int
	ActiveAlerts     int
}

type MonitoringEvent struct {
	ID        string
	VaultID   string
	EventType MonitoringEventType
	Severity  Severity
	Message   string
	Details   map[string]interface{}
	Timestamp time.Time
	Resolved  bool
}

type MonitoringEventType string
type Severity string

type EventFilter struct {
	OrganizationID string
	Resolved       *bool
	StartTime      *time.Time
	Limit          int
}

type UserFilter struct {
	OrganizationID string
}

type UserListResponse struct {
	Total int
}

type DashboardData struct {
	OverviewMetrics   OverviewMetrics
	PerformanceTrends []TimeSeriesData
}

type OverviewMetrics struct {
	TotalVaults      int
	OnlineVaults     int
	TotalRequests24h int64
	AverageLatency   float64
	ErrorRate        float64
	StorageUsageGB   float64
}

type TimeSeriesData struct {
	DataPoints []TimeSeriesDataPoint
}

type TimeSeriesDataPoint struct {
	Timestamp time.Time
	Value     float64
}

type CapacityMetrics struct {
	StorageUsageBytes    int64
	StorageCapacityBytes int64
	StorageUtilization   float64
}
