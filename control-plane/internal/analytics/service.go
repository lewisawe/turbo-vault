package analytics

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Service implements the AnalyticsService interface
type Service struct {
	metricsStorage  MetricsStorage
	thresholdStorage ThresholdStorage
	vaultRegistry   VaultRegistry
	notification    NotificationService
}

// NewService creates a new analytics service
func NewService(
	metricsStorage MetricsStorage,
	thresholdStorage ThresholdStorage,
	vaultRegistry VaultRegistry,
	notification NotificationService,
) *Service {
	return &Service{
		metricsStorage:   metricsStorage,
		thresholdStorage: thresholdStorage,
		vaultRegistry:    vaultRegistry,
		notification:     notification,
	}
}

// RecordUsageMetrics records usage metrics for a vault
func (s *Service) RecordUsageMetrics(ctx context.Context, metrics *UsageMetrics) error {
	if metrics.Timestamp.IsZero() {
		metrics.Timestamp = time.Now()
	}
	
	return s.metricsStorage.StoreUsageMetrics(ctx, metrics)
}

// GetUsageReport generates a usage report for an organization
func (s *Service) GetUsageReport(ctx context.Context, orgID string, period string, startTime, endTime time.Time) (*UsageReport, error) {
	// Get usage metrics for the period
	filter := &MetricsFilter{
		OrganizationID: orgID,
		StartTime:      &startTime,
		EndTime:        &endTime,
		Granularity:    period,
	}
	
	usageMetrics, err := s.metricsStorage.GetUsageMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage metrics: %w", err)
	}

	// Get performance metrics
	performanceMetrics, err := s.metricsStorage.GetPerformanceMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance metrics: %w", err)
	}

	// Get capacity metrics
	capacityMetrics, err := s.metricsStorage.GetCapacityMetrics(ctx, orgID, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get capacity metrics: %w", err)
	}

	// Generate report
	report := &UsageReport{
		OrganizationID: orgID,
		ReportPeriod:   period,
		StartTime:      startTime,
		EndTime:        endTime,
		GeneratedAt:    time.Now(),
	}

	// Calculate summary
	report.Summary = s.calculateUsageSummary(usageMetrics)
	
	// Calculate vault metrics
	report.VaultMetrics = s.calculateVaultUsage(usageMetrics)
	
	// Set performance and capacity data
	if len(performanceMetrics) > 0 {
		report.PerformanceData = performanceMetrics[0]
	}
	
	if len(capacityMetrics) > 0 {
		report.CapacityData = capacityMetrics[0]
	}

	// Generate recommendations
	report.Recommendations = s.generateRecommendationsFromData(usageMetrics, performanceMetrics, capacityMetrics)

	return report, nil
}

// GetPerformanceMetrics retrieves performance metrics with filtering
func (s *Service) GetPerformanceMetrics(ctx context.Context, filter *MetricsFilter) ([]PerformanceMetrics, error) {
	return s.metricsStorage.GetPerformanceMetrics(ctx, filter)
}

// GetCapacityMetrics retrieves capacity planning metrics
func (s *Service) GetCapacityMetrics(ctx context.Context, orgID string, period string) (*CapacityMetrics, error) {
	endTime := time.Now()
	var startTime time.Time
	
	switch period {
	case "daily":
		startTime = endTime.AddDate(0, 0, -1)
	case "weekly":
		startTime = endTime.AddDate(0, 0, -7)
	case "monthly":
		startTime = endTime.AddDate(0, -1, 0)
	default:
		startTime = endTime.AddDate(0, 0, -7) // Default to weekly
	}

	capacityMetrics, err := s.metricsStorage.GetCapacityMetrics(ctx, orgID, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get capacity metrics: %w", err)
	}

	if len(capacityMetrics) == 0 {
		return nil, fmt.Errorf("no capacity metrics found for organization %s", orgID)
	}

	return &capacityMetrics[0], nil
}

// GetTimeSeriesData retrieves time-series data for metrics
func (s *Service) GetTimeSeriesData(ctx context.Context, filter *MetricsFilter) ([]TimeSeriesData, error) {
	usageMetrics, err := s.metricsStorage.GetUsageMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage metrics: %w", err)
	}

	// Group metrics by vault and metric type
	timeSeriesMap := make(map[string]map[string][]TimeSeriesDataPoint)
	
	for _, metric := range usageMetrics {
		if timeSeriesMap[metric.VaultID] == nil {
			timeSeriesMap[metric.VaultID] = make(map[string][]TimeSeriesDataPoint)
		}
		
		// Add data points for different metric types
		timeSeriesMap[metric.VaultID]["request_count"] = append(
			timeSeriesMap[metric.VaultID]["request_count"],
			TimeSeriesDataPoint{Timestamp: metric.Timestamp, Value: float64(metric.RequestCount)},
		)
		
		timeSeriesMap[metric.VaultID]["average_latency"] = append(
			timeSeriesMap[metric.VaultID]["average_latency"],
			TimeSeriesDataPoint{Timestamp: metric.Timestamp, Value: metric.AverageLatencyMs},
		)
		
		timeSeriesMap[metric.VaultID]["error_count"] = append(
			timeSeriesMap[metric.VaultID]["error_count"],
			TimeSeriesDataPoint{Timestamp: metric.Timestamp, Value: float64(metric.ErrorCount)},
		)
	}

	// Convert to TimeSeriesData format
	var result []TimeSeriesData
	for vaultID, metrics := range timeSeriesMap {
		for metricName, dataPoints := range metrics {
			// Sort data points by timestamp
			sort.Slice(dataPoints, func(i, j int) bool {
				return dataPoints[i].Timestamp.Before(dataPoints[j].Timestamp)
			})
			
			result = append(result, TimeSeriesData{
				MetricName: metricName,
				VaultID:    vaultID,
				DataPoints: dataPoints,
			})
		}
	}

	return result, nil
}

// GetDashboardData retrieves data for analytics dashboard
func (s *Service) GetDashboardData(ctx context.Context, orgID string, timeRange string) (*DashboardData, error) {
	endTime := time.Now()
	var startTime time.Time
	
	switch timeRange {
	case "1h":
		startTime = endTime.Add(-1 * time.Hour)
	case "24h":
		startTime = endTime.Add(-24 * time.Hour)
	case "7d":
		startTime = endTime.AddDate(0, 0, -7)
	case "30d":
		startTime = endTime.AddDate(0, 0, -30)
	default:
		startTime = endTime.Add(-24 * time.Hour) // Default to 24h
	}

	// Get vaults for organization
	vaults, err := s.vaultRegistry.ListVaults(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vaults: %w", err)
	}

	// Get usage metrics
	filter := &MetricsFilter{
		OrganizationID: orgID,
		StartTime:      &startTime,
		EndTime:        &endTime,
	}
	
	usageMetrics, err := s.metricsStorage.GetUsageMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage metrics: %w", err)
	}

	// Get performance trends
	performanceTrends, err := s.GetTimeSeriesData(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance trends: %w", err)
	}

	dashboard := &DashboardData{
		OrganizationID:    orgID,
		GeneratedAt:       time.Now(),
		TimeRange:         timeRange,
		OverviewMetrics:   s.calculateOverviewMetrics(vaults, usageMetrics),
		VaultStatuses:     s.calculateVaultStatuses(vaults),
		PerformanceTrends: performanceTrends,
		TopVaultsByUsage:  s.calculateTopVaultsByUsage(usageMetrics, 10),
		RecentAlerts:      []AlertSummary{}, // Would be populated from monitoring service
	}

	return dashboard, nil
}

// RecordEvent records an analytics event
func (s *Service) RecordEvent(ctx context.Context, event *AnalyticsEvent) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	return s.metricsStorage.StoreEvent(ctx, event)
}

// CreateAlertThreshold creates a new alert threshold
func (s *Service) CreateAlertThreshold(ctx context.Context, threshold *AlertThreshold) error {
	threshold.ID = uuid.New().String()
	threshold.CreatedAt = time.Now()
	threshold.UpdatedAt = time.Now()
	
	return s.thresholdStorage.CreateThreshold(ctx, threshold)
}

// UpdateAlertThreshold updates an existing alert threshold
func (s *Service) UpdateAlertThreshold(ctx context.Context, thresholdID string, threshold *AlertThreshold) error {
	threshold.UpdatedAt = time.Now()
	return s.thresholdStorage.UpdateThreshold(ctx, thresholdID, threshold)
}

// DeleteAlertThreshold deletes an alert threshold
func (s *Service) DeleteAlertThreshold(ctx context.Context, thresholdID string) error {
	return s.thresholdStorage.DeleteThreshold(ctx, thresholdID)
}

// GetAlertThresholds retrieves alert thresholds for an organization
func (s *Service) GetAlertThresholds(ctx context.Context, orgID string) ([]AlertThreshold, error) {
	return s.thresholdStorage.ListThresholds(ctx, orgID)
}

// CheckThresholds checks metrics against alert thresholds
func (s *Service) CheckThresholds(ctx context.Context, orgID string) ([]AlertSummary, error) {
	thresholds, err := s.thresholdStorage.GetEnabledThresholds(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get thresholds: %w", err)
	}

	// Get recent metrics
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute) // Check last 5 minutes
	
	filter := &MetricsFilter{
		OrganizationID: orgID,
		StartTime:      &startTime,
		EndTime:        &endTime,
	}
	
	usageMetrics, err := s.metricsStorage.GetUsageMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage metrics: %w", err)
	}

	var alerts []AlertSummary
	
	for _, threshold := range thresholds {
		for _, metric := range usageMetrics {
			if s.checkThreshold(threshold, metric) {
				alert := AlertSummary{
					ID:        uuid.New().String(),
					VaultID:   metric.VaultID,
					AlertType: threshold.MetricType,
					Severity:  "warning", // Could be derived from threshold
					Message:   fmt.Sprintf("Threshold exceeded for %s: %.2f", threshold.MetricType, s.getMetricValue(threshold.MetricType, metric)),
					Timestamp: time.Now(),
				}
				alerts = append(alerts, alert)
				
				// Send notification
				if s.notification != nil {
					s.notification.SendAlert(ctx, &alert, threshold.NotificationChannels)
				}
			}
		}
	}

	return alerts, nil
}

// GenerateRecommendations generates capacity and performance recommendations
func (s *Service) GenerateRecommendations(ctx context.Context, orgID string) ([]string, error) {
	// Get recent metrics for analysis
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -7) // Last 7 days
	
	filter := &MetricsFilter{
		OrganizationID: orgID,
		StartTime:      &startTime,
		EndTime:        &endTime,
	}
	
	usageMetrics, err := s.metricsStorage.GetUsageMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage metrics: %w", err)
	}

	performanceMetrics, err := s.metricsStorage.GetPerformanceMetrics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance metrics: %w", err)
	}

	capacityMetrics, err := s.metricsStorage.GetCapacityMetrics(ctx, orgID, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get capacity metrics: %w", err)
	}

	return s.generateRecommendationsFromData(usageMetrics, performanceMetrics, capacityMetrics), nil
}

// Helper methods

func (s *Service) calculateUsageSummary(metrics []UsageMetrics) UsageSummary {
	if len(metrics) == 0 {
		return UsageSummary{}
	}

	var totalRequests, totalSecrets int64
	var totalStorage, totalLatency, totalErrors float64
	vaultCount := make(map[string]bool)

	for _, metric := range metrics {
		vaultCount[metric.VaultID] = true
		totalRequests += metric.RequestCount
		totalSecrets += metric.SecretCount
		totalStorage += float64(metric.StorageUsageBytes)
		totalLatency += metric.AverageLatencyMs
		totalErrors += float64(metric.ErrorCount)
	}

	avgLatency := totalLatency / float64(len(metrics))
	errorRate := totalErrors / float64(totalRequests)
	if totalRequests == 0 {
		errorRate = 0
	}

	return UsageSummary{
		TotalVaults:      len(vaultCount),
		TotalRequests:    totalRequests,
		TotalSecrets:     totalSecrets,
		TotalStorageGB:   totalStorage / (1024 * 1024 * 1024), // Convert to GB
		AverageLatency:   avgLatency,
		OverallErrorRate: errorRate,
		UptimePercentage: 99.9, // Would be calculated from actual uptime data
	}
}

func (s *Service) calculateVaultUsage(metrics []UsageMetrics) []VaultUsage {
	vaultMap := make(map[string]*VaultUsage)

	for _, metric := range metrics {
		if vaultMap[metric.VaultID] == nil {
			vaultMap[metric.VaultID] = &VaultUsage{
				VaultID: metric.VaultID,
			}
		}

		usage := vaultMap[metric.VaultID]
		usage.RequestCount += metric.RequestCount
		usage.SecretCount = metric.SecretCount // Use latest value
		usage.StorageUsageGB = float64(metric.StorageUsageBytes) / (1024 * 1024 * 1024)
		usage.AverageLatency = metric.AverageLatencyMs // Use latest value
		
		if metric.RequestCount > 0 {
			usage.ErrorRate = float64(metric.ErrorCount) / float64(metric.RequestCount)
		}
		usage.UptimePercentage = 99.9 // Would be calculated from actual uptime data
	}

	var result []VaultUsage
	for _, usage := range vaultMap {
		result = append(result, *usage)
	}

	return result
}

func (s *Service) calculateOverviewMetrics(vaults []VaultInfo, metrics []UsageMetrics) OverviewMetrics {
	onlineCount := 0
	for _, vault := range vaults {
		if vault.Status == "online" {
			onlineCount++
		}
	}

	var totalRequests int64
	var totalLatency, totalErrors float64
	var totalStorage int64

	for _, metric := range metrics {
		totalRequests += metric.RequestCount
		totalLatency += metric.AverageLatencyMs
		totalErrors += float64(metric.ErrorCount)
		totalStorage += metric.StorageUsageBytes
	}

	avgLatency := float64(0)
	errorRate := float64(0)
	
	if len(metrics) > 0 {
		avgLatency = totalLatency / float64(len(metrics))
	}
	
	if totalRequests > 0 {
		errorRate = totalErrors / float64(totalRequests)
	}

	return OverviewMetrics{
		TotalVaults:      len(vaults),
		OnlineVaults:     onlineCount,
		TotalRequests24h: totalRequests,
		AverageLatency:   avgLatency,
		ErrorRate:        errorRate,
		StorageUsageGB:   float64(totalStorage) / (1024 * 1024 * 1024),
	}
}

func (s *Service) calculateVaultStatuses(vaults []VaultInfo) []VaultStatusSummary {
	var statuses []VaultStatusSummary
	
	for _, vault := range vaults {
		health := "healthy"
		if vault.Status != "online" {
			health = "unhealthy"
		} else if time.Since(vault.LastHeartbeat) > 5*time.Minute {
			health = "degraded"
		}

		statuses = append(statuses, VaultStatusSummary{
			VaultID:   vault.ID,
			VaultName: vault.Name,
			Status:    vault.Status,
			Health:    health,
		})
	}

	return statuses
}

func (s *Service) calculateTopVaultsByUsage(metrics []UsageMetrics, limit int) []VaultUsage {
	vaultUsage := s.calculateVaultUsage(metrics)
	
	// Sort by request count
	sort.Slice(vaultUsage, func(i, j int) bool {
		return vaultUsage[i].RequestCount > vaultUsage[j].RequestCount
	})

	if len(vaultUsage) > limit {
		vaultUsage = vaultUsage[:limit]
	}

	return vaultUsage
}

func (s *Service) checkThreshold(threshold AlertThreshold, metric UsageMetrics) bool {
	value := s.getMetricValue(threshold.MetricType, metric)
	
	switch threshold.ComparisonType {
	case "greater_than":
		return value > threshold.ThresholdValue
	case "less_than":
		return value < threshold.ThresholdValue
	case "equals":
		return math.Abs(value-threshold.ThresholdValue) < 0.001
	default:
		return false
	}
}

func (s *Service) getMetricValue(metricType string, metric UsageMetrics) float64 {
	switch metricType {
	case "request_count":
		return float64(metric.RequestCount)
	case "error_count":
		return float64(metric.ErrorCount)
	case "average_latency":
		return metric.AverageLatencyMs
	case "cpu_usage":
		return metric.CPUUsagePercent
	case "memory_usage":
		return float64(metric.MemoryUsageBytes)
	case "storage_usage":
		return float64(metric.StorageUsageBytes)
	default:
		return 0
	}
}

func (s *Service) generateRecommendationsFromData(usage []UsageMetrics, performance []PerformanceMetrics, capacity []CapacityMetrics) []string {
	var recommendations []string

	// Analyze usage patterns
	if len(usage) > 0 {
		avgLatency := float64(0)
		avgErrorRate := float64(0)
		
		for _, metric := range usage {
			avgLatency += metric.AverageLatencyMs
			if metric.RequestCount > 0 {
				avgErrorRate += float64(metric.ErrorCount) / float64(metric.RequestCount)
			}
		}
		
		avgLatency /= float64(len(usage))
		avgErrorRate /= float64(len(usage))

		if avgLatency > 500 {
			recommendations = append(recommendations, "Consider optimizing vault performance - average latency is high (>500ms)")
		}

		if avgErrorRate > 0.05 {
			recommendations = append(recommendations, "Investigate error sources - error rate is above 5%")
		}
	}

	// Analyze capacity
	if len(capacity) > 0 {
		cap := capacity[0]
		if cap.StorageUtilization > 0.8 {
			recommendations = append(recommendations, "Storage utilization is high (>80%) - consider expanding storage capacity")
		}

		if cap.AverageCPUUsage > 0.8 {
			recommendations = append(recommendations, "CPU usage is high (>80%) - consider scaling up vault instances")
		}

		if cap.GrowthRate > 0.2 {
			recommendations = append(recommendations, "High growth rate detected - plan for capacity expansion")
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "System is performing well - no immediate action required")
	}

	return recommendations
}
