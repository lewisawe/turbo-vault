package analytics

import (
	"context"
	"time"
)

// AnalyticsService defines the interface for analytics operations
type AnalyticsService interface {
	// RecordUsageMetrics records usage metrics for a vault
	RecordUsageMetrics(ctx context.Context, metrics *UsageMetrics) error
	
	// GetUsageReport generates a usage report for an organization
	GetUsageReport(ctx context.Context, orgID string, period string, startTime, endTime time.Time) (*UsageReport, error)
	
	// GetPerformanceMetrics retrieves performance metrics with filtering
	GetPerformanceMetrics(ctx context.Context, filter *MetricsFilter) ([]PerformanceMetrics, error)
	
	// GetCapacityMetrics retrieves capacity planning metrics
	GetCapacityMetrics(ctx context.Context, orgID string, period string) (*CapacityMetrics, error)
	
	// GetTimeSeriesData retrieves time-series data for metrics
	GetTimeSeriesData(ctx context.Context, filter *MetricsFilter) ([]TimeSeriesData, error)
	
	// GetDashboardData retrieves data for analytics dashboard
	GetDashboardData(ctx context.Context, orgID string, timeRange string) (*DashboardData, error)
	
	// RecordEvent records an analytics event
	RecordEvent(ctx context.Context, event *AnalyticsEvent) error
	
	// CreateAlertThreshold creates a new alert threshold
	CreateAlertThreshold(ctx context.Context, threshold *AlertThreshold) error
	
	// UpdateAlertThreshold updates an existing alert threshold
	UpdateAlertThreshold(ctx context.Context, thresholdID string, threshold *AlertThreshold) error
	
	// DeleteAlertThreshold deletes an alert threshold
	DeleteAlertThreshold(ctx context.Context, thresholdID string) error
	
	// GetAlertThresholds retrieves alert thresholds for an organization
	GetAlertThresholds(ctx context.Context, orgID string) ([]AlertThreshold, error)
	
	// CheckThresholds checks metrics against alert thresholds
	CheckThresholds(ctx context.Context, orgID string) ([]AlertSummary, error)
	
	// GenerateRecommendations generates capacity and performance recommendations
	GenerateRecommendations(ctx context.Context, orgID string) ([]string, error)
}

// MetricsStorage defines the interface for storing analytics metrics
type MetricsStorage interface {
	// StoreUsageMetrics stores usage metrics
	StoreUsageMetrics(ctx context.Context, metrics *UsageMetrics) error
	
	// GetUsageMetrics retrieves usage metrics with filtering
	GetUsageMetrics(ctx context.Context, filter *MetricsFilter) ([]UsageMetrics, error)
	
	// StorePerformanceMetrics stores aggregated performance metrics
	StorePerformanceMetrics(ctx context.Context, metrics *PerformanceMetrics) error
	
	// GetPerformanceMetrics retrieves performance metrics
	GetPerformanceMetrics(ctx context.Context, filter *MetricsFilter) ([]PerformanceMetrics, error)
	
	// StoreCapacityMetrics stores capacity metrics
	StoreCapacityMetrics(ctx context.Context, metrics *CapacityMetrics) error
	
	// GetCapacityMetrics retrieves capacity metrics
	GetCapacityMetrics(ctx context.Context, orgID string, startTime, endTime time.Time) ([]CapacityMetrics, error)
	
	// StoreEvent stores an analytics event
	StoreEvent(ctx context.Context, event *AnalyticsEvent) error
	
	// GetEvents retrieves analytics events with filtering
	GetEvents(ctx context.Context, filter *EventFilter) ([]AnalyticsEvent, error)
	
	// AggregateMetrics performs metric aggregation for a time period
	AggregateMetrics(ctx context.Context, orgID string, startTime, endTime time.Time, granularity string) ([]PerformanceMetrics, error)
	
	// CleanupOldMetrics removes metrics older than the specified duration
	CleanupOldMetrics(ctx context.Context, olderThan time.Duration) error
}

// ThresholdStorage defines the interface for storing alert thresholds
type ThresholdStorage interface {
	// CreateThreshold creates a new alert threshold
	CreateThreshold(ctx context.Context, threshold *AlertThreshold) error
	
	// GetThreshold retrieves an alert threshold by ID
	GetThreshold(ctx context.Context, thresholdID string) (*AlertThreshold, error)
	
	// UpdateThreshold updates an existing alert threshold
	UpdateThreshold(ctx context.Context, thresholdID string, threshold *AlertThreshold) error
	
	// DeleteThreshold deletes an alert threshold
	DeleteThreshold(ctx context.Context, thresholdID string) error
	
	// ListThresholds retrieves alert thresholds for an organization
	ListThresholds(ctx context.Context, orgID string) ([]AlertThreshold, error)
	
	// GetEnabledThresholds retrieves enabled alert thresholds
	GetEnabledThresholds(ctx context.Context, orgID string) ([]AlertThreshold, error)
}

// EventFilter represents filtering options for analytics events
type EventFilter struct {
	OrganizationID string     `json:"organization_id"`
	VaultID        string     `json:"vault_id"`
	EventType      string     `json:"event_type"`
	UserID         string     `json:"user_id"`
	StartTime      *time.Time `json:"start_time"`
	EndTime        *time.Time `json:"end_time"`
	Limit          int        `json:"limit"`
	Offset         int        `json:"offset"`
}

// VaultRegistry interface for accessing vault information
type VaultRegistry interface {
	GetVault(ctx context.Context, vaultID string) (*VaultInfo, error)
	ListVaults(ctx context.Context, orgID string) ([]VaultInfo, error)
}

// VaultInfo represents vault information for analytics
type VaultInfo struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	OrganizationID string    `json:"organization_id"`
	Status         string    `json:"status"`
	LastHeartbeat  time.Time `json:"last_heartbeat"`
}

// NotificationService interface for sending alerts
type NotificationService interface {
	SendAlert(ctx context.Context, alert *AlertSummary, channels []string) error
}