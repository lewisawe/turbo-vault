package security

import (
	"context"
	"time"
)

// SecurityScanner defines the interface for security scanning and vulnerability assessment
type SecurityScanner interface {
	ScanVulnerabilities(ctx context.Context, config *ScanConfig) (*ScanResult, error)
	ScanConfiguration(ctx context.Context) (*ConfigScanResult, error)
	ScanCertificates(ctx context.Context) (*CertScanResult, error)
	ScanDependencies(ctx context.Context) (*DependencyScanResult, error)
	GetScanHistory(ctx context.Context, limit int) ([]*ScanResult, error)
}

// ComplianceReporter handles compliance reporting for various standards
type ComplianceReporter interface {
	GenerateSOC2Report(ctx context.Context, period *ReportPeriod) (*ComplianceReport, error)
	GenerateISO27001Report(ctx context.Context, period *ReportPeriod) (*ComplianceReport, error)
	GeneratePCIDSSReport(ctx context.Context, period *ReportPeriod) (*ComplianceReport, error)
	GenerateHIPAAReport(ctx context.Context, period *ReportPeriod) (*ComplianceReport, error)
	GetComplianceStatus(ctx context.Context, standard ComplianceStandard) (*ComplianceStatus, error)
	ValidateCompliance(ctx context.Context, standard ComplianceStandard) (*ValidationResult, error)
}

// PenetrationTester provides security validation and attack simulation
type PenetrationTester interface {
	RunSecurityTests(ctx context.Context, config *PenTestConfig) (*PenTestResult, error)
	SimulateAttack(ctx context.Context, attack *AttackScenario) (*AttackResult, error)
	ValidateSecurityControls(ctx context.Context) (*SecurityValidation, error)
	GenerateSecurityReport(ctx context.Context) (*SecurityReport, error)
}

// ZeroTrustValidator ensures zero-trust network security principles
type ZeroTrustValidator interface {
	ValidateNetworkAccess(ctx context.Context, request *NetworkRequest) (*AccessDecision, error)
	VerifyDeviceIdentity(ctx context.Context, device *DeviceInfo) (*IdentityVerification, error)
	EnforceNetworkPolicies(ctx context.Context, policies []*NetworkPolicy) error
	MonitorNetworkTraffic(ctx context.Context) (*TrafficAnalysis, error)
}

// SecurityPolicyManager manages security policies and templates
type SecurityPolicyManager interface {
	CreatePolicyTemplate(ctx context.Context, template *PolicyTemplate) error
	ApplySecurityPolicy(ctx context.Context, policy *SecurityPolicy) error
	ValidatePolicyCompliance(ctx context.Context, policy *SecurityPolicy) (*PolicyValidation, error)
	GetBestPracticeGuides(ctx context.Context, category string) ([]*BestPracticeGuide, error)
	GeneratePolicyRecommendations(ctx context.Context) ([]*PolicyRecommendation, error)
}

// SecurityEventMonitor handles security event detection and response
type SecurityEventMonitor interface {
	DetectSecurityEvents(ctx context.Context) ([]*SecurityEvent, error)
	AnalyzeThreatPatterns(ctx context.Context, events []*SecurityEvent) (*ThreatAnalysis, error)
	TriggerSecurityResponse(ctx context.Context, event *SecurityEvent) error
	GetSecurityMetrics(ctx context.Context, period *ReportPeriod) (*SecurityMetrics, error)
}