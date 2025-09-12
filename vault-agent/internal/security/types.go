package security

import (
	"time"
)

// ScanConfig defines configuration for security scans
type ScanConfig struct {
	ScanType     ScanType          `json:"scan_type"`
	Targets      []string          `json:"targets"`
	Depth        ScanDepth         `json:"depth"`
	Timeout      time.Duration     `json:"timeout"`
	Options      map[string]string `json:"options"`
	ExcludeRules []string          `json:"exclude_rules"`
}

// ScanResult represents the result of a security scan
type ScanResult struct {
	ID           string              `json:"id"`
	ScanType     ScanType            `json:"scan_type"`
	StartTime    time.Time           `json:"start_time"`
	EndTime      time.Time           `json:"end_time"`
	Status       ScanStatus          `json:"status"`
	Findings     []*SecurityFinding  `json:"findings"`
	Summary      *ScanSummary        `json:"summary"`
	Metadata     map[string]string   `json:"metadata"`
}

// SecurityFinding represents a security vulnerability or issue
type SecurityFinding struct {
	ID          string            `json:"id"`
	Type        FindingType       `json:"type"`
	Severity    SeverityLevel     `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Location    string            `json:"location"`
	Evidence    []string          `json:"evidence"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
	CVSS        *CVSSScore        `json:"cvss,omitempty"`
	CWE         string            `json:"cwe,omitempty"`
	CVE         string            `json:"cve,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// ComplianceReport represents a compliance assessment report
type ComplianceReport struct {
	ID               string                    `json:"id"`
	Standard         ComplianceStandard        `json:"standard"`
	Period           *ReportPeriod             `json:"period"`
	OverallScore     float64                   `json:"overall_score"`
	Status           ComplianceStatus          `json:"status"`
	Controls         []*ComplianceControl      `json:"controls"`
	Recommendations  []*ComplianceRecommendation `json:"recommendations"`
	Evidence         []*ComplianceEvidence     `json:"evidence"`
	GeneratedAt      time.Time                 `json:"generated_at"`
	GeneratedBy      string                    `json:"generated_by"`
}

// SecurityPolicy defines security policy configuration
type SecurityPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Category    PolicyCategory         `json:"category"`
	Rules       []*PolicyRule          `json:"rules"`
	Enforcement EnforcementLevel       `json:"enforcement"`
	Scope       []string               `json:"scope"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}// E
nums and constants
type ScanType string

const (
	ScanTypeVulnerability   ScanType = "vulnerability"
	ScanTypeConfiguration   ScanType = "configuration"
	ScanTypeCertificate     ScanType = "certificate"
	ScanTypeDependency      ScanType = "dependency"
	ScanTypeNetwork         ScanType = "network"
	ScanTypeCompliance      ScanType = "compliance"
)

type ScanDepth string

const (
	ScanDepthBasic      ScanDepth = "basic"
	ScanDepthStandard   ScanDepth = "standard"
	ScanDepthDeep       ScanDepth = "deep"
	ScanDepthExhaustive ScanDepth = "exhaustive"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type FindingType string

const (
	FindingTypeVulnerability     FindingType = "vulnerability"
	FindingTypeMisconfiguration  FindingType = "misconfiguration"
	FindingTypeWeakCrypto        FindingType = "weak_crypto"
	FindingTypeAccessControl     FindingType = "access_control"
	FindingTypeDataExposure      FindingType = "data_exposure"
	FindingTypeInsecureProtocol  FindingType = "insecure_protocol"
)

type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityInfo     SeverityLevel = "info"
)

type ComplianceStandard string

const (
	ComplianceSOC2     ComplianceStandard = "soc2"
	ComplianceISO27001 ComplianceStandard = "iso27001"
	CompliancePCIDSS   ComplianceStandard = "pci_dss"
	ComplianceHIPAA    ComplianceStandard = "hipaa"
	ComplianceGDPR     ComplianceStandard = "gdpr"
	ComplianceNIST     ComplianceStandard = "nist"
)

type ComplianceStatus string

const (
	ComplianceStatusCompliant    ComplianceStatus = "compliant"
	ComplianceStatusNonCompliant ComplianceStatus = "non_compliant"
	ComplianceStatusPartial      ComplianceStatus = "partial"
	ComplianceStatusUnknown      ComplianceStatus = "unknown"
)

type PolicyCategory string

const (
	PolicyCategoryAccess       PolicyCategory = "access"
	PolicyCategoryEncryption   PolicyCategory = "encryption"
	PolicyCategoryAudit        PolicyCategory = "audit"
	PolicyCategoryNetwork      PolicyCategory = "network"
	PolicyCategoryCompliance   PolicyCategory = "compliance"
)

type EnforcementLevel string

const (
	EnforcementLevelAdvisory   EnforcementLevel = "advisory"
	EnforcementLevelWarning    EnforcementLevel = "warning"
	EnforcementLevelEnforcing  EnforcementLevel = "enforcing"
	EnforcementLevelBlocking   EnforcementLevel = "blocking"
)// Addit
ional types for security components

type CVSSScore struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
}

type ScanSummary struct {
	TotalFindings    int                       `json:"total_findings"`
	FindingsBySeverity map[SeverityLevel]int   `json:"findings_by_severity"`
	FindingsByType   map[FindingType]int       `json:"findings_by_type"`
	RiskScore        float64                   `json:"risk_score"`
}

type ReportPeriod struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

type ComplianceControl struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Status      ComplianceStatus `json:"status"`
	Score       float64          `json:"score"`
	Evidence    []string         `json:"evidence"`
	Gaps        []string         `json:"gaps"`
}

type ComplianceRecommendation struct {
	ID          string         `json:"id"`
	Priority    SeverityLevel  `json:"priority"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Actions     []string       `json:"actions"`
	Timeline    string         `json:"timeline"`
}

type ComplianceEvidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
	Data        string    `json:"data"`
}

type PolicyRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Condition   string                 `json:"condition"`
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	Enabled     bool                   `json:"enabled"`
}

type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors"`
	Score   float64  `json:"score"`
	Details string   `json:"details"`
}

type ConfigScanResult struct {
	*ScanResult
	ConfigFiles []*ConfigFileResult `json:"config_files"`
}

type ConfigFileResult struct {
	Path     string              `json:"path"`
	Issues   []*SecurityFinding  `json:"issues"`
	Score    float64             `json:"score"`
}

type CertScanResult struct {
	*ScanResult
	Certificates []*CertificateResult `json:"certificates"`
}

type CertificateResult struct {
	Subject    string              `json:"subject"`
	Issuer     string              `json:"issuer"`
	ExpiresAt  time.Time           `json:"expires_at"`
	Issues     []*SecurityFinding  `json:"issues"`
	Valid      bool                `json:"valid"`
}

type DependencyScanResult struct {
	*ScanResult
	Dependencies []*DependencyResult `json:"dependencies"`
}

type DependencyResult struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Vulnerabilities []*SecurityFinding  `json:"vulnerabilities"`
	License         string              `json:"license"`
	RiskScore       float64             `json:"risk_score"`
}