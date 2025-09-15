package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SecurityManager orchestrates all security hardening and compliance features
type SecurityManager struct {
	config            *ManagerConfig
	hardening         *SecurityHardening
	scanner           *VulnerabilityScanner
	testSuite         *SecurityTestSuite
	complianceManager *ComplianceManager
	policyManager     *PolicyManager
}

// ManagerConfig contains security manager configuration
type ManagerConfig struct {
	EnableHardening     bool
	EnableScanning      bool
	EnableTesting       bool
	EnableCompliance    bool
	ReportDirectory     string
	ScanInterval        time.Duration
	TestInterval        time.Duration
	ComplianceStandards []string
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *ManagerConfig) *SecurityManager {
	if config == nil {
		config = &ManagerConfig{
			EnableHardening:     true,
			EnableScanning:      true,
			EnableTesting:       true,
			EnableCompliance:    true,
			ReportDirectory:     "./security-reports",
			ScanInterval:        24 * time.Hour,
			TestInterval:        7 * 24 * time.Hour,
			ComplianceStandards: []string{"SOC2", "ISO27001", "PCI-DSS"},
		}
	}

	// Ensure report directory exists
	os.MkdirAll(config.ReportDirectory, 0755)

	return &SecurityManager{
		config:            config,
		hardening:         NewSecurityHardening(nil),
		scanner:           NewVulnerabilityScanner(nil),
		testSuite:         NewSecurityTestSuite(nil),
		complianceManager: NewComplianceManager(nil),
		policyManager:     NewPolicyManager(nil),
	}
}

// SecurityStatus represents the overall security status
type SecurityStatus struct {
	Timestamp           time.Time                `json:"timestamp"`
	OverallScore        int                      `json:"overall_score"`
	SecurityLevel       string                   `json:"security_level"`
	HardeningStatus     *HardeningStatus         `json:"hardening_status"`
	VulnerabilityStatus *VulnerabilityStatus     `json:"vulnerability_status"`
	ComplianceStatus    *ComplianceStatus        `json:"compliance_status"`
	TestStatus          *TestStatus              `json:"test_status"`
	Recommendations     []string                 `json:"recommendations"`
	LastScan            time.Time                `json:"last_scan"`
	LastTest            time.Time                `json:"last_test"`
	NextScheduledScan   time.Time                `json:"next_scheduled_scan"`
	NextScheduledTest   time.Time                `json:"next_scheduled_test"`
}

// HardeningStatus represents security hardening status
type HardeningStatus struct {
	Applied       bool              `json:"applied"`
	Issues        []SecurityIssue   `json:"issues"`
	LastApplied   time.Time         `json:"last_applied"`
	Configuration *HardeningConfig  `json:"configuration"`
}

// VulnerabilityStatus represents vulnerability scan status
type VulnerabilityStatus struct {
	LastScan        time.Time    `json:"last_scan"`
	TotalVulns      int          `json:"total_vulnerabilities"`
	CriticalVulns   int          `json:"critical_vulnerabilities"`
	HighVulns       int          `json:"high_vulnerabilities"`
	MediumVulns     int          `json:"medium_vulnerabilities"`
	LowVulns        int          `json:"low_vulnerabilities"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus struct {
	Standards       []string          `json:"standards"`
	OverallScore    int               `json:"overall_score"`
	ComplianceLevel string            `json:"compliance_level"`
	LastAssessment  time.Time         `json:"last_assessment"`
	Issues          []ComplianceIssue `json:"issues"`
}

// TestStatus represents security test status
type TestStatus struct {
	LastTest     time.Time `json:"last_test"`
	TotalTests   int       `json:"total_tests"`
	PassedTests  int       `json:"passed_tests"`
	FailedTests  int       `json:"failed_tests"`
	WarningTests int       `json:"warning_tests"`
	TestDuration time.Duration `json:"test_duration"`
}

// Initialize initializes the security manager
func (sm *SecurityManager) Initialize(ctx context.Context) error {
	// Apply security hardening
	if sm.config.EnableHardening {
		if err := sm.hardening.ApplyHardening(ctx); err != nil {
			return fmt.Errorf("failed to apply security hardening: %w", err)
		}
	}

	// Load security policies
	if err := sm.policyManager.LoadPolicies(ctx); err != nil {
		return fmt.Errorf("failed to load security policies: %w", err)
	}

	// Start background tasks
	go sm.startBackgroundTasks(ctx)

	return nil
}

// GetSecurityStatus returns the current security status
func (sm *SecurityManager) GetSecurityStatus(ctx context.Context) (*SecurityStatus, error) {
	status := &SecurityStatus{
		Timestamp: time.Now(),
	}

	// Get hardening status
	if sm.config.EnableHardening {
		issues := sm.hardening.ValidateSecurityConfiguration()
		status.HardeningStatus = &HardeningStatus{
			Applied:     true,
			Issues:      issues,
			LastApplied: time.Now(), // This should be tracked properly
		}
	}

	// Get vulnerability status from last scan
	vulnStatus, err := sm.getLastVulnerabilityStatus()
	if err == nil {
		status.VulnerabilityStatus = vulnStatus
	}

	// Get compliance status
	if sm.config.EnableCompliance {
		compStatus, err := sm.getComplianceStatus(ctx)
		if err == nil {
			status.ComplianceStatus = compStatus
		}
	}

	// Get test status
	testStatus, err := sm.getLastTestStatus()
	if err == nil {
		status.TestStatus = testStatus
	}

	// Calculate overall score and security level
	status.OverallScore = sm.calculateOverallScore(status)
	status.SecurityLevel = sm.determineSecurityLevel(status.OverallScore)
	status.Recommendations = sm.generateRecommendations(status)

	// Set next scheduled activities
	status.NextScheduledScan = time.Now().Add(sm.config.ScanInterval)
	status.NextScheduledTest = time.Now().Add(sm.config.TestInterval)

	return status, nil
}

// PerformSecurityScan performs a comprehensive security scan
func (sm *SecurityManager) PerformSecurityScan(ctx context.Context, targetPath string) error {
	if !sm.config.EnableScanning {
		return nil
	}

	// Perform vulnerability scan
	scanResult, err := sm.scanner.PerformScan(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("vulnerability scan failed: %w", err)
	}

	// Save scan results
	reportPath := filepath.Join(sm.config.ReportDirectory, 
		fmt.Sprintf("vulnerability-scan-%s.json", time.Now().Format("2006-01-02-15-04-05")))
	
	if err := sm.saveScanResults(scanResult, reportPath); err != nil {
		return fmt.Errorf("failed to save scan results: %w", err)
	}

	return nil
}

// PerformSecurityTests performs comprehensive security tests
func (sm *SecurityManager) PerformSecurityTests(ctx context.Context) error {
	if !sm.config.EnableTesting {
		return nil
	}

	// Run security test suite
	testReport, err := sm.testSuite.RunAllTests(ctx)
	if err != nil {
		return fmt.Errorf("security tests failed: %w", err)
	}

	// Save test results
	reportPath := filepath.Join(sm.config.ReportDirectory,
		fmt.Sprintf("security-tests-%s.json", time.Now().Format("2006-01-02-15-04-05")))
	
	if err := sm.saveTestResults(testReport, reportPath); err != nil {
		return fmt.Errorf("failed to save test results: %w", err)
	}

	return nil
}

// PerformComplianceAssessment performs compliance assessment
func (sm *SecurityManager) PerformComplianceAssessment(ctx context.Context) error {
	if !sm.config.EnableCompliance {
		return nil
	}

	for _, standard := range sm.config.ComplianceStandards {
		report, err := sm.complianceManager.GenerateComplianceReport(ctx, standard)
		if err != nil {
			continue // Log error but continue with other standards
		}

		// Save compliance report
		reportPath := filepath.Join(sm.config.ReportDirectory,
			fmt.Sprintf("compliance-%s-%s.json", standard, time.Now().Format("2006-01-02-15-04-05")))
		
		if err := sm.saveComplianceReport(report, reportPath); err != nil {
			continue // Log error but continue
		}
	}

	return nil
}

// GenerateSecurityReport generates a comprehensive security report
func (sm *SecurityManager) GenerateSecurityReport(ctx context.Context) (*SecurityReport, error) {
	status, err := sm.GetSecurityStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security status: %w", err)
	}

	report := &SecurityReport{
		Timestamp:       time.Now(),
		SecurityStatus:  status,
		ExecutiveSummary: sm.generateExecutiveSummary(status),
		DetailedFindings: sm.generateDetailedFindings(status),
		ActionPlan:      sm.generateActionPlan(status),
		Appendices:      sm.generateAppendices(status),
	}

	return report, nil
}

// SecurityReport represents a comprehensive security report
type SecurityReport struct {
	Timestamp        time.Time       `json:"timestamp"`
	SecurityStatus   *SecurityStatus `json:"security_status"`
	ExecutiveSummary string          `json:"executive_summary"`
	DetailedFindings []Finding       `json:"detailed_findings"`
	ActionPlan       []Action        `json:"action_plan"`
	Appendices       []Appendix      `json:"appendices"`
}

// Finding represents a security finding
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Evidence    []string  `json:"evidence"`
	Remediation string    `json:"remediation"`
	References  []string  `json:"references"`
	Timestamp   time.Time `json:"timestamp"`
}

// Action represents a recommended action
type Action struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Priority    string    `json:"priority"`
	Description string    `json:"description"`
	Steps       []string  `json:"steps"`
	Timeline    string    `json:"timeline"`
	Owner       string    `json:"owner"`
	Status      string    `json:"status"`
	DueDate     time.Time `json:"due_date"`
}

// Appendix represents report appendix
type Appendix struct {
	Title   string      `json:"title"`
	Content interface{} `json:"content"`
}

// Helper methods

// startBackgroundTasks starts background security tasks
func (sm *SecurityManager) startBackgroundTasks(ctx context.Context) {
	// Periodic vulnerability scanning
	scanTicker := time.NewTicker(sm.config.ScanInterval)
	defer scanTicker.Stop()

	// Periodic security testing
	testTicker := time.NewTicker(sm.config.TestInterval)
	defer testTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			sm.PerformSecurityScan(ctx, ".")
		case <-testTicker.C:
			sm.PerformSecurityTests(ctx)
		}
	}
}

// calculateOverallScore calculates overall security score
func (sm *SecurityManager) calculateOverallScore(status *SecurityStatus) int {
	score := 100

	// Deduct points for vulnerabilities
	if status.VulnerabilityStatus != nil {
		score -= status.VulnerabilityStatus.CriticalVulns * 20
		score -= status.VulnerabilityStatus.HighVulns * 10
		score -= status.VulnerabilityStatus.MediumVulns * 5
		score -= status.VulnerabilityStatus.LowVulns * 1
	}

	// Deduct points for hardening issues
	if status.HardeningStatus != nil {
		for _, issue := range status.HardeningStatus.Issues {
			switch issue.Severity {
			case "high":
				score -= 10
			case "medium":
				score -= 5
			case "low":
				score -= 2
			}
		}
	}

	// Deduct points for failed tests
	if status.TestStatus != nil && status.TestStatus.TotalTests > 0 {
		failureRate := float64(status.TestStatus.FailedTests) / float64(status.TestStatus.TotalTests)
		score -= int(failureRate * 30)
	}

	if score < 0 {
		score = 0
	}

	return score
}

// determineSecurityLevel determines security level based on score
func (sm *SecurityManager) determineSecurityLevel(score int) string {
	switch {
	case score >= 90:
		return "Excellent"
	case score >= 80:
		return "Good"
	case score >= 70:
		return "Fair"
	case score >= 60:
		return "Poor"
	default:
		return "Critical"
	}
}

// generateRecommendations generates security recommendations
func (sm *SecurityManager) generateRecommendations(status *SecurityStatus) []string {
	var recommendations []string

	if status.VulnerabilityStatus != nil {
		if status.VulnerabilityStatus.CriticalVulns > 0 {
			recommendations = append(recommendations, "Address critical vulnerabilities immediately")
		}
		if status.VulnerabilityStatus.HighVulns > 0 {
			recommendations = append(recommendations, "Prioritize high severity vulnerabilities")
		}
	}

	if status.TestStatus != nil && status.TestStatus.FailedTests > 0 {
		recommendations = append(recommendations, "Review and fix failed security tests")
	}

	if status.HardeningStatus != nil && len(status.HardeningStatus.Issues) > 0 {
		recommendations = append(recommendations, "Apply security hardening recommendations")
	}

	return recommendations
}

// File I/O helper methods

func (sm *SecurityManager) saveScanResults(result *ScanResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (sm *SecurityManager) saveTestResults(report *SecurityTestReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (sm *SecurityManager) saveComplianceReport(report *ComplianceReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (sm *SecurityManager) getLastVulnerabilityStatus() (*VulnerabilityStatus, error) {
	// Implementation would read from last scan results
	return &VulnerabilityStatus{
		LastScan:      time.Now().Add(-24 * time.Hour),
		TotalVulns:    0,
		CriticalVulns: 0,
		HighVulns:     0,
		MediumVulns:   0,
		LowVulns:      0,
		ScanDuration:  5 * time.Minute,
	}, nil
}

func (sm *SecurityManager) getComplianceStatus(ctx context.Context) (*ComplianceStatus, error) {
	// Implementation would get compliance status from compliance manager
	return &ComplianceStatus{
		Standards:       sm.config.ComplianceStandards,
		OverallScore:    85,
		ComplianceLevel: "Good",
		LastAssessment:  time.Now().Add(-7 * 24 * time.Hour),
		Issues:          []ComplianceIssue{},
	}, nil
}

func (sm *SecurityManager) getLastTestStatus() (*TestStatus, error) {
	// Implementation would read from last test results
	return &TestStatus{
		LastTest:     time.Now().Add(-7 * 24 * time.Hour),
		TotalTests:   25,
		PassedTests:  23,
		FailedTests:  1,
		WarningTests: 1,
		TestDuration: 10 * time.Minute,
	}, nil
}

func (sm *SecurityManager) generateExecutiveSummary(status *SecurityStatus) string {
	return fmt.Sprintf("Security assessment completed with overall score of %d (%s). "+
		"System demonstrates %s security posture with %d recommendations for improvement.",
		status.OverallScore, status.SecurityLevel, 
		strings.ToLower(status.SecurityLevel), len(status.Recommendations))
}

func (sm *SecurityManager) generateDetailedFindings(status *SecurityStatus) []Finding {
	var findings []Finding
	
	// Convert various issues to findings
	if status.HardeningStatus != nil {
		for _, issue := range status.HardeningStatus.Issues {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("HARD-%d", len(findings)+1),
				Title:       issue.Description,
				Severity:    issue.Severity,
				Category:    "Security Hardening",
				Description: issue.Description,
				Remediation: issue.Remediation,
				Timestamp:   time.Now(),
			})
		}
	}
	
	return findings
}

func (sm *SecurityManager) generateActionPlan(status *SecurityStatus) []Action {
	var actions []Action
	
	for i, rec := range status.Recommendations {
		actions = append(actions, Action{
			ID:          fmt.Sprintf("ACT-%d", i+1),
			Title:       rec,
			Priority:    "High",
			Description: rec,
			Timeline:    "30 days",
			Status:      "Open",
			DueDate:     time.Now().Add(30 * 24 * time.Hour),
		})
	}
	
	return actions
}

func (sm *SecurityManager) generateAppendices(status *SecurityStatus) []Appendix {
	return []Appendix{
		{
			Title:   "Security Configuration",
			Content: status.HardeningStatus,
		},
		{
			Title:   "Vulnerability Summary",
			Content: status.VulnerabilityStatus,
		},
		{
			Title:   "Test Results",
			Content: status.TestStatus,
		},
	}
}
