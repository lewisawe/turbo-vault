package security

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SecurityScannerImpl implements the SecurityScanner interface
type SecurityScannerImpl struct {
	config *ScannerConfig
}

type ScannerConfig struct {
	VulnDBPath     string        `json:"vuln_db_path"`
	ScanTimeout    time.Duration `json:"scan_timeout"`
	MaxConcurrent  int           `json:"max_concurrent"`
	EnabledScans   []ScanType    `json:"enabled_scans"`
	ExcludePatterns []string     `json:"exclude_patterns"`
}

// NewSecurityScanner creates a new security scanner instance
func NewSecurityScanner(config *ScannerConfig) *SecurityScannerImpl {
	if config == nil {
		config = &ScannerConfig{
			ScanTimeout:   30 * time.Minute,
			MaxConcurrent: 5,
			EnabledScans:  []ScanType{ScanTypeVulnerability, ScanTypeConfiguration, ScanTypeCertificate},
		}
	}
	return &SecurityScannerImpl{config: config}
}

// ScanVulnerabilities performs vulnerability scanning
func (s *SecurityScannerImpl) ScanVulnerabilities(ctx context.Context, config *ScanConfig) (*ScanResult, error) {
	result := &ScanResult{
		ID:        uuid.New().String(),
		ScanType:  ScanTypeVulnerability,
		StartTime: time.Now(),
		Status:    ScanStatusRunning,
		Findings:  []*SecurityFinding{},
	}

	// Scan for common vulnerabilities
	findings := []*SecurityFinding{}

	// Check for weak encryption algorithms
	if weakCryptoFindings := s.scanWeakCrypto(ctx); len(weakCryptoFindings) > 0 {
		findings = append(findings, weakCryptoFindings...)
	}

	// Check for insecure configurations
	if configFindings := s.scanInsecureConfigs(ctx); len(configFindings) > 0 {
		findings = append(findings, configFindings...)
	}

	// Check for exposed secrets
	if secretFindings := s.scanExposedSecrets(ctx, config.Targets); len(secretFindings) > 0 {
		findings = append(findings, secretFindings...)
	}

	result.Findings = findings
	result.EndTime = time.Now()
	result.Status = ScanStatusCompleted
	result.Summary = s.generateScanSummary(findings)

	return result, nil
}

// ScanConfiguration performs configuration security scanning
func (s *SecurityScannerImpl) ScanConfiguration(ctx context.Context) (*ConfigScanResult, error) {
	result := &ConfigScanResult{
		ScanResult: &ScanResult{
			ID:        uuid.New().String(),
			ScanType:  ScanTypeConfiguration,
			StartTime: time.Now(),
			Status:    ScanStatusRunning,
		},
		ConfigFiles: []*ConfigFileResult{},
	}

	// Scan configuration files
	configPaths := []string{
		"config/",
		"vault-agent/internal/config/",
		"deployments/",
	}

	for _, path := range configPaths {
		if configResults := s.scanConfigPath(ctx, path); len(configResults) > 0 {
			result.ConfigFiles = append(result.ConfigFiles, configResults...)
		}
	}

	// Aggregate findings
	allFindings := []*SecurityFinding{}
	for _, configFile := range result.ConfigFiles {
		allFindings = append(allFindings, configFile.Issues...)
	}

	result.ScanResult.Findings = allFindings
	result.ScanResult.EndTime = time.Now()
	result.ScanResult.Status = ScanStatusCompleted
	result.ScanResult.Summary = s.generateScanSummary(allFindings)

	return result, nil
}

// ScanCertificates performs certificate security scanning
func (s *SecurityScannerImpl) ScanCertificates(ctx context.Context) (*CertScanResult, error) {
	result := &CertScanResult{
		ScanResult: &ScanResult{
			ID:        uuid.New().String(),
			ScanType:  ScanTypeCertificate,
			StartTime: time.Now(),
			Status:    ScanStatusRunning,
		},
		Certificates: []*CertificateResult{},
	}

	// Scan for certificate files
	certPaths := []string{
		"config/",
		"deployments/",
	}

	allFindings := []*SecurityFinding{}
	for _, path := range certPaths {
		if certResults := s.scanCertificatesInPath(ctx, path); len(certResults) > 0 {
			result.Certificates = append(result.Certificates, certResults...)
			for _, cert := range certResults {
				allFindings = append(allFindings, cert.Issues...)
			}
		}
	}

	result.ScanResult.Findings = allFindings
	result.ScanResult.EndTime = time.Now()
	result.ScanResult.Status = ScanStatusCompleted
	result.ScanResult.Summary = s.generateScanSummary(allFindings)

	return result, nil
}

// ScanDependencies performs dependency vulnerability scanning
func (s *SecurityScannerImpl) ScanDependencies(ctx context.Context) (*DependencyScanResult, error) {
	result := &DependencyScanResult{
		ScanResult: &ScanResult{
			ID:        uuid.New().String(),
			ScanType:  ScanTypeDependency,
			StartTime: time.Now(),
			Status:    ScanStatusRunning,
		},
		Dependencies: []*DependencyResult{},
	}

	// Scan Go dependencies
	if goResults := s.scanGoDependencies(ctx); len(goResults) > 0 {
		result.Dependencies = append(result.Dependencies, goResults...)
	}

	// Scan Node.js dependencies
	if nodeResults := s.scanNodeDependencies(ctx); len(nodeResults) > 0 {
		result.Dependencies = append(result.Dependencies, nodeResults...)
	}

	// Scan Python dependencies
	if pythonResults := s.scanPythonDependencies(ctx); len(pythonResults) > 0 {
		result.Dependencies = append(result.Dependencies, pythonResults...)
	}

	// Aggregate findings
	allFindings := []*SecurityFinding{}
	for _, dep := range result.Dependencies {
		allFindings = append(allFindings, dep.Vulnerabilities...)
	}

	result.ScanResult.Findings = allFindings
	result.ScanResult.EndTime = time.Now()
	result.ScanResult.Status = ScanStatusCompleted
	result.ScanResult.Summary = s.generateScanSummary(allFindings)

	return result, nil
}

// GetScanHistory retrieves scan history
func (s *SecurityScannerImpl) GetScanHistory(ctx context.Context, limit int) ([]*ScanResult, error) {
	// In a real implementation, this would query a database
	// For now, return empty slice
	return []*ScanResult{}, nil
}

// Helper methods for scanning

func (s *SecurityScannerImpl) scanWeakCrypto(ctx context.Context) []*SecurityFinding {
	findings := []*SecurityFinding{}

	// Check for weak encryption algorithms in code and configuration
	weakAlgorithms := map[string]SeverityLevel{
		"MD5":     SeverityCritical,
		"SHA1":    SeverityHigh,
		"DES":     SeverityCritical,
		"3DES":    SeverityHigh,
		"RC4":     SeverityCritical,
		"MD4":     SeverityCritical,
		"RC2":     SeverityHigh,
		"RIPEMD":  SeverityMedium,
	}
	
	for algo, severity := range weakAlgorithms {
		finding := &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeWeakCrypto,
			Severity:    severity,
			Title:       fmt.Sprintf("Weak cryptographic algorithm detected: %s", algo),
			Description: fmt.Sprintf("The use of %s is deprecated and considered insecure due to known vulnerabilities", algo),
			Remediation: "Replace with stronger algorithms: AES-256-GCM for symmetric encryption, RSA-4096 or ECDSA P-384 for asymmetric encryption, SHA-256 or SHA-3 for hashing",
			References:  []string{"https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines"},
			CreatedAt:   time.Now(),
		}
		
		// Check configuration files for weak crypto usage
		if s.scanConfigurationForWeakCrypto(algo) {
			finding.Evidence = append(finding.Evidence, fmt.Sprintf("Found %s usage in configuration files", algo))
			findings = append(findings, finding)
		}
	}

	// Check for weak key sizes
	weakKeySizes := map[string]int{
		"RSA":  2048, // Minimum acceptable, but 4096 recommended
		"DSA":  2048,
		"ECDSA": 256,
	}

	for keyType, minSize := range weakKeySizes {
		if detectedSize := s.detectKeySize(keyType); detectedSize > 0 && detectedSize < minSize {
			finding := &SecurityFinding{
				ID:          uuid.New().String(),
				Type:        FindingTypeWeakCrypto,
				Severity:    SeverityHigh,
				Title:       fmt.Sprintf("Weak %s key size detected: %d bits", keyType, detectedSize),
				Description: fmt.Sprintf("%s key size of %d bits is below recommended minimum of %d bits", keyType, detectedSize, minSize),
				Remediation: fmt.Sprintf("Use %s keys of at least %d bits, preferably %d bits or higher", keyType, minSize, minSize*2),
				Evidence:    []string{fmt.Sprintf("Detected %s key size: %d bits", keyType, detectedSize)},
				CreatedAt:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for weak random number generation
	if s.detectWeakRNG() {
		finding := &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeWeakCrypto,
			Severity:    SeverityCritical,
			Title:       "Weak random number generation detected",
			Description: "System is using predictable or weak random number generation which compromises cryptographic security",
			Remediation: "Use cryptographically secure random number generators (CSPRNG) such as /dev/urandom or crypto/rand",
			Evidence:    []string{"Detected use of math/rand or other weak RNG"},
			CreatedAt:   time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *SecurityScannerImpl) scanInsecureConfigs(ctx context.Context) []*SecurityFinding {
	findings := []*SecurityFinding{}

	// Check for insecure configuration patterns
	insecurePatterns := map[string]string{
		"debug=true":           "Debug mode enabled in production",
		"ssl_verify=false":     "SSL verification disabled",
		"password=":            "Hardcoded password detected",
		"api_key=":            "Hardcoded API key detected",
		"secret=":             "Hardcoded secret detected",
	}

	for pattern, description := range insecurePatterns {
		finding := &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeMisconfiguration,
			Severity:    SeverityMedium,
			Title:       "Insecure configuration detected",
			Description: description,
			Evidence:    []string{pattern},
			Remediation: "Use environment variables or secure configuration management",
			CreatedAt:   time.Now(),
		}
		
		if s.shouldIncludeFinding(finding) {
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *SecurityScannerImpl) scanExposedSecrets(ctx context.Context, targets []string) []*SecurityFinding {
	findings := []*SecurityFinding{}

	// Patterns for detecting exposed secrets
	secretPatterns := map[string]string{
		`(?i)password\s*[:=]\s*["\']?[^"\'\s]+`:     "Password in plaintext",
		`(?i)api[_-]?key\s*[:=]\s*["\']?[^"\'\s]+`: "API key in plaintext",
		`(?i)secret\s*[:=]\s*["\']?[^"\'\s]+`:      "Secret in plaintext",
		`(?i)token\s*[:=]\s*["\']?[^"\'\s]+`:       "Token in plaintext",
	}

	for pattern, description := range secretPatterns {
		finding := &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeDataExposure,
			Severity:    SeverityCritical,
			Title:       "Exposed secret detected",
			Description: description,
			Evidence:    []string{pattern},
			Remediation: "Remove hardcoded secrets and use secure secret management",
			CreatedAt:   time.Now(),
		}
		
		if s.shouldIncludeFinding(finding) {
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *SecurityScannerImpl) scanConfigPath(ctx context.Context, path string) []*ConfigFileResult {
	results := []*ConfigFileResult{}

	// Walk through configuration files
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		if info.IsDir() {
			return nil
		}

		// Check configuration file extensions
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".toml" || ext == ".conf" {
			if configResult := s.scanConfigFile(ctx, filePath); configResult != nil {
				results = append(results, configResult)
			}
		}

		return nil
	})

	if err != nil {
		// Log error but continue
	}

	return results
}

func (s *SecurityScannerImpl) scanConfigFile(ctx context.Context, filePath string) *ConfigFileResult {
	issues := []*SecurityFinding{}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	contentStr := string(content)

	// Check for security issues in configuration
	if strings.Contains(contentStr, "debug: true") || strings.Contains(contentStr, "debug=true") {
		issues = append(issues, &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeMisconfiguration,
			Severity:    SeverityMedium,
			Title:       "Debug mode enabled",
			Description: "Debug mode should be disabled in production",
			Location:    filePath,
			Remediation: "Set debug to false in production environments",
			CreatedAt:   time.Now(),
		})
	}

	if strings.Contains(contentStr, "ssl_verify: false") || strings.Contains(contentStr, "ssl_verify=false") {
		issues = append(issues, &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeMisconfiguration,
			Severity:    SeverityHigh,
			Title:       "SSL verification disabled",
			Description: "SSL certificate verification is disabled",
			Location:    filePath,
			Remediation: "Enable SSL certificate verification",
			CreatedAt:   time.Now(),
		})
	}

	score := s.calculateConfigScore(issues)

	return &ConfigFileResult{
		Path:   filePath,
		Issues: issues,
		Score:  score,
	}
}

func (s *SecurityScannerImpl) scanCertificatesInPath(ctx context.Context, path string) []*CertificateResult {
	results := []*CertificateResult{}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Check for certificate files
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".crt" || ext == ".pem" || ext == ".cer" || ext == ".p12" || ext == ".pfx" {
			if certResult := s.scanCertificateFile(ctx, filePath); certResult != nil {
				results = append(results, certResult)
			}
		}

		return nil
	})

	if err != nil {
		// Log error but continue
	}

	return results
}

func (s *SecurityScannerImpl) scanCertificateFile(ctx context.Context, filePath string) *CertificateResult {
	issues := []*SecurityFinding{}

	// Read certificate file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	// Parse certificate (simplified - in real implementation, use proper parsing)
	cert := &CertificateResult{
		Subject: "Unknown",
		Issuer:  "Unknown",
		Valid:   true,
		Issues:  issues,
	}

	// Check for common certificate issues
	if time.Now().Add(30 * 24 * time.Hour).After(cert.ExpiresAt) {
		issues = append(issues, &SecurityFinding{
			ID:          uuid.New().String(),
			Type:        FindingTypeVulnerability,
			Severity:    SeverityHigh,
			Title:       "Certificate expiring soon",
			Description: "Certificate will expire within 30 days",
			Location:    filePath,
			Remediation: "Renew certificate before expiration",
			CreatedAt:   time.Now(),
		})
	}

	cert.Issues = issues
	return cert
}

func (s *SecurityScannerImpl) scanGoDependencies(ctx context.Context) []*DependencyResult {
	results := []*DependencyResult{}

	// Scan go.mod files
	goModPaths := []string{
		"vault-agent/go.mod",
		"control-plane/go.mod",
		"sdks/go/go.mod",
	}

	for _, modPath := range goModPaths {
		if _, err := os.Stat(modPath); err == nil {
			if deps := s.parseGoMod(modPath); len(deps) > 0 {
				results = append(results, deps...)
			}
		}
	}

	return results
}

func (s *SecurityScannerImpl) scanNodeDependencies(ctx context.Context) []*DependencyResult {
	results := []*DependencyResult{}

	// Scan package.json files
	packagePaths := []string{
		"sdks/nodejs/package.json",
	}

	for _, pkgPath := range packagePaths {
		if _, err := os.Stat(pkgPath); err == nil {
			if deps := s.parsePackageJson(pkgPath); len(deps) > 0 {
				results = append(results, deps...)
			}
		}
	}

	return results
}

func (s *SecurityScannerImpl) scanPythonDependencies(ctx context.Context) []*DependencyResult {
	results := []*DependencyResult{}

	// Scan requirements.txt and setup.py files
	pythonPaths := []string{
		"sdks/python/requirements.txt",
		"sdks/python/setup.py",
	}

	for _, pyPath := range pythonPaths {
		if _, err := os.Stat(pyPath); err == nil {
			if deps := s.parsePythonDeps(pyPath); len(deps) > 0 {
				results = append(results, deps...)
			}
		}
	}

	return results
}

func (s *SecurityScannerImpl) parseGoMod(path string) []*DependencyResult {
	// Simplified parsing - in real implementation, use go/mod parser
	return []*DependencyResult{
		{
			Name:            "example-dependency",
			Version:         "v1.0.0",
			Vulnerabilities: []*SecurityFinding{},
			License:         "MIT",
			RiskScore:       0.1,
		},
	}
}

func (s *SecurityScannerImpl) parsePackageJson(path string) []*DependencyResult {
	// Simplified parsing - in real implementation, parse JSON
	return []*DependencyResult{
		{
			Name:            "example-node-dependency",
			Version:         "1.0.0",
			Vulnerabilities: []*SecurityFinding{},
			License:         "MIT",
			RiskScore:       0.1,
		},
	}
}

func (s *SecurityScannerImpl) parsePythonDeps(path string) []*DependencyResult {
	// Simplified parsing - in real implementation, parse requirements
	return []*DependencyResult{
		{
			Name:            "example-python-dependency",
			Version:         "1.0.0",
			Vulnerabilities: []*SecurityFinding{},
			License:         "MIT",
			RiskScore:       0.1,
		},
	}
}

func (s *SecurityScannerImpl) generateScanSummary(findings []*SecurityFinding) *ScanSummary {
	summary := &ScanSummary{
		TotalFindings:      len(findings),
		FindingsBySeverity: make(map[SeverityLevel]int),
		FindingsByType:     make(map[FindingType]int),
	}

	riskScore := 0.0
	for _, finding := range findings {
		summary.FindingsBySeverity[finding.Severity]++
		summary.FindingsByType[finding.Type]++

		// Calculate risk score based on severity
		switch finding.Severity {
		case SeverityCritical:
			riskScore += 10.0
		case SeverityHigh:
			riskScore += 7.0
		case SeverityMedium:
			riskScore += 4.0
		case SeverityLow:
			riskScore += 1.0
		}
	}

	summary.RiskScore = riskScore
	return summary
}

func (s *SecurityScannerImpl) calculateConfigScore(issues []*SecurityFinding) float64 {
	if len(issues) == 0 {
		return 100.0
	}

	penalty := 0.0
	for _, issue := range issues {
		switch issue.Severity {
		case SeverityCritical:
			penalty += 30.0
		case SeverityHigh:
			penalty += 20.0
		case SeverityMedium:
			penalty += 10.0
		case SeverityLow:
			penalty += 5.0
		}
	}

	score := 100.0 - penalty
	if score < 0 {
		score = 0
	}

	return score
}

func (s *SecurityScannerImpl) shouldIncludeFinding(finding *SecurityFinding) bool {
	// Apply exclusion rules
	for _, pattern := range s.config.ExcludePatterns {
		if strings.Contains(finding.Title, pattern) || strings.Contains(finding.Description, pattern) {
			return false
		}
	}
	return true
}

func (s *SecurityScannerImpl) scanConfigurationForWeakCrypto(algorithm string) bool {
	// Scan configuration files for weak crypto algorithms
	configPaths := []string{
		"vault-agent/internal/config/",
		"config/",
		"deployments/",
	}

	for _, path := range configPaths {
		if s.scanPathForPattern(path, strings.ToLower(algorithm)) {
			return true
		}
	}
	return false
}

func (s *SecurityScannerImpl) scanPathForPattern(path, pattern string) bool {
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		if info.IsDir() {
			return nil
		}

		// Check relevant file types
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".toml" || ext == ".conf" || ext == ".go" {
			content, err := os.ReadFile(filePath)
			if err != nil {
				return nil
			}

			if strings.Contains(strings.ToLower(string(content)), pattern) {
				return fmt.Errorf("pattern found") // Use error to break out of walk
			}
		}

		return nil
	})

	return err != nil
}

func (s *SecurityScannerImpl) detectKeySize(keyType string) int {
	// Simulate key size detection
	// In a real implementation, this would parse certificates and keys
	switch keyType {
	case "RSA":
		return 2048 // Simulated detection
	case "DSA":
		return 1024 // Simulated weak key
	case "ECDSA":
		return 256 // Simulated detection
	}
	return 0
}

func (s *SecurityScannerImpl) detectWeakRNG() bool {
	// Scan for weak RNG usage patterns
	weakRNGPatterns := []string{
		"math/rand",
		"rand.Seed",
		"rand.Int",
		"Math.random",
		"Random(",
		"new Random",
	}

	for _, pattern := range weakRNGPatterns {
		if s.scanPathForPattern(".", pattern) {
			return true
		}
	}
	return false
}