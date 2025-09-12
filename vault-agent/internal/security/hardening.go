package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// SecurityHardening implements security hardening measures
type SecurityHardening struct {
	config *HardeningConfig
}

// HardeningConfig contains security hardening configuration
type HardeningConfig struct {
	EnableFilePermissionChecks bool
	EnableNetworkSecurityChecks bool
	EnableProcessSecurityChecks bool
	EnableTLSHardening bool
	MinTLSVersion uint16
	AllowedCipherSuites []uint16
	RequireMTLS bool
}

// NewSecurityHardening creates a new security hardening instance
func NewSecurityHardening(config *HardeningConfig) *SecurityHardening {
	if config == nil {
		config = &HardeningConfig{
			EnableFilePermissionChecks: true,
			EnableNetworkSecurityChecks: true,
			EnableProcessSecurityChecks: true,
			EnableTLSHardening: true,
			MinTLSVersion: tls.VersionTLS13,
			RequireMTLS: true,
		}
	}
	return &SecurityHardening{config: config}
}

// ApplyHardening applies all security hardening measures
func (sh *SecurityHardening) ApplyHardening(ctx context.Context) error {
	if err := sh.hardenFilePermissions(); err != nil {
		return fmt.Errorf("file permission hardening failed: %w", err)
	}

	if err := sh.hardenNetworkSecurity(); err != nil {
		return fmt.Errorf("network security hardening failed: %w", err)
	}

	if err := sh.hardenProcessSecurity(); err != nil {
		return fmt.Errorf("process security hardening failed: %w", err)
	}

	return nil
}

// hardenFilePermissions ensures secure file permissions
func (sh *SecurityHardening) hardenFilePermissions() error {
	if !sh.config.EnableFilePermissionChecks {
		return nil
	}

	// Check and fix permissions for sensitive directories
	sensitiveDirectories := []string{
		"/data",
		"/config",
		"/logs",
		"/certs",
	}

	for _, dir := range sensitiveDirectories {
		if err := sh.secureDirectory(dir); err != nil {
			return fmt.Errorf("failed to secure directory %s: %w", dir, err)
		}
	}

	return nil
}

// secureDirectory sets secure permissions on a directory
func (sh *SecurityHardening) secureDirectory(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // Directory doesn't exist, skip
	}

	// Set directory permissions to 700 (owner read/write/execute only)
	if err := os.Chmod(path, 0700); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}

	// Walk through directory and secure all files
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return os.Chmod(filePath, 0700)
		}

		// Set file permissions to 600 (owner read/write only)
		return os.Chmod(filePath, 0600)
	})
}

// hardenNetworkSecurity applies network security hardening
func (sh *SecurityHardening) hardenNetworkSecurity() error {
	if !sh.config.EnableNetworkSecurityChecks {
		return nil
	}

	// Check for open ports that shouldn't be exposed
	if err := sh.checkOpenPorts(); err != nil {
		return fmt.Errorf("network port check failed: %w", err)
	}

	return nil
}

// checkOpenPorts verifies only necessary ports are open
func (sh *SecurityHardening) checkOpenPorts() error {
	allowedPorts := map[int]bool{
		8080: true, // Vault agent API
		8443: true, // Vault agent HTTPS
		9090: true, // Metrics
	}

	// Check common ports that should not be open
	dangerousPorts := []int{22, 23, 21, 25, 53, 80, 135, 139, 445, 993, 995}

	for _, port := range dangerousPorts {
		if allowedPorts[port] {
			continue
		}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), time.Second)
		if err == nil {
			conn.Close()
			return fmt.Errorf("dangerous port %d is open and accessible", port)
		}
	}

	return nil
}

// hardenProcessSecurity applies process-level security hardening
func (sh *SecurityHardening) hardenProcessSecurity() error {
	if !sh.config.EnableProcessSecurityChecks {
		return nil
	}

	// Set process limits
	if err := sh.setResourceLimits(); err != nil {
		return fmt.Errorf("failed to set resource limits: %w", err)
	}

	// Drop unnecessary capabilities (Linux only)
	if err := sh.dropCapabilities(); err != nil {
		return fmt.Errorf("failed to drop capabilities: %w", err)
	}

	return nil
}

// setResourceLimits sets secure resource limits for the process
func (sh *SecurityHardening) setResourceLimits() error {
	limits := []struct {
		resource int
		limit    uint64
	}{
		{syscall.RLIMIT_NOFILE, 65536},    // Max open files
		{syscall.RLIMIT_NPROC, 32768},     // Max processes
		{syscall.RLIMIT_AS, 2 << 30},      // Max virtual memory (2GB)
		{syscall.RLIMIT_CORE, 0},          // Disable core dumps
	}

	for _, l := range limits {
		rlimit := &syscall.Rlimit{
			Cur: l.limit,
			Max: l.limit,
		}
		if err := syscall.Setrlimit(l.resource, rlimit); err != nil {
			return fmt.Errorf("failed to set resource limit %d: %w", l.resource, err)
		}
	}

	return nil
}

// dropCapabilities drops unnecessary Linux capabilities
func (sh *SecurityHardening) dropCapabilities() error {
	// This would require CGO and Linux-specific capability libraries
	// For now, we'll just log that capabilities should be dropped
	// In a real implementation, you'd use libraries like:
	// - github.com/syndtr/gocapability/capability
	// - kernel.org/pub/linux/libs/security/libcap/cap
	
	return nil
}

// GetTLSConfig returns a hardened TLS configuration
func (sh *SecurityHardening) GetTLSConfig() *tls.Config {
	if !sh.config.EnableTLSHardening {
		return &tls.Config{}
	}

	config := &tls.Config{
		MinVersion: sh.config.MinTLSVersion,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		InsecureSkipVerify: false,
	}

	if sh.config.RequireMTLS {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config
}

// ValidateSecurityConfiguration validates the current security configuration
func (sh *SecurityHardening) ValidateSecurityConfiguration() []SecurityIssue {
	var issues []SecurityIssue

	// Check file permissions
	if sh.config.EnableFilePermissionChecks {
		issues = append(issues, sh.checkFilePermissions()...)
	}

	// Check network configuration
	if sh.config.EnableNetworkSecurityChecks {
		issues = append(issues, sh.checkNetworkConfiguration()...)
	}

	// Check TLS configuration
	if sh.config.EnableTLSHardening {
		issues = append(issues, sh.checkTLSConfiguration()...)
	}

	return issues
}

// checkFilePermissions validates file permissions
func (sh *SecurityHardening) checkFilePermissions() []SecurityIssue {
	var issues []SecurityIssue

	sensitiveFiles := []string{
		"/config/vault.yaml",
		"/certs/server.key",
		"/certs/client.key",
		"/data/secrets.db",
	}

	for _, file := range sensitiveFiles {
		if info, err := os.Stat(file); err == nil {
			mode := info.Mode()
			if mode&0077 != 0 { // Check if group/other have any permissions
				issues = append(issues, SecurityIssue{
					Type:        "file_permissions",
					Severity:    "high",
					Description: fmt.Sprintf("File %s has overly permissive permissions: %o", file, mode),
					Remediation: fmt.Sprintf("chmod 600 %s", file),
				})
			}
		}
	}

	return issues
}

// checkNetworkConfiguration validates network security
func (sh *SecurityHardening) checkNetworkConfiguration() []SecurityIssue {
	var issues []SecurityIssue

	// Check for insecure network bindings
	insecureBindings := []string{
		"0.0.0.0:8080",
		"*:8080",
		"[::]8080",
	}

	for _, binding := range insecureBindings {
		if sh.isPortBound(binding) {
			issues = append(issues, SecurityIssue{
				Type:        "network_binding",
				Severity:    "medium",
				Description: fmt.Sprintf("Service bound to insecure address: %s", binding),
				Remediation: "Bind to specific interfaces or use localhost",
			})
		}
	}

	return issues
}

// checkTLSConfiguration validates TLS security
func (sh *SecurityHardening) checkTLSConfiguration() []SecurityIssue {
	var issues []SecurityIssue

	if sh.config.MinTLSVersion < tls.VersionTLS12 {
		issues = append(issues, SecurityIssue{
			Type:        "tls_version",
			Severity:    "high",
			Description: "TLS version below 1.2 is not secure",
			Remediation: "Set minimum TLS version to 1.2 or higher",
		})
	}

	if !sh.config.RequireMTLS {
		issues = append(issues, SecurityIssue{
			Type:        "mtls",
			Severity:    "medium",
			Description: "Mutual TLS is not required",
			Remediation: "Enable mutual TLS authentication",
		})
	}

	return issues
}

// isPortBound checks if a port is bound to the given address
func (sh *SecurityHardening) isPortBound(address string) bool {
	conn, err := net.Dial("tcp", address)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

// SecurityIssue represents a security configuration issue
type SecurityIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// GenerateSecurityReport generates a comprehensive security report
func (sh *SecurityHardening) GenerateSecurityReport() *SecurityReport {
	issues := sh.ValidateSecurityConfiguration()
	
	report := &SecurityReport{
		Timestamp: time.Now(),
		Issues:    issues,
		Summary: SecuritySummary{
			TotalIssues:  len(issues),
			HighSeverity: countIssuesBySeverity(issues, "high"),
			MediumSeverity: countIssuesBySeverity(issues, "medium"),
			LowSeverity:  countIssuesBySeverity(issues, "low"),
		},
		Recommendations: sh.generateRecommendations(issues),
	}

	return report
}

// SecurityReport contains the results of a security assessment
type SecurityReport struct {
	Timestamp       time.Time         `json:"timestamp"`
	Issues          []SecurityIssue   `json:"issues"`
	Summary         SecuritySummary   `json:"summary"`
	Recommendations []string          `json:"recommendations"`
}

// SecuritySummary provides a summary of security issues
type SecuritySummary struct {
	TotalIssues    int `json:"total_issues"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
}

// countIssuesBySeverity counts issues by severity level
func countIssuesBySeverity(issues []SecurityIssue, severity string) int {
	count := 0
	for _, issue := range issues {
		if strings.EqualFold(issue.Severity, severity) {
			count++
		}
	}
	return count
}

// generateRecommendations generates security recommendations based on issues
func (sh *SecurityHardening) generateRecommendations(issues []SecurityIssue) []string {
	recommendations := []string{
		"Regularly update the vault agent to the latest version",
		"Monitor security logs for suspicious activity",
		"Implement network segmentation and firewall rules",
		"Use strong, unique passwords for all accounts",
		"Enable two-factor authentication where possible",
		"Regularly backup configuration and audit logs",
		"Conduct periodic security assessments",
		"Train staff on security best practices",
	}

	// Add specific recommendations based on found issues
	for _, issue := range issues {
		if issue.Remediation != "" {
			recommendations = append(recommendations, issue.Remediation)
		}
	}

	return recommendations
}
