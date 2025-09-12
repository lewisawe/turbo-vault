package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/vault-agent/internal/security"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security hardening and compliance operations",
	Long:  `Perform security hardening, vulnerability scanning, compliance assessment, and security testing.`,
}

var hardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Apply security hardening measures",
	Long:  `Apply comprehensive security hardening measures including file permissions, network security, and process security.`,
	RunE:  runHarden,
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Perform vulnerability scan",
	Long:  `Perform comprehensive vulnerability scanning including CVE checks, dependency analysis, and configuration review.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run security tests",
	Long:  `Run comprehensive security test suite including authentication, encryption, input validation, and access control tests.`,
	RunE:  runTest,
}

var complianceCmd = &cobra.Command{
	Use:   "compliance [standard]",
	Short: "Generate compliance report",
	Long:  `Generate compliance reports for various standards including SOC2, ISO27001, and PCI-DSS.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runCompliance,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show security status",
	Long:  `Display comprehensive security status including hardening, vulnerabilities, compliance, and test results.`,
	RunE:  runStatus,
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate security report",
	Long:  `Generate comprehensive security report with executive summary, findings, and action plan.`,
	RunE:  runReport,
}

// Command flags
var (
	outputFormat   string
	outputFile     string
	reportDir      string
	enableAll      bool
	standards      []string
	scanTimeout    time.Duration
	testTimeout    time.Duration
	verbose        bool
)

func init() {
	// Add subcommands
	securityCmd.AddCommand(hardenCmd)
	securityCmd.AddCommand(scanCmd)
	securityCmd.AddCommand(testCmd)
	securityCmd.AddCommand(complianceCmd)
	securityCmd.AddCommand(statusCmd)
	securityCmd.AddCommand(reportCmd)

	// Global flags
	securityCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json, yaml, table)")
	securityCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	securityCmd.PersistentFlags().StringVar(&reportDir, "report-dir", "./security-reports", "Report directory")
	securityCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Harden command flags
	hardenCmd.Flags().BoolVar(&enableAll, "all", true, "Enable all hardening measures")

	// Scan command flags
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 30*time.Minute, "Scan timeout")
	scanCmd.Flags().StringSliceVar(&standards, "standards", []string{"CVE", "OWASP"}, "Scanning standards")

	// Test command flags
	testCmd.Flags().DurationVar(&testTimeout, "timeout", 10*time.Minute, "Test timeout")
	testCmd.Flags().StringSliceVar(&standards, "categories", []string{"auth", "tls", "input", "access", "network"}, "Test categories")

	// Compliance command flags
	complianceCmd.Flags().StringSliceVar(&standards, "standards", []string{"SOC2", "ISO27001", "PCI-DSS"}, "Compliance standards")

	// Add to root command
	rootCmd.AddCommand(securityCmd)
}

func runHarden(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Create security hardening instance
	config := &security.HardeningConfig{
		EnableFilePermissionChecks:  enableAll,
		EnableNetworkSecurityChecks: enableAll,
		EnableProcessSecurityChecks: enableAll,
		EnableTLSHardening:         enableAll,
	}

	hardening := security.NewSecurityHardening(config)

	if verbose {
		fmt.Println("Applying security hardening measures...")
	}

	// Apply hardening
	if err := hardening.ApplyHardening(ctx); err != nil {
		return fmt.Errorf("failed to apply security hardening: %w", err)
	}

	// Validate configuration
	issues := hardening.ValidateSecurityConfiguration()

	// Generate report
	report := hardening.GenerateSecurityReport()

	// Output results
	if err := outputResults(report, "Security Hardening Report"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if len(issues) > 0 {
		fmt.Printf("\nFound %d security issues that need attention:\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("- [%s] %s: %s\n", issue.Severity, issue.Type, issue.Description)
			if verbose && issue.Remediation != "" {
				fmt.Printf("  Remediation: %s\n", issue.Remediation)
			}
		}
	} else {
		fmt.Println("\n✓ All security hardening measures are properly configured")
	}

	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Determine scan target
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	// Create vulnerability scanner
	config := &security.ScannerConfig{
		EnableCVEScanning:     true,
		EnableDependencyCheck: true,
		EnableConfigScanning:  true,
		ScanTimeout:          scanTimeout,
	}

	scanner := security.NewVulnerabilityScanner(config)

	if verbose {
		fmt.Printf("Performing vulnerability scan on %s...\n", targetPath)
	}

	// Perform scan
	result, err := scanner.PerformScan(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("vulnerability scan failed: %w", err)
	}

	// Save detailed report if output file specified
	if outputFile != "" {
		if err := scanner.ExportReport(result, outputFormat, outputFile); err != nil {
			return fmt.Errorf("failed to export report: %w", err)
		}
		fmt.Printf("Detailed report saved to: %s\n", outputFile)
	}

	// Output summary
	if err := outputResults(result, "Vulnerability Scan Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Print summary
	fmt.Printf("\nScan Summary:\n")
	fmt.Printf("- Total Vulnerabilities: %d\n", result.Summary.TotalVulnerabilities)
	fmt.Printf("- Critical: %d, High: %d, Medium: %d, Low: %d\n",
		result.Summary.CriticalCount, result.Summary.HighCount,
		result.Summary.MediumCount, result.Summary.LowCount)
	fmt.Printf("- Dependencies Scanned: %d\n", result.Summary.DependencyCount)
	fmt.Printf("- Configuration Issues: %d\n", result.Summary.ConfigIssueCount)

	if result.Summary.CriticalCount > 0 || result.Summary.HighCount > 0 {
		fmt.Printf("\n⚠️  Critical or high severity vulnerabilities found! Review the detailed report.\n")
		return fmt.Errorf("critical security vulnerabilities detected")
	}

	fmt.Printf("\n✓ No critical vulnerabilities found\n")
	return nil
}

func runTest(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create test suite
	config := &security.TestConfig{
		TargetHost:     "localhost",
		TargetPort:     8080,
		TestTimeout:    testTimeout,
		EnableAllTests: true,
		TestCategories: standards,
	}

	testSuite := security.NewSecurityTestSuite(config)

	if verbose {
		fmt.Println("Running comprehensive security test suite...")
	}

	// Run tests
	report, err := testSuite.RunAllTests(ctx)
	if err != nil {
		return fmt.Errorf("security tests failed: %w", err)
	}

	// Output results
	if err := outputResults(report, "Security Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Print summary
	fmt.Printf("\nTest Summary:\n")
	fmt.Printf("- Total Tests: %d\n", report.Summary.TotalTests)
	fmt.Printf("- Passed: %d, Failed: %d, Warnings: %d\n",
		report.Summary.PassedTests, report.Summary.FailedTests, report.Summary.WarningTests)
	fmt.Printf("- Test Duration: %v\n", report.Duration)

	// Show failed tests
	if report.Summary.FailedTests > 0 {
		fmt.Printf("\nFailed Tests:\n")
		for _, result := range report.TestResults {
			if result.Status == "FAILED" {
				fmt.Printf("- [%s] %s: %s\n", result.Severity, result.TestName, result.Description)
				if verbose && result.Details != "" {
					fmt.Printf("  Details: %s\n", result.Details)
				}
			}
		}
		return fmt.Errorf("security tests failed")
	}

	fmt.Printf("\n✓ All security tests passed\n")
	return nil
}

func runCompliance(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Determine compliance standards
	targetStandards := standards
	if len(args) > 0 {
		targetStandards = []string{args[0]}
	}

	// Create compliance manager
	config := &security.ComplianceConfig{
		Standards:       targetStandards,
		ReportDirectory: reportDir,
	}

	complianceManager := security.NewComplianceManager(config)

	if verbose {
		fmt.Printf("Generating compliance reports for: %v\n", targetStandards)
	}

	// Generate reports for each standard
	for _, standard := range targetStandards {
		report, err := complianceManager.GenerateComplianceReport(ctx, standard)
		if err != nil {
			fmt.Printf("Failed to generate %s report: %v\n", standard, err)
			continue
		}

		// Save report
		reportPath := filepath.Join(reportDir, fmt.Sprintf("compliance-%s-%s.json",
			standard, time.Now().Format("2006-01-02-15-04-05")))

		if err := saveReport(report, reportPath); err != nil {
			fmt.Printf("Failed to save %s report: %v\n", standard, err)
			continue
		}

		fmt.Printf("✓ %s compliance report generated: %s\n", standard, reportPath)

		// Output summary if verbose
		if verbose {
			fmt.Printf("  Overall Score: %d\n", report.OverallScore)
			fmt.Printf("  Compliance Level: %s\n", report.ComplianceLevel)
			fmt.Printf("  Issues Found: %d\n", len(report.Issues))
		}
	}

	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Create security manager
	config := &security.ManagerConfig{
		EnableHardening:  true,
		EnableScanning:   true,
		EnableTesting:    true,
		EnableCompliance: true,
		ReportDirectory:  reportDir,
	}

	manager := security.NewSecurityManager(config)

	if verbose {
		fmt.Println("Gathering security status...")
	}

	// Get security status
	status, err := manager.GetSecurityStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get security status: %w", err)
	}

	// Output results
	if err := outputResults(status, "Security Status"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Print summary
	fmt.Printf("\nSecurity Status Summary:\n")
	fmt.Printf("- Overall Score: %d (%s)\n", status.OverallScore, status.SecurityLevel)
	
	if status.VulnerabilityStatus != nil {
		fmt.Printf("- Vulnerabilities: %d total (%d critical, %d high)\n",
			status.VulnerabilityStatus.TotalVulns,
			status.VulnerabilityStatus.CriticalVulns,
			status.VulnerabilityStatus.HighVulns)
	}

	if status.TestStatus != nil {
		fmt.Printf("- Security Tests: %d/%d passed\n",
			status.TestStatus.PassedTests, status.TestStatus.TotalTests)
	}

	if status.ComplianceStatus != nil {
		fmt.Printf("- Compliance: %s (%d score)\n",
			status.ComplianceStatus.ComplianceLevel,
			status.ComplianceStatus.OverallScore)
	}

	// Show recommendations
	if len(status.Recommendations) > 0 {
		fmt.Printf("\nRecommendations:\n")
		for _, rec := range status.Recommendations {
			fmt.Printf("- %s\n", rec)
		}
	}

	return nil
}

func runReport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Create security manager
	config := &security.ManagerConfig{
		EnableHardening:  true,
		EnableScanning:   true,
		EnableTesting:    true,
		EnableCompliance: true,
		ReportDirectory:  reportDir,
	}

	manager := security.NewSecurityManager(config)

	if verbose {
		fmt.Println("Generating comprehensive security report...")
	}

	// Generate report
	report, err := manager.GenerateSecurityReport(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate security report: %w", err)
	}

	// Save report
	reportPath := filepath.Join(reportDir, fmt.Sprintf("security-report-%s.json",
		time.Now().Format("2006-01-02-15-04-05")))

	if err := saveReport(report, reportPath); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	fmt.Printf("✓ Comprehensive security report generated: %s\n", reportPath)

	// Output summary
	if err := outputResults(report, "Security Report"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	return nil
}

// Helper functions

func outputResults(data interface{}, title string) error {
	if outputFile != "" {
		return saveReport(data, outputFile)
	}

	switch outputFormat {
	case "json":
		return outputJSON(data)
	case "yaml":
		return outputYAML(data)
	case "table":
		return outputTable(data, title)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}

func outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func outputYAML(data interface{}) error {
	// YAML output would require yaml package
	fmt.Println("YAML output not implemented yet")
	return outputJSON(data)
}

func outputTable(data interface{}, title string) error {
	fmt.Printf("\n=== %s ===\n", title)
	// Table formatting would be implemented here
	return outputJSON(data)
}

func saveReport(data interface{}, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal data
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write file
	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
