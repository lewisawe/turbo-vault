package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vault-agent/internal/testing"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Comprehensive testing and quality assurance operations",
	Long:  `Execute comprehensive testing including unit tests, integration tests, end-to-end tests, performance tests, and chaos engineering.`,
}

var unitTestCmd = &cobra.Command{
	Use:   "unit [path]",
	Short: "Run unit tests with coverage analysis",
	Long:  `Execute comprehensive unit test suite with high coverage analysis and code quality metrics.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runUnitTests,
}

var integrationTestCmd = &cobra.Command{
	Use:   "integration",
	Short: "Run integration tests",
	Long:  `Execute integration tests covering all component interactions and system workflows.`,
	RunE:  runIntegrationTests,
}

var e2eTestCmd = &cobra.Command{
	Use:   "e2e",
	Short: "Run end-to-end tests",
	Long:  `Execute end-to-end tests covering complete user workflows and system scenarios.`,
	RunE:  runE2ETests,
}

var performanceTestCmd = &cobra.Command{
	Use:   "performance",
	Short: "Run performance tests",
	Long:  `Execute performance tests including load testing, benchmarking, and throughput analysis.`,
	RunE:  runPerformanceTests,
}

var chaosTestCmd = &cobra.Command{
	Use:   "chaos",
	Short: "Run chaos engineering tests",
	Long:  `Execute chaos engineering tests for failure scenario validation and system resilience testing.`,
	RunE:  runChaosTests,
}

var allTestsCmd = &cobra.Command{
	Use:   "all [path]",
	Short: "Run all test suites",
	Long:  `Execute comprehensive testing including all test suites with quality gate evaluation.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAllTests,
}

// Test command flags
var (
	testTimeout        time.Duration
	coverageThreshold  float64
	reportDirectory    string
	reportFormats      []string
	parallelExecution  bool
	failFast           bool
	verbose            bool
	enableChaos        bool
	testPattern        string
	excludePattern     string
)

func init() {
	// Add subcommands
	testCmd.AddCommand(unitTestCmd)
	testCmd.AddCommand(integrationTestCmd)
	testCmd.AddCommand(e2eTestCmd)
	testCmd.AddCommand(performanceTestCmd)
	testCmd.AddCommand(chaosTestCmd)
	testCmd.AddCommand(allTestsCmd)

	// Global test flags
	testCmd.PersistentFlags().DurationVar(&testTimeout, "timeout", 30*time.Minute, "Test execution timeout")
	testCmd.PersistentFlags().Float64Var(&coverageThreshold, "coverage", 90.0, "Minimum code coverage threshold")
	testCmd.PersistentFlags().StringVar(&reportDirectory, "report-dir", "./test-reports", "Test report directory")
	testCmd.PersistentFlags().StringSliceVar(&reportFormats, "formats", []string{"json", "html"}, "Report formats (json, html, junit)")
	testCmd.PersistentFlags().BoolVar(&parallelExecution, "parallel", false, "Execute tests in parallel")
	testCmd.PersistentFlags().BoolVar(&failFast, "fail-fast", false, "Stop on first test failure")
	testCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Unit test specific flags
	unitTestCmd.Flags().StringVar(&testPattern, "pattern", "", "Test pattern to match")
	unitTestCmd.Flags().StringVar(&excludePattern, "exclude", "", "Test pattern to exclude")

	// Chaos test specific flags
	chaosTestCmd.Flags().BoolVar(&enableChaos, "enable-chaos", false, "Enable destructive chaos tests")

	// All tests specific flags
	allTestsCmd.Flags().BoolVar(&enableChaos, "enable-chaos", false, "Include chaos engineering tests")

	// Add to root command
	rootCmd.AddCommand(testCmd)
}

func runUnitTests(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Determine target path
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	// Create unit test suite
	config := &testing.UnitTestConfig{
		TargetCoverage:  coverageThreshold,
		TestTimeout:     testTimeout,
		ParallelTests:   parallelExecution,
		VerboseOutput:   verbose,
		FailFast:        failFast,
		TestPatterns:    []string{testPattern},
		ExcludePatterns: []string{excludePattern},
	}

	suite := testing.NewUnitTestSuite(config)

	if verbose {
		fmt.Printf("Running unit tests on %s...\n", targetPath)
		fmt.Printf("Coverage threshold: %.1f%%\n", coverageThreshold)
	}

	// Run tests
	results, err := suite.RunAllTests(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("unit tests failed: %w", err)
	}

	// Generate report
	report := suite.GenerateTestReport()

	// Output results
	if err := outputTestResults(report, "Unit Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Validate coverage
	if err := suite.ValidateCoverage(); err != nil {
		fmt.Printf("❌ Coverage validation failed: %v\n", err)
		return err
	}

	fmt.Printf("✅ Unit tests completed successfully\n")
	fmt.Printf("Coverage: %.1f%% (target: %.1f%%)\n", results.Coverage, coverageThreshold)
	fmt.Printf("Tests: %d passed, %d failed, %d skipped\n", 
		results.PassedTests, results.FailedTests, results.SkippedTests)

	return nil
}

func runIntegrationTests(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create integration test suite
	config := &testing.IntegrationTestConfig{
		TestTimeout:      testTimeout,
		CleanupAfterTest: true,
	}

	suite := testing.NewIntegrationTestSuite(config)

	if verbose {
		fmt.Println("Running integration tests...")
	}

	// Run tests
	results, err := suite.RunAllTests(ctx)
	if err != nil {
		return fmt.Errorf("integration tests failed: %w", err)
	}

	// Generate report
	report := suite.GenerateIntegrationReport()

	// Output results
	if err := outputTestResults(report, "Integration Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	fmt.Printf("✅ Integration tests completed successfully\n")
	fmt.Printf("Tests: %d passed, %d failed\n", results.PassedTests, results.FailedTests)
	fmt.Printf("Components tested: %d\n", len(results.ComponentTests))
	fmt.Printf("Scenarios executed: %d\n", len(results.Scenarios))

	return nil
}

func runE2ETests(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create E2E test suite
	config := &testing.E2ETestConfig{
		TestTimeout:      testTimeout,
		Headless:         !verbose,
		ScreenshotOnFail: true,
	}

	suite := testing.NewE2ETestSuite(config)

	if verbose {
		fmt.Println("Running end-to-end tests...")
	}

	// Run tests
	results, err := suite.RunAllWorkflows(ctx)
	if err != nil {
		return fmt.Errorf("e2e tests failed: %w", err)
	}

	// Output results
	if err := outputTestResults(results, "End-to-End Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	fmt.Printf("✅ End-to-end tests completed successfully\n")
	fmt.Printf("Tests: %d passed, %d failed, %d skipped\n", 
		results.PassedTests, results.FailedTests, results.SkippedTests)
	fmt.Printf("Workflows executed: %d\n", len(results.Workflows))

	return nil
}

func runPerformanceTests(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create performance test suite
	config := &testing.PerformanceTestConfig{
		TestDuration:   testTimeout,
		MaxConcurrency: 100,
		TargetRPS:      1000,
	}

	suite := testing.NewPerformanceTestSuite(config)

	if verbose {
		fmt.Println("Running performance tests...")
	}

	// Run tests
	results, err := suite.RunAllTests(ctx)
	if err != nil {
		return fmt.Errorf("performance tests failed: %w", err)
	}

	// Generate report
	report := suite.GeneratePerformanceReport()

	// Output results
	if err := outputTestResults(report, "Performance Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	fmt.Printf("✅ Performance tests completed successfully\n")
	fmt.Printf("Average RPS: %.1f\n", results.AvgRPS)
	fmt.Printf("Error Rate: %.2f%%\n", results.ErrorRate)
	fmt.Printf("Load Tests: %d\n", len(results.LoadTests))
	fmt.Printf("Benchmarks: %d\n", len(results.Benchmarks))

	return nil
}

func runChaosTests(cmd *cobra.Command, args []string) error {
	if !enableChaos {
		return fmt.Errorf("chaos tests are disabled. Use --enable-chaos to run destructive tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create chaos test suite
	config := &testing.ChaosTestConfig{
		TestDuration:        testTimeout,
		EnableNetworkFaults: true,
		EnableDiskFaults:    true,
		EnableMemoryFaults:  true,
		EnableCPUFaults:     true,
		EnableServiceFaults: true,
	}

	suite := testing.NewChaosTestSuite(config)

	if verbose {
		fmt.Println("Running chaos engineering tests...")
		fmt.Println("⚠️  Warning: These tests may cause system instability")
	}

	// Run tests
	results, err := suite.RunAllExperiments(ctx)
	if err != nil {
		return fmt.Errorf("chaos tests failed: %w", err)
	}

	// Output results
	if err := outputTestResults(results, "Chaos Engineering Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	fmt.Printf("✅ Chaos engineering tests completed\n")
	fmt.Printf("Experiments: %d total, %d successful, %d failed\n", 
		results.TotalExperiments, results.SuccessfulTests, results.FailedTests)
	fmt.Printf("System Resilience Score: %.1f%%\n", results.SystemResilience.ResilienceScore)
	fmt.Printf("Mean Time to Recovery: %v\n", results.SystemResilience.MeanTimeToRecovery)

	if len(results.Recommendations) > 0 {
		fmt.Println("\nRecommendations:")
		for _, rec := range results.Recommendations {
			fmt.Printf("- %s\n", rec)
		}
	}

	return nil
}

func runAllTests(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Determine target path
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	// Create test manager
	config := &testing.TestManagerConfig{
		EnableUnitTests:        true,
		EnableIntegrationTests: true,
		EnableE2ETests:         true,
		EnablePerformanceTests: true,
		EnableChaosTests:       enableChaos,
		ReportDirectory:        reportDirectory,
		ParallelExecution:      parallelExecution,
		FailFast:               failFast,
		CoverageThreshold:      coverageThreshold,
		GenerateReports:        true,
		ReportFormats:          reportFormats,
	}

	manager := testing.NewTestManager(config)

	if verbose {
		fmt.Println("Running comprehensive test suite...")
		fmt.Printf("Target path: %s\n", targetPath)
		fmt.Printf("Coverage threshold: %.1f%%\n", coverageThreshold)
		fmt.Printf("Report directory: %s\n", reportDirectory)
		if enableChaos {
			fmt.Println("⚠️  Chaos engineering tests enabled")
		}
	}

	// Run all tests
	results, err := manager.RunAllTests(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("comprehensive tests failed: %w", err)
	}

	// Output results
	if err := outputTestResults(results, "Comprehensive Test Results"); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Print summary
	fmt.Printf("\n=== Test Execution Summary ===\n")
	fmt.Printf("Overall Status: %s\n", getStatusIcon(results.OverallSuccess))
	fmt.Printf("Total Tests: %d\n", results.Summary.TotalTests)
	fmt.Printf("Passed: %d\n", results.Summary.PassedTests)
	fmt.Printf("Failed: %d\n", results.Summary.FailedTests)
	fmt.Printf("Skipped: %d\n", results.Summary.SkippedTests)
	fmt.Printf("Coverage: %.1f%%\n", results.Summary.Coverage)
	fmt.Printf("Duration: %v\n", results.Summary.Duration)

	// Print quality gate results
	fmt.Printf("\n=== Quality Gate ===\n")
	fmt.Printf("Status: %s\n", getStatusIcon(results.QualityGate.Passed))
	fmt.Printf("Grade: %s\n", results.QualityGate.Grade)
	fmt.Printf("Score: %d\n", results.QualityGate.Score)

	for _, condition := range results.QualityGate.Conditions {
		status := "✅"
		if !condition.Passed {
			status = "❌"
		}
		fmt.Printf("%s %s: %.1f (threshold: %.1f)\n", 
			status, condition.Name, condition.ActualValue, condition.Threshold)
	}

	// Print test suite breakdown
	fmt.Printf("\n=== Test Suite Breakdown ===\n")
	for testType, summary := range results.Summary.TestTypes {
		if summary.Executed {
			status := getStatusIcon(summary.Success)
			fmt.Printf("%s %s: %d passed, %d failed (%v)\n", 
				status, strings.Title(testType), summary.Passed, summary.Failed, summary.Duration)
		}
	}

	// Print report locations
	fmt.Printf("\n=== Reports Generated ===\n")
	for _, format := range reportFormats {
		var filename string
		switch format {
		case "json":
			filename = "comprehensive-test-report.json"
		case "html":
			filename = "comprehensive-test-report.html"
		case "junit":
			filename = "junit-report.xml"
		}
		if filename != "" {
			fmt.Printf("📄 %s: %s/%s\n", strings.ToUpper(format), reportDirectory, filename)
		}
	}

	if !results.OverallSuccess {
		return fmt.Errorf("some tests failed")
	}

	if !results.QualityGate.Passed {
		return fmt.Errorf("quality gate failed")
	}

	fmt.Printf("\n🎉 All tests passed and quality gate requirements met!\n")
	return nil
}

// Helper functions

func outputTestResults(data interface{}, title string) error {
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

func getStatusIcon(success bool) string {
	if success {
		return "✅ PASSED"
	}
	return "❌ FAILED"
}
