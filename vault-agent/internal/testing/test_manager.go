package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TestManager orchestrates all testing suites
type TestManager struct {
	config         *TestManagerConfig
	unitSuite      *UnitTestSuite
	integrationSuite *IntegrationTestSuite
	e2eSuite       *E2ETestSuite
	performanceSuite *PerformanceTestSuite
	chaosSuite     *ChaosTestSuite
	results        *ComprehensiveTestResults
}

// TestManagerConfig contains test manager configuration
type TestManagerConfig struct {
	EnableUnitTests        bool
	EnableIntegrationTests bool
	EnableE2ETests         bool
	EnablePerformanceTests bool
	EnableChaosTests       bool
	ReportDirectory        string
	ParallelExecution      bool
	FailFast               bool
	CoverageThreshold      float64
	GenerateReports        bool
	ReportFormats          []string // json, html, xml, junit
}

// ComprehensiveTestResults contains results from all test suites
type ComprehensiveTestResults struct {
	StartTime         time.Time                  `json:"start_time"`
	EndTime           time.Time                  `json:"end_time"`
	Duration          time.Duration              `json:"duration"`
	OverallSuccess    bool                       `json:"overall_success"`
	UnitResults       *TestReport                `json:"unit_results,omitempty"`
	IntegrationResults *IntegrationTestReport    `json:"integration_results,omitempty"`
	E2EResults        *E2EResults                `json:"e2e_results,omitempty"`
	PerformanceResults *PerformanceTestReport    `json:"performance_results,omitempty"`
	ChaosResults      *ChaosResults              `json:"chaos_results,omitempty"`
	Summary           TestExecutionSummary       `json:"summary"`
	QualityGate       QualityGateResult          `json:"quality_gate"`
}

// TestExecutionSummary provides a summary of all test executions
type TestExecutionSummary struct {
	TotalTests       int           `json:"total_tests"`
	PassedTests      int           `json:"passed_tests"`
	FailedTests      int           `json:"failed_tests"`
	SkippedTests     int           `json:"skipped_tests"`
	Coverage         float64       `json:"coverage"`
	Duration         time.Duration `json:"duration"`
	TestTypes        map[string]TestTypeSummary `json:"test_types"`
}

// TestTypeSummary provides summary for each test type
type TestTypeSummary struct {
	Executed bool          `json:"executed"`
	Passed   int           `json:"passed"`
	Failed   int           `json:"failed"`
	Skipped  int           `json:"skipped"`
	Duration time.Duration `json:"duration"`
	Success  bool          `json:"success"`
}

// QualityGateResult contains quality gate evaluation results
type QualityGateResult struct {
	Passed      bool                    `json:"passed"`
	Conditions  []QualityGateCondition  `json:"conditions"`
	Score       int                     `json:"score"`
	Grade       string                  `json:"grade"`
}

// QualityGateCondition represents a quality gate condition
type QualityGateCondition struct {
	Name        string  `json:"name"`
	Threshold   float64 `json:"threshold"`
	ActualValue float64 `json:"actual_value"`
	Passed      bool    `json:"passed"`
	Critical    bool    `json:"critical"`
}

// NewTestManager creates a new test manager
func NewTestManager(config *TestManagerConfig) *TestManager {
	if config == nil {
		config = &TestManagerConfig{
			EnableUnitTests:        true,
			EnableIntegrationTests: true,
			EnableE2ETests:         true,
			EnablePerformanceTests: true,
			EnableChaosTests:       false, // Disabled by default
			ReportDirectory:        "./test-reports",
			ParallelExecution:      false, // Sequential by default for stability
			FailFast:               false,
			CoverageThreshold:      90.0,
			GenerateReports:        true,
			ReportFormats:          []string{"json", "html"},
		}
	}

	// Ensure report directory exists
	os.MkdirAll(config.ReportDirectory, 0755)

	return &TestManager{
		config:  config,
		results: &ComprehensiveTestResults{},
	}
}

// RunAllTests executes all enabled test suites
func (tm *TestManager) RunAllTests(ctx context.Context, rootPath string) (*ComprehensiveTestResults, error) {
	tm.results.StartTime = time.Now()
	defer func() {
		tm.results.EndTime = time.Now()
		tm.results.Duration = tm.results.EndTime.Sub(tm.results.StartTime)
	}()

	// Initialize test suites
	if err := tm.initializeTestSuites(); err != nil {
		return nil, fmt.Errorf("failed to initialize test suites: %w", err)
	}

	// Execute tests based on configuration
	if tm.config.ParallelExecution {
		if err := tm.runTestsInParallel(ctx, rootPath); err != nil {
			return nil, err
		}
	} else {
		if err := tm.runTestsSequentially(ctx, rootPath); err != nil {
			return nil, err
		}
	}

	// Calculate overall results
	tm.calculateOverallResults()

	// Evaluate quality gate
	tm.evaluateQualityGate()

	// Generate reports
	if tm.config.GenerateReports {
		if err := tm.generateReports(); err != nil {
			return nil, fmt.Errorf("failed to generate reports: %w", err)
		}
	}

	return tm.results, nil
}

// initializeTestSuites initializes all test suites
func (tm *TestManager) initializeTestSuites() error {
	if tm.config.EnableUnitTests {
		tm.unitSuite = NewUnitTestSuite(&UnitTestConfig{
			TargetCoverage: tm.config.CoverageThreshold,
			FailFast:       tm.config.FailFast,
		})
	}

	if tm.config.EnableIntegrationTests {
		tm.integrationSuite = NewIntegrationTestSuite(&IntegrationTestConfig{
			CleanupAfterTest: true,
		})
	}

	if tm.config.EnableE2ETests {
		tm.e2eSuite = NewE2ETestSuite(&E2ETestConfig{
			Headless:         true,
			ScreenshotOnFail: true,
		})
	}

	if tm.config.EnablePerformanceTests {
		tm.performanceSuite = NewPerformanceTestSuite(&PerformanceTestConfig{
			TestDuration: 5 * time.Minute,
		})
	}

	if tm.config.EnableChaosTests {
		tm.chaosSuite = NewChaosTestSuite(&ChaosTestConfig{
			TestDuration: 10 * time.Minute,
		})
	}

	return nil
}

// runTestsSequentially runs tests one after another
func (tm *TestManager) runTestsSequentially(ctx context.Context, rootPath string) error {
	// Unit Tests
	if tm.config.EnableUnitTests && tm.unitSuite != nil {
		fmt.Println("Running unit tests...")
		results, err := tm.unitSuite.RunAllTests(ctx, rootPath)
		if err != nil {
			if tm.config.FailFast {
				return fmt.Errorf("unit tests failed: %w", err)
			}
			fmt.Printf("Unit tests failed: %v\n", err)
		}
		if results != nil {
			tm.results.UnitResults = tm.unitSuite.GenerateTestReport()
		}
	}

	// Integration Tests
	if tm.config.EnableIntegrationTests && tm.integrationSuite != nil {
		fmt.Println("Running integration tests...")
		results, err := tm.integrationSuite.RunAllTests(ctx)
		if err != nil {
			if tm.config.FailFast {
				return fmt.Errorf("integration tests failed: %w", err)
			}
			fmt.Printf("Integration tests failed: %v\n", err)
		}
		if results != nil {
			tm.results.IntegrationResults = tm.integrationSuite.GenerateIntegrationReport()
		}
	}

	// E2E Tests
	if tm.config.EnableE2ETests && tm.e2eSuite != nil {
		fmt.Println("Running end-to-end tests...")
		results, err := tm.e2eSuite.RunAllWorkflows(ctx)
		if err != nil {
			if tm.config.FailFast {
				return fmt.Errorf("e2e tests failed: %w", err)
			}
			fmt.Printf("E2E tests failed: %v\n", err)
		}
		tm.results.E2EResults = results
	}

	// Performance Tests
	if tm.config.EnablePerformanceTests && tm.performanceSuite != nil {
		fmt.Println("Running performance tests...")
		results, err := tm.performanceSuite.RunAllTests(ctx)
		if err != nil {
			if tm.config.FailFast {
				return fmt.Errorf("performance tests failed: %w", err)
			}
			fmt.Printf("Performance tests failed: %v\n", err)
		}
		if results != nil {
			tm.results.PerformanceResults = tm.performanceSuite.GeneratePerformanceReport()
		}
	}

	// Chaos Tests
	if tm.config.EnableChaosTests && tm.chaosSuite != nil {
		fmt.Println("Running chaos engineering tests...")
		results, err := tm.chaosSuite.RunAllExperiments(ctx)
		if err != nil {
			if tm.config.FailFast {
				return fmt.Errorf("chaos tests failed: %w", err)
			}
			fmt.Printf("Chaos tests failed: %v\n", err)
		}
		tm.results.ChaosResults = results
	}

	return nil
}

// runTestsInParallel runs tests in parallel (simplified implementation)
func (tm *TestManager) runTestsInParallel(ctx context.Context, rootPath string) error {
	// For simplicity, this implementation runs tests sequentially
	// In a real implementation, you would use goroutines and proper synchronization
	return tm.runTestsSequentially(ctx, rootPath)
}

// calculateOverallResults calculates overall test results
func (tm *TestManager) calculateOverallResults() {
	summary := TestExecutionSummary{
		TestTypes: make(map[string]TestTypeSummary),
	}

	// Unit test results
	if tm.results.UnitResults != nil {
		summary.TotalTests += tm.results.UnitResults.Summary.TotalTests
		summary.PassedTests += tm.results.UnitResults.Summary.PassedTests
		summary.FailedTests += tm.results.UnitResults.Summary.FailedTests
		summary.SkippedTests += tm.results.UnitResults.Summary.SkippedTests
		summary.Coverage = tm.results.UnitResults.Summary.Coverage
		summary.Duration += tm.results.UnitResults.Summary.Duration

		summary.TestTypes["unit"] = TestTypeSummary{
			Executed: true,
			Passed:   tm.results.UnitResults.Summary.PassedTests,
			Failed:   tm.results.UnitResults.Summary.FailedTests,
			Skipped:  tm.results.UnitResults.Summary.SkippedTests,
			Duration: tm.results.UnitResults.Summary.Duration,
			Success:  tm.results.UnitResults.Summary.Success,
		}
	}

	// Integration test results
	if tm.results.IntegrationResults != nil {
		summary.TotalTests += tm.results.IntegrationResults.Summary.TotalTests
		summary.PassedTests += tm.results.IntegrationResults.Summary.PassedTests
		summary.FailedTests += tm.results.IntegrationResults.Summary.FailedTests
		summary.Duration += tm.results.IntegrationResults.Summary.Duration

		summary.TestTypes["integration"] = TestTypeSummary{
			Executed: true,
			Passed:   tm.results.IntegrationResults.Summary.PassedTests,
			Failed:   tm.results.IntegrationResults.Summary.FailedTests,
			Duration: tm.results.IntegrationResults.Summary.Duration,
			Success:  tm.results.IntegrationResults.Summary.Success,
		}
	}

	// E2E test results
	if tm.results.E2EResults != nil {
		summary.TotalTests += tm.results.E2EResults.TotalTests
		summary.PassedTests += tm.results.E2EResults.PassedTests
		summary.FailedTests += tm.results.E2EResults.FailedTests
		summary.SkippedTests += tm.results.E2EResults.SkippedTests
		summary.Duration += tm.results.E2EResults.Duration

		summary.TestTypes["e2e"] = TestTypeSummary{
			Executed: true,
			Passed:   tm.results.E2EResults.PassedTests,
			Failed:   tm.results.E2EResults.FailedTests,
			Skipped:  tm.results.E2EResults.SkippedTests,
			Duration: tm.results.E2EResults.Duration,
			Success:  tm.results.E2EResults.FailedTests == 0,
		}
	}

	// Performance test results
	if tm.results.PerformanceResults != nil {
		summary.TestTypes["performance"] = TestTypeSummary{
			Executed: true,
			Duration: tm.results.PerformanceResults.Summary.Duration,
			Success:  tm.results.PerformanceResults.Summary.TargetsMet,
		}
	}

	// Chaos test results
	if tm.results.ChaosResults != nil {
		summary.TotalTests += tm.results.ChaosResults.TotalExperiments
		summary.PassedTests += tm.results.ChaosResults.SuccessfulTests
		summary.FailedTests += tm.results.ChaosResults.FailedTests
		summary.Duration += tm.results.ChaosResults.Duration

		summary.TestTypes["chaos"] = TestTypeSummary{
			Executed: true,
			Passed:   tm.results.ChaosResults.SuccessfulTests,
			Failed:   tm.results.ChaosResults.FailedTests,
			Duration: tm.results.ChaosResults.Duration,
			Success:  tm.results.ChaosResults.FailedTests == 0,
		}
	}

	tm.results.Summary = summary
	tm.results.OverallSuccess = summary.FailedTests == 0
}

// evaluateQualityGate evaluates quality gate conditions
func (tm *TestManager) evaluateQualityGate() {
	conditions := []QualityGateCondition{
		{
			Name:        "Code Coverage",
			Threshold:   tm.config.CoverageThreshold,
			ActualValue: tm.results.Summary.Coverage,
			Critical:    true,
		},
		{
			Name:        "Test Success Rate",
			Threshold:   95.0,
			ActualValue: tm.calculateTestSuccessRate(),
			Critical:    true,
		},
		{
			Name:        "Performance Targets",
			Threshold:   1.0,
			ActualValue: tm.getPerformanceScore(),
			Critical:    false,
		},
	}

	allPassed := true
	score := 0
	maxScore := 0

	for i := range conditions {
		condition := &conditions[i]
		condition.Passed = condition.ActualValue >= condition.Threshold
		
		if !condition.Passed && condition.Critical {
			allPassed = false
		}

		if condition.Passed {
			if condition.Critical {
				score += 40
			} else {
				score += 20
			}
		}

		if condition.Critical {
			maxScore += 40
		} else {
			maxScore += 20
		}
	}

	grade := "F"
	if score >= maxScore*0.9 {
		grade = "A"
	} else if score >= maxScore*0.8 {
		grade = "B"
	} else if score >= maxScore*0.7 {
		grade = "C"
	} else if score >= maxScore*0.6 {
		grade = "D"
	}

	tm.results.QualityGate = QualityGateResult{
		Passed:     allPassed,
		Conditions: conditions,
		Score:      score,
		Grade:      grade,
	}
}

// calculateTestSuccessRate calculates overall test success rate
func (tm *TestManager) calculateTestSuccessRate() float64 {
	if tm.results.Summary.TotalTests == 0 {
		return 100.0
	}
	return float64(tm.results.Summary.PassedTests) / float64(tm.results.Summary.TotalTests) * 100.0
}

// getPerformanceScore gets performance test score
func (tm *TestManager) getPerformanceScore() float64 {
	if tm.results.PerformanceResults != nil {
		if tm.results.PerformanceResults.Summary.TargetsMet {
			return 1.0
		}
	}
	return 0.0
}

// generateReports generates test reports in various formats
func (tm *TestManager) generateReports() error {
	for _, format := range tm.config.ReportFormats {
		switch format {
		case "json":
			if err := tm.generateJSONReport(); err != nil {
				return fmt.Errorf("failed to generate JSON report: %w", err)
			}
		case "html":
			if err := tm.generateHTMLReport(); err != nil {
				return fmt.Errorf("failed to generate HTML report: %w", err)
			}
		case "junit":
			if err := tm.generateJUnitReport(); err != nil {
				return fmt.Errorf("failed to generate JUnit report: %w", err)
			}
		}
	}
	return nil
}

// generateJSONReport generates JSON test report
func (tm *TestManager) generateJSONReport() error {
	data, err := json.MarshalIndent(tm.results, "", "  ")
	if err != nil {
		return err
	}

	reportPath := filepath.Join(tm.config.ReportDirectory, "comprehensive-test-report.json")
	return os.WriteFile(reportPath, data, 0644)
}

// generateHTMLReport generates HTML test report
func (tm *TestManager) generateHTMLReport() error {
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .success { color: #28a745; }
        .failure { color: #dc3545; }
        .warning { color: #ffc107; }
        table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .quality-gate { margin: 20px 0; padding: 15px; border-radius: 5px; }
        .quality-gate.passed { background: #d4edda; border: 1px solid #c3e6cb; }
        .quality-gate.failed { background: #f8d7da; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <h1>Comprehensive Test Report</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Status:</strong> <span class="%s">%s</span></p>
        <p><strong>Total Tests:</strong> %d</p>
        <p><strong>Passed:</strong> <span class="success">%d</span></p>
        <p><strong>Failed:</strong> <span class="failure">%d</span></p>
        <p><strong>Coverage:</strong> %.1f%%</p>
        <p><strong>Duration:</strong> %v</p>
    </div>

    <div class="quality-gate %s">
        <h2>Quality Gate: %s (Grade: %s)</h2>
        <p>Score: %d</p>
    </div>

    <h2>Test Suite Results</h2>
    <table>
        <tr>
            <th>Test Suite</th>
            <th>Status</th>
            <th>Tests</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Duration</th>
        </tr>
        %s
    </table>
</body>
</html>`

	statusClass := "success"
	statusText := "PASSED"
	if !tm.results.OverallSuccess {
		statusClass = "failure"
		statusText = "FAILED"
	}

	qualityGateClass := "passed"
	qualityGateStatus := "PASSED"
	if !tm.results.QualityGate.Passed {
		qualityGateClass = "failed"
		qualityGateStatus = "FAILED"
	}

	// Generate test suite rows
	var suiteRows string
	for testType, summary := range tm.results.Summary.TestTypes {
		if summary.Executed {
			suiteStatus := "PASSED"
			suiteClass := "success"
			if !summary.Success {
				suiteStatus = "FAILED"
				suiteClass = "failure"
			}

			suiteRows += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td><span class="%s">%s</span></td>
            <td>%d</td>
            <td>%d</td>
            <td>%d</td>
            <td>%v</td>
        </tr>`,
				testType, suiteClass, suiteStatus,
				summary.Passed+summary.Failed+summary.Skipped,
				summary.Passed, summary.Failed, summary.Duration)
		}
	}

	html := fmt.Sprintf(htmlTemplate,
		statusClass, statusText,
		tm.results.Summary.TotalTests,
		tm.results.Summary.PassedTests,
		tm.results.Summary.FailedTests,
		tm.results.Summary.Coverage,
		tm.results.Summary.Duration,
		qualityGateClass, qualityGateStatus, tm.results.QualityGate.Grade,
		tm.results.QualityGate.Score,
		suiteRows)

	reportPath := filepath.Join(tm.config.ReportDirectory, "comprehensive-test-report.html")
	return os.WriteFile(reportPath, []byte(html), 0644)
}

// generateJUnitReport generates JUnit XML test report
func (tm *TestManager) generateJUnitReport() error {
	junitXML := `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Comprehensive Test Suite" tests="%d" failures="%d" time="%.3f">
%s
</testsuites>`

	var testSuites string
	for testType, summary := range tm.results.Summary.TestTypes {
		if summary.Executed {
			testSuites += fmt.Sprintf(`  <testsuite name="%s" tests="%d" failures="%d" time="%.3f">
  </testsuite>
`,
				testType,
				summary.Passed+summary.Failed+summary.Skipped,
				summary.Failed,
				summary.Duration.Seconds())
		}
	}

	xml := fmt.Sprintf(junitXML,
		tm.results.Summary.TotalTests,
		tm.results.Summary.FailedTests,
		tm.results.Summary.Duration.Seconds(),
		testSuites)

	reportPath := filepath.Join(tm.config.ReportDirectory, "junit-report.xml")
	return os.WriteFile(reportPath, []byte(xml), 0644)
}
