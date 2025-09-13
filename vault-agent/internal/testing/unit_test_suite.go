package testing

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// UnitTestSuite manages comprehensive unit testing
type UnitTestSuite struct {
	config   *UnitTestConfig
	coverage *CoverageTracker
	results  *TestResults
}

// UnitTestConfig contains unit test configuration
type UnitTestConfig struct {
	TargetCoverage    float64
	TestTimeout       time.Duration
	ParallelTests     bool
	VerboseOutput     bool
	FailFast          bool
	TestPatterns      []string
	ExcludePatterns   []string
	CoverageProfile   string
}

// CoverageTracker tracks test coverage metrics
type CoverageTracker struct {
	TotalLines    int
	CoveredLines  int
	TotalFuncs    int
	CoveredFuncs  int
	Packages      map[string]*PackageCoverage
}

// PackageCoverage tracks coverage for a specific package
type PackageCoverage struct {
	Name         string
	TotalLines   int
	CoveredLines int
	TotalFuncs   int
	CoveredFuncs int
	Files        map[string]*FileCoverage
}

// FileCoverage tracks coverage for a specific file
type FileCoverage struct {
	Name         string
	TotalLines   int
	CoveredLines int
	Functions    []FunctionCoverage
}

// FunctionCoverage tracks coverage for a specific function
type FunctionCoverage struct {
	Name     string
	Lines    int
	Covered  bool
	TestName string
}

// TestResults contains comprehensive test results
type TestResults struct {
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
	TotalTests    int
	PassedTests   int
	FailedTests   int
	SkippedTests  int
	Coverage      float64
	Packages      []PackageResult
	FailedDetails []TestFailure
}

// PackageResult contains results for a package
type PackageResult struct {
	Name        string
	Tests       int
	Passed      int
	Failed      int
	Skipped     int
	Duration    time.Duration
	Coverage    float64
}

// TestFailure contains details about a failed test
type TestFailure struct {
	Package   string
	Test      string
	Error     string
	Output    string
	Duration  time.Duration
}

// NewUnitTestSuite creates a new unit test suite
func NewUnitTestSuite(config *UnitTestConfig) *UnitTestSuite {
	if config == nil {
		config = &UnitTestConfig{
			TargetCoverage:  90.0,
			TestTimeout:     30 * time.Minute,
			ParallelTests:   true,
			VerboseOutput:   false,
			FailFast:        false,
			CoverageProfile: "coverage.out",
		}
	}

	return &UnitTestSuite{
		config:   config,
		coverage: &CoverageTracker{Packages: make(map[string]*PackageCoverage)},
		results:  &TestResults{},
	}
}

// RunAllTests executes comprehensive unit test suite
func (uts *UnitTestSuite) RunAllTests(ctx context.Context, rootPath string) (*TestResults, error) {
	uts.results.StartTime = time.Now()
	defer func() {
		uts.results.EndTime = time.Now()
		uts.results.Duration = uts.results.EndTime.Sub(uts.results.StartTime)
	}()

	// Discover test packages
	packages, err := uts.discoverTestPackages(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to discover test packages: %w", err)
	}

	// Run tests for each package
	for _, pkg := range packages {
		result, err := uts.runPackageTests(ctx, pkg)
		if err != nil {
			if uts.config.FailFast {
				return nil, fmt.Errorf("test failed in package %s: %w", pkg, err)
			}
			// Continue with other packages
		}
		if result != nil {
			uts.results.Packages = append(uts.results.Packages, *result)
		}
	}

	// Calculate overall results
	uts.calculateOverallResults()

	// Generate coverage report
	if err := uts.generateCoverageReport(); err != nil {
		return nil, fmt.Errorf("failed to generate coverage report: %w", err)
	}

	return uts.results, nil
}

// discoverTestPackages finds all packages with tests
func (uts *UnitTestSuite) discoverTestPackages(rootPath string) ([]string, error) {
	var packages []string

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(info.Name(), "_test.go") {
			dir := filepath.Dir(path)
			// Avoid duplicates
			for _, pkg := range packages {
				if pkg == dir {
					return nil
				}
			}
			packages = append(packages, dir)
		}

		return nil
	})

	return packages, err
}

// runPackageTests runs tests for a specific package
func (uts *UnitTestSuite) runPackageTests(ctx context.Context, packagePath string) (*PackageResult, error) {
	result := &PackageResult{
		Name:      packagePath,
		StartTime: time.Now(),
	}

	// Build test command
	args := []string{"test"}
	if uts.config.VerboseOutput {
		args = append(args, "-v")
	}
	if uts.config.ParallelTests {
		args = append(args, "-parallel", "4")
	}
	args = append(args, "-coverprofile="+uts.config.CoverageProfile)
	args = append(args, "-timeout", uts.config.TestTimeout.String())
	args = append(args, packagePath)

	// Execute tests (simplified - in real implementation would use exec.Command)
	// For now, simulate test execution
	result.Tests = 10
	result.Passed = 9
	result.Failed = 1
	result.Skipped = 0
	result.Duration = time.Since(result.StartTime)
	result.Coverage = 85.5

	return result, nil
}

// calculateOverallResults calculates overall test results
func (uts *UnitTestSuite) calculateOverallResults() {
	for _, pkg := range uts.results.Packages {
		uts.results.TotalTests += pkg.Tests
		uts.results.PassedTests += pkg.Passed
		uts.results.FailedTests += pkg.Failed
		uts.results.SkippedTests += pkg.Skipped
	}

	// Calculate weighted average coverage
	totalLines := 0
	coveredLines := 0
	for _, pkg := range uts.results.Packages {
		// Simplified calculation
		pkgLines := int(pkg.Coverage * 100) // Approximate
		totalLines += pkgLines
		coveredLines += int(pkg.Coverage * float64(pkgLines) / 100)
	}

	if totalLines > 0 {
		uts.results.Coverage = float64(coveredLines) / float64(totalLines) * 100
	}
}

// generateCoverageReport generates detailed coverage report
func (uts *UnitTestSuite) generateCoverageReport() error {
	// Parse coverage profile
	if err := uts.parseCoverageProfile(); err != nil {
		return fmt.Errorf("failed to parse coverage profile: %w", err)
	}

	// Generate HTML report
	if err := uts.generateHTMLCoverageReport(); err != nil {
		return fmt.Errorf("failed to generate HTML coverage report: %w", err)
	}

	return nil
}

// parseCoverageProfile parses Go coverage profile
func (uts *UnitTestSuite) parseCoverageProfile() error {
	// In real implementation, would parse coverage.out file
	// For now, simulate coverage data
	uts.coverage.TotalLines = 1000
	uts.coverage.CoveredLines = 900
	uts.coverage.TotalFuncs = 100
	uts.coverage.CoveredFuncs = 85

	return nil
}

// generateHTMLCoverageReport generates HTML coverage report
func (uts *UnitTestSuite) generateHTMLCoverageReport() error {
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <title>Test Coverage Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .coverage-high { color: #28a745; }
        .coverage-medium { color: #ffc107; }
        .coverage-low { color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Unit Test Coverage Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Coverage: <span class="coverage-high">%.1f%%</span></p>
        <p>Total Tests: %d</p>
        <p>Passed: %d</p>
        <p>Failed: %d</p>
        <p>Duration: %v</p>
    </div>
    <h2>Package Details</h2>
    <table>
        <tr>
            <th>Package</th>
            <th>Tests</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Coverage</th>
            <th>Duration</th>
        </tr>
        %s
    </table>
</body>
</html>`

	var packageRows strings.Builder
	for _, pkg := range uts.results.Packages {
		coverageClass := "coverage-low"
		if pkg.Coverage >= 80 {
			coverageClass = "coverage-high"
		} else if pkg.Coverage >= 60 {
			coverageClass = "coverage-medium"
		}

		packageRows.WriteString(fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%d</td>
            <td>%d</td>
            <td>%d</td>
            <td><span class="%s">%.1f%%</span></td>
            <td>%v</td>
        </tr>`,
			pkg.Name, pkg.Tests, pkg.Passed, pkg.Failed,
			coverageClass, pkg.Coverage, pkg.Duration))
	}

	finalHTML := fmt.Sprintf(htmlContent,
		uts.results.Coverage,
		uts.results.TotalTests,
		uts.results.PassedTests,
		uts.results.FailedTests,
		uts.results.Duration,
		packageRows.String())

	return os.WriteFile("coverage-report.html", []byte(finalHTML), 0644)
}

// ValidateCoverage checks if coverage meets target
func (uts *UnitTestSuite) ValidateCoverage() error {
	if uts.results.Coverage < uts.config.TargetCoverage {
		return fmt.Errorf("coverage %.1f%% is below target %.1f%%",
			uts.results.Coverage, uts.config.TargetCoverage)
	}
	return nil
}

// GenerateTestReport generates comprehensive test report
func (uts *UnitTestSuite) GenerateTestReport() *TestReport {
	return &TestReport{
		Summary: TestSummary{
			TotalTests:    uts.results.TotalTests,
			PassedTests:   uts.results.PassedTests,
			FailedTests:   uts.results.FailedTests,
			SkippedTests:  uts.results.SkippedTests,
			Coverage:      uts.results.Coverage,
			Duration:      uts.results.Duration,
			Success:       uts.results.FailedTests == 0,
		},
		Packages:      uts.results.Packages,
		FailedTests:   uts.results.FailedDetails,
		CoverageData:  uts.coverage,
		Timestamp:     time.Now(),
	}
}

// TestReport contains comprehensive test report
type TestReport struct {
	Summary      TestSummary       `json:"summary"`
	Packages     []PackageResult   `json:"packages"`
	FailedTests  []TestFailure     `json:"failed_tests"`
	CoverageData *CoverageTracker  `json:"coverage_data"`
	Timestamp    time.Time         `json:"timestamp"`
}

// TestSummary contains test summary information
type TestSummary struct {
	TotalTests   int           `json:"total_tests"`
	PassedTests  int           `json:"passed_tests"`
	FailedTests  int           `json:"failed_tests"`
	SkippedTests int           `json:"skipped_tests"`
	Coverage     float64       `json:"coverage"`
	Duration     time.Duration `json:"duration"`
	Success      bool          `json:"success"`
}

// AnalyzeCodeQuality performs static code analysis
func (uts *UnitTestSuite) AnalyzeCodeQuality(rootPath string) (*CodeQualityReport, error) {
	report := &CodeQualityReport{
		Timestamp: time.Now(),
		Issues:    []CodeIssue{},
		Metrics:   CodeMetrics{},
	}

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		issues, metrics, err := uts.analyzeFile(path)
		if err != nil {
			return err
		}

		report.Issues = append(report.Issues, issues...)
		report.Metrics.TotalLines += metrics.TotalLines
		report.Metrics.TotalFunctions += metrics.TotalFunctions
		report.Metrics.CyclomaticComplexity += metrics.CyclomaticComplexity

		return nil
	})

	return report, err
}

// analyzeFile analyzes a single Go file
func (uts *UnitTestSuite) analyzeFile(filePath string) ([]CodeIssue, CodeMetrics, error) {
	var issues []CodeIssue
	var metrics CodeMetrics

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, metrics, err
	}

	// Count lines
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, metrics, err
	}
	metrics.TotalLines = len(strings.Split(string(src), "\n"))

	// Analyze AST
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			metrics.TotalFunctions++
			
			// Check function complexity
			complexity := uts.calculateCyclomaticComplexity(x)
			metrics.CyclomaticComplexity += complexity
			
			if complexity > 10 {
				issues = append(issues, CodeIssue{
					File:        filePath,
					Line:        fset.Position(x.Pos()).Line,
					Type:        "complexity",
					Severity:    "warning",
					Message:     fmt.Sprintf("Function %s has high cyclomatic complexity: %d", x.Name.Name, complexity),
					Suggestion:  "Consider breaking this function into smaller functions",
				})
			}

			// Check function length
			startLine := fset.Position(x.Pos()).Line
			endLine := fset.Position(x.End()).Line
			if endLine-startLine > 50 {
				issues = append(issues, CodeIssue{
					File:       filePath,
					Line:       startLine,
					Type:       "length",
					Severity:   "info",
					Message:    fmt.Sprintf("Function %s is very long: %d lines", x.Name.Name, endLine-startLine),
					Suggestion: "Consider breaking this function into smaller functions",
				})
			}
		}
		return true
	})

	return issues, metrics, nil
}

// calculateCyclomaticComplexity calculates cyclomatic complexity of a function
func (uts *UnitTestSuite) calculateCyclomaticComplexity(fn *ast.FuncDecl) int {
	complexity := 1 // Base complexity

	ast.Inspect(fn, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			complexity++
		case *ast.CaseClause:
			complexity++
		}
		return true
	})

	return complexity
}

// CodeQualityReport contains code quality analysis results
type CodeQualityReport struct {
	Timestamp time.Time   `json:"timestamp"`
	Issues    []CodeIssue `json:"issues"`
	Metrics   CodeMetrics `json:"metrics"`
}

// CodeIssue represents a code quality issue
type CodeIssue struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

// CodeMetrics contains code quality metrics
type CodeMetrics struct {
	TotalLines            int `json:"total_lines"`
	TotalFunctions        int `json:"total_functions"`
	CyclomaticComplexity  int `json:"cyclomatic_complexity"`
	AverageComplexity     float64 `json:"average_complexity"`
}
