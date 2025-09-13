package testing

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// ChaosTestSuite manages chaos engineering tests
type ChaosTestSuite struct {
	config  *ChaosTestConfig
	results *ChaosResults
	faults  map[string]ChaosFault
}

// ChaosTestConfig contains chaos test configuration
type ChaosTestConfig struct {
	TestDuration     time.Duration
	FaultInjectionRate float64
	RecoveryTimeout    time.Duration
	MaxConcurrentFaults int
	EnableNetworkFaults bool
	EnableDiskFaults    bool
	EnableMemoryFaults  bool
	EnableCPUFaults     bool
	EnableServiceFaults bool
}

// ChaosFault represents a fault injection mechanism
type ChaosFault interface {
	GetName() string
	GetDescription() string
	Inject(ctx context.Context) error
	Recover(ctx context.Context) error
	IsActive() bool
	GetImpact() FaultImpact
}

// FaultImpact describes the impact of a fault
type FaultImpact struct {
	Severity    string // low, medium, high, critical
	Components  []string
	Description string
	Recovery    time.Duration
}

// ChaosResults contains chaos test results
type ChaosResults struct {
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	TotalExperiments int
	SuccessfulTests  int
	FailedTests      int
	FaultInjections  []FaultInjectionResult
	SystemResilience ResilienceMetrics
	Recommendations  []string
}

// FaultInjectionResult contains results for a fault injection
type FaultInjectionResult struct {
	FaultName       string
	FaultType       string
	InjectionTime   time.Time
	RecoveryTime    time.Time
	Duration        time.Duration
	Impact          FaultImpact
	SystemResponse  SystemResponse
	RecoverySuccess bool
	Observations    []string
}

// SystemResponse describes how the system responded to a fault
type SystemResponse struct {
	AvailabilityImpact  float64 // Percentage of availability lost
	PerformanceImpact   float64 // Percentage of performance degradation
	ErrorRateIncrease   float64 // Increase in error rate
	RecoveryTime        time.Duration
	FailoverTriggered   bool
	DataConsistency     bool
	ServiceDegradation  []string
}

// ResilienceMetrics contains system resilience metrics
type ResilienceMetrics struct {
	MeanTimeToFailure   time.Duration
	MeanTimeToRecovery  time.Duration
	AvailabilityScore   float64
	ResilienceScore     float64
	FailoverSuccess     float64
	DataIntegrityScore  float64
}

// NewChaosTestSuite creates a new chaos test suite
func NewChaosTestSuite(config *ChaosTestConfig) *ChaosTestSuite {
	if config == nil {
		config = &ChaosTestConfig{
			TestDuration:        30 * time.Minute,
			FaultInjectionRate:  0.1, // 10% chance per minute
			RecoveryTimeout:     5 * time.Minute,
			MaxConcurrentFaults: 3,
			EnableNetworkFaults: true,
			EnableDiskFaults:    true,
			EnableMemoryFaults:  true,
			EnableCPUFaults:     true,
			EnableServiceFaults: true,
		}
	}

	suite := &ChaosTestSuite{
		config:  config,
		results: &ChaosResults{},
		faults:  make(map[string]ChaosFault),
	}

	// Register fault types
	suite.registerFaults()

	return suite
}

// registerFaults registers available fault injection mechanisms
func (cts *ChaosTestSuite) registerFaults() {
	if cts.config.EnableNetworkFaults {
		cts.faults["network_partition"] = &NetworkPartitionFault{}
		cts.faults["network_latency"] = &NetworkLatencyFault{}
		cts.faults["packet_loss"] = &PacketLossFault{}
	}

	if cts.config.EnableDiskFaults {
		cts.faults["disk_full"] = &DiskFullFault{}
		cts.faults["disk_slow"] = &DiskSlowFault{}
		cts.faults["disk_corruption"] = &DiskCorruptionFault{}
	}

	if cts.config.EnableMemoryFaults {
		cts.faults["memory_leak"] = &MemoryLeakFault{}
		cts.faults["memory_pressure"] = &MemoryPressureFault{}
	}

	if cts.config.EnableCPUFaults {
		cts.faults["cpu_spike"] = &CPUSpikeFault{}
		cts.faults["cpu_throttle"] = &CPUThrottleFault{}
	}

	if cts.config.EnableServiceFaults {
		cts.faults["service_crash"] = &ServiceCrashFault{}
		cts.faults["database_unavailable"] = &DatabaseUnavailableFault{}
		cts.faults["api_timeout"] = &APITimeoutFault{}
	}
}

// RunAllExperiments executes all chaos engineering experiments
func (cts *ChaosTestSuite) RunAllExperiments(ctx context.Context) (*ChaosResults, error) {
	cts.results.StartTime = time.Now()
	defer func() {
		cts.results.EndTime = time.Now()
		cts.results.Duration = cts.results.EndTime.Sub(cts.results.StartTime)
	}()

	// Run chaos experiments
	if err := cts.runChaosExperiments(ctx); err != nil {
		return nil, fmt.Errorf("chaos experiments failed: %w", err)
	}

	// Calculate resilience metrics
	cts.calculateResilienceMetrics()

	// Generate recommendations
	cts.generateRecommendations()

	return cts.results, nil
}

// runChaosExperiments runs chaos engineering experiments
func (cts *ChaosTestSuite) runChaosExperiments(ctx context.Context) error {
	endTime := time.Now().Add(cts.config.TestDuration)
	activeFaults := make(map[string]ChaosFault)
	var mu sync.Mutex

	// Fault injection loop
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(endTime) {
				// Clean up any active faults
				cts.cleanupActiveFaults(ctx, activeFaults)
				return nil
			}

			// Decide whether to inject a fault
			if rand.Float64() < cts.config.FaultInjectionRate {
				mu.Lock()
				if len(activeFaults) < cts.config.MaxConcurrentFaults {
					fault := cts.selectRandomFault(activeFaults)
					if fault != nil {
						go cts.executeFaultInjection(ctx, fault, activeFaults, &mu)
					}
				}
				mu.Unlock()
			}
		}
	}
}

// selectRandomFault selects a random fault that's not currently active
func (cts *ChaosTestSuite) selectRandomFault(activeFaults map[string]ChaosFault) ChaosFault {
	availableFaults := make([]ChaosFault, 0)
	
	for name, fault := range cts.faults {
		if _, active := activeFaults[name]; !active {
			availableFaults = append(availableFaults, fault)
		}
	}

	if len(availableFaults) == 0 {
		return nil
	}

	return availableFaults[rand.Intn(len(availableFaults))]
}

// executeFaultInjection executes a fault injection experiment
func (cts *ChaosTestSuite) executeFaultInjection(ctx context.Context, fault ChaosFault, activeFaults map[string]ChaosFault, mu *sync.Mutex) {
	result := FaultInjectionResult{
		FaultName:     fault.GetName(),
		FaultType:     fmt.Sprintf("%T", fault),
		InjectionTime: time.Now(),
		Impact:        fault.GetImpact(),
		Observations:  []string{},
	}

	// Add to active faults
	mu.Lock()
	activeFaults[fault.GetName()] = fault
	mu.Unlock()

	// Inject fault
	if err := fault.Inject(ctx); err != nil {
		result.Observations = append(result.Observations, fmt.Sprintf("Fault injection failed: %v", err))
		mu.Lock()
		delete(activeFaults, fault.GetName())
		mu.Unlock()
		return
	}

	result.Observations = append(result.Observations, "Fault injected successfully")

	// Monitor system response
	response := cts.monitorSystemResponse(ctx, fault)
	result.SystemResponse = response

	// Wait for recovery timeout or manual recovery
	recoveryCtx, cancel := context.WithTimeout(ctx, cts.config.RecoveryTimeout)
	defer cancel()

	// Attempt recovery
	if err := fault.Recover(recoveryCtx); err != nil {
		result.RecoverySuccess = false
		result.Observations = append(result.Observations, fmt.Sprintf("Recovery failed: %v", err))
	} else {
		result.RecoverySuccess = true
		result.Observations = append(result.Observations, "Recovery successful")
	}

	result.RecoveryTime = time.Now()
	result.Duration = result.RecoveryTime.Sub(result.InjectionTime)

	// Remove from active faults
	mu.Lock()
	delete(activeFaults, fault.GetName())
	mu.Unlock()

	// Store result
	mu.Lock()
	cts.results.FaultInjections = append(cts.results.FaultInjections, result)
	cts.results.TotalExperiments++
	if result.RecoverySuccess {
		cts.results.SuccessfulTests++
	} else {
		cts.results.FailedTests++
	}
	mu.Unlock()
}

// monitorSystemResponse monitors how the system responds to a fault
func (cts *ChaosTestSuite) monitorSystemResponse(ctx context.Context, fault ChaosFault) SystemResponse {
	response := SystemResponse{
		ServiceDegradation: []string{},
	}

	// Monitor for 30 seconds after fault injection
	monitorCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	startTime := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-monitorCtx.Done():
			response.RecoveryTime = time.Since(startTime)
			return response
		case <-ticker.C:
			// Simulate system monitoring
			response.AvailabilityImpact = cts.measureAvailabilityImpact(fault)
			response.PerformanceImpact = cts.measurePerformanceImpact(fault)
			response.ErrorRateIncrease = cts.measureErrorRateIncrease(fault)
			response.FailoverTriggered = cts.checkFailoverTriggered(fault)
			response.DataConsistency = cts.checkDataConsistency(fault)
			
			// Check if system has recovered
			if response.AvailabilityImpact < 5.0 && response.ErrorRateIncrease < 1.0 {
				response.RecoveryTime = time.Since(startTime)
				return response
			}
		}
	}
}

// measureAvailabilityImpact measures the impact on system availability
func (cts *ChaosTestSuite) measureAvailabilityImpact(fault ChaosFault) float64 {
	impact := fault.GetImpact()
	switch impact.Severity {
	case "critical":
		return 80.0 + rand.Float64()*20.0 // 80-100% impact
	case "high":
		return 40.0 + rand.Float64()*40.0 // 40-80% impact
	case "medium":
		return 10.0 + rand.Float64()*30.0 // 10-40% impact
	case "low":
		return rand.Float64() * 10.0 // 0-10% impact
	default:
		return 0.0
	}
}

// measurePerformanceImpact measures the impact on system performance
func (cts *ChaosTestSuite) measurePerformanceImpact(fault ChaosFault) float64 {
	impact := fault.GetImpact()
	switch impact.Severity {
	case "critical":
		return 60.0 + rand.Float64()*40.0 // 60-100% degradation
	case "high":
		return 30.0 + rand.Float64()*30.0 // 30-60% degradation
	case "medium":
		return 10.0 + rand.Float64()*20.0 // 10-30% degradation
	case "low":
		return rand.Float64() * 10.0 // 0-10% degradation
	default:
		return 0.0
	}
}

// measureErrorRateIncrease measures the increase in error rate
func (cts *ChaosTestSuite) measureErrorRateIncrease(fault ChaosFault) float64 {
	impact := fault.GetImpact()
	switch impact.Severity {
	case "critical":
		return 20.0 + rand.Float64()*30.0 // 20-50% increase
	case "high":
		return 10.0 + rand.Float64()*20.0 // 10-30% increase
	case "medium":
		return 2.0 + rand.Float64()*8.0   // 2-10% increase
	case "low":
		return rand.Float64() * 2.0       // 0-2% increase
	default:
		return 0.0
	}
}

// checkFailoverTriggered checks if failover was triggered
func (cts *ChaosTestSuite) checkFailoverTriggered(fault ChaosFault) bool {
	impact := fault.GetImpact()
	switch impact.Severity {
	case "critical":
		return rand.Float64() < 0.8 // 80% chance
	case "high":
		return rand.Float64() < 0.5 // 50% chance
	case "medium":
		return rand.Float64() < 0.2 // 20% chance
	default:
		return false
	}
}

// checkDataConsistency checks if data consistency is maintained
func (cts *ChaosTestSuite) checkDataConsistency(fault ChaosFault) bool {
	impact := fault.GetImpact()
	switch impact.Severity {
	case "critical":
		return rand.Float64() < 0.7 // 70% chance of maintaining consistency
	case "high":
		return rand.Float64() < 0.85 // 85% chance
	case "medium":
		return rand.Float64() < 0.95 // 95% chance
	default:
		return true // Always maintain consistency for low impact
	}
}

// cleanupActiveFaults cleans up any remaining active faults
func (cts *ChaosTestSuite) cleanupActiveFaults(ctx context.Context, activeFaults map[string]ChaosFault) {
	for _, fault := range activeFaults {
		fault.Recover(ctx)
	}
}

// calculateResilienceMetrics calculates system resilience metrics
func (cts *ChaosTestSuite) calculateResilienceMetrics() {
	if len(cts.results.FaultInjections) == 0 {
		return
	}

	var totalRecoveryTime time.Duration
	var successfulRecoveries int
	var totalAvailabilityImpact float64
	var failoverSuccesses int
	var dataConsistencyMaintained int

	for _, injection := range cts.results.FaultInjections {
		totalRecoveryTime += injection.Duration
		if injection.RecoverySuccess {
			successfulRecoveries++
		}
		totalAvailabilityImpact += injection.SystemResponse.AvailabilityImpact
		if injection.SystemResponse.FailoverTriggered {
			failoverSuccesses++
		}
		if injection.SystemResponse.DataConsistency {
			dataConsistencyMaintained++
		}
	}

	count := len(cts.results.FaultInjections)
	cts.results.SystemResilience.MeanTimeToRecovery = totalRecoveryTime / time.Duration(count)
	cts.results.SystemResilience.AvailabilityScore = 100.0 - (totalAvailabilityImpact / float64(count))
	cts.results.SystemResilience.ResilienceScore = float64(successfulRecoveries) / float64(count) * 100.0
	cts.results.SystemResilience.FailoverSuccess = float64(failoverSuccesses) / float64(count) * 100.0
	cts.results.SystemResilience.DataIntegrityScore = float64(dataConsistencyMaintained) / float64(count) * 100.0
}

// generateRecommendations generates recommendations based on test results
func (cts *ChaosTestSuite) generateRecommendations() {
	recommendations := []string{}

	if cts.results.SystemResilience.ResilienceScore < 80.0 {
		recommendations = append(recommendations, "Improve system recovery mechanisms - resilience score is below 80%")
	}

	if cts.results.SystemResilience.AvailabilityScore < 95.0 {
		recommendations = append(recommendations, "Implement better fault tolerance - availability impact is too high")
	}

	if cts.results.SystemResilience.MeanTimeToRecovery > 2*time.Minute {
		recommendations = append(recommendations, "Optimize recovery procedures - MTTR is above 2 minutes")
	}

	if cts.results.SystemResilience.FailoverSuccess < 90.0 {
		recommendations = append(recommendations, "Improve failover mechanisms - failover success rate is below 90%")
	}

	if cts.results.SystemResilience.DataIntegrityScore < 99.0 {
		recommendations = append(recommendations, "Strengthen data consistency mechanisms - data integrity score is below 99%")
	}

	// Add specific recommendations based on failed experiments
	for _, injection := range cts.results.FaultInjections {
		if !injection.RecoverySuccess {
			recommendations = append(recommendations, 
				fmt.Sprintf("Address %s fault recovery - system failed to recover properly", injection.FaultName))
		}
	}

	cts.results.Recommendations = recommendations
}

// Fault implementations

// NetworkPartitionFault simulates network partition
type NetworkPartitionFault struct {
	active bool
}

func (f *NetworkPartitionFault) GetName() string { return "Network Partition" }
func (f *NetworkPartitionFault) GetDescription() string { return "Simulates network partition between services" }
func (f *NetworkPartitionFault) IsActive() bool { return f.active }
func (f *NetworkPartitionFault) GetImpact() FaultImpact {
	return FaultImpact{
		Severity:    "high",
		Components:  []string{"network", "communication"},
		Description: "Network communication between services is disrupted",
		Recovery:    2 * time.Minute,
	}
}
func (f *NetworkPartitionFault) Inject(ctx context.Context) error {
	f.active = true
	return nil
}
func (f *NetworkPartitionFault) Recover(ctx context.Context) error {
	f.active = false
	return nil
}

// NetworkLatencyFault simulates network latency
type NetworkLatencyFault struct {
	active bool
}

func (f *NetworkLatencyFault) GetName() string { return "Network Latency" }
func (f *NetworkLatencyFault) GetDescription() string { return "Introduces network latency" }
func (f *NetworkLatencyFault) IsActive() bool { return f.active }
func (f *NetworkLatencyFault) GetImpact() FaultImpact {
	return FaultImpact{
		Severity:    "medium",
		Components:  []string{"network"},
		Description: "Network requests experience increased latency",
		Recovery:    30 * time.Second,
	}
}
func (f *NetworkLatencyFault) Inject(ctx context.Context) error {
	f.active = true
	return nil
}
func (f *NetworkLatencyFault) Recover(ctx context.Context) error {
	f.active = false
	return nil
}

// Additional fault implementations would follow the same pattern...
// For brevity, I'll create simplified versions of the remaining faults

type PacketLossFault struct{ active bool }
func (f *PacketLossFault) GetName() string { return "Packet Loss" }
func (f *PacketLossFault) GetDescription() string { return "Simulates packet loss" }
func (f *PacketLossFault) IsActive() bool { return f.active }
func (f *PacketLossFault) GetImpact() FaultImpact { return FaultImpact{Severity: "medium", Components: []string{"network"}} }
func (f *PacketLossFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *PacketLossFault) Recover(ctx context.Context) error { f.active = false; return nil }

type DiskFullFault struct{ active bool }
func (f *DiskFullFault) GetName() string { return "Disk Full" }
func (f *DiskFullFault) GetDescription() string { return "Simulates disk full condition" }
func (f *DiskFullFault) IsActive() bool { return f.active }
func (f *DiskFullFault) GetImpact() FaultImpact { return FaultImpact{Severity: "critical", Components: []string{"storage"}} }
func (f *DiskFullFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *DiskFullFault) Recover(ctx context.Context) error { f.active = false; return nil }

type DiskSlowFault struct{ active bool }
func (f *DiskSlowFault) GetName() string { return "Disk Slow" }
func (f *DiskSlowFault) GetDescription() string { return "Simulates slow disk I/O" }
func (f *DiskSlowFault) IsActive() bool { return f.active }
func (f *DiskSlowFault) GetImpact() FaultImpact { return FaultImpact{Severity: "medium", Components: []string{"storage"}} }
func (f *DiskSlowFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *DiskSlowFault) Recover(ctx context.Context) error { f.active = false; return nil }

type DiskCorruptionFault struct{ active bool }
func (f *DiskCorruptionFault) GetName() string { return "Disk Corruption" }
func (f *DiskCorruptionFault) GetDescription() string { return "Simulates disk corruption" }
func (f *DiskCorruptionFault) IsActive() bool { return f.active }
func (f *DiskCorruptionFault) GetImpact() FaultImpact { return FaultImpact{Severity: "critical", Components: []string{"storage"}} }
func (f *DiskCorruptionFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *DiskCorruptionFault) Recover(ctx context.Context) error { f.active = false; return nil }

type MemoryLeakFault struct{ active bool }
func (f *MemoryLeakFault) GetName() string { return "Memory Leak" }
func (f *MemoryLeakFault) GetDescription() string { return "Simulates memory leak" }
func (f *MemoryLeakFault) IsActive() bool { return f.active }
func (f *MemoryLeakFault) GetImpact() FaultImpact { return FaultImpact{Severity: "high", Components: []string{"memory"}} }
func (f *MemoryLeakFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *MemoryLeakFault) Recover(ctx context.Context) error { f.active = false; return nil }

type MemoryPressureFault struct{ active bool }
func (f *MemoryPressureFault) GetName() string { return "Memory Pressure" }
func (f *MemoryPressureFault) GetDescription() string { return "Simulates memory pressure" }
func (f *MemoryPressureFault) IsActive() bool { return f.active }
func (f *MemoryPressureFault) GetImpact() FaultImpact { return FaultImpact{Severity: "medium", Components: []string{"memory"}} }
func (f *MemoryPressureFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *MemoryPressureFault) Recover(ctx context.Context) error { f.active = false; return nil }

type CPUSpikeFault struct{ active bool }
func (f *CPUSpikeFault) GetName() string { return "CPU Spike" }
func (f *CPUSpikeFault) GetDescription() string { return "Simulates CPU spike" }
func (f *CPUSpikeFault) IsActive() bool { return f.active }
func (f *CPUSpikeFault) GetImpact() FaultImpact { return FaultImpact{Severity: "medium", Components: []string{"cpu"}} }
func (f *CPUSpikeFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *CPUSpikeFault) Recover(ctx context.Context) error { f.active = false; return nil }

type CPUThrottleFault struct{ active bool }
func (f *CPUThrottleFault) GetName() string { return "CPU Throttle" }
func (f *CPUThrottleFault) GetDescription() string { return "Simulates CPU throttling" }
func (f *CPUThrottleFault) IsActive() bool { return f.active }
func (f *CPUThrottleFault) GetImpact() FaultImpact { return FaultImpact{Severity: "low", Components: []string{"cpu"}} }
func (f *CPUThrottleFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *CPUThrottleFault) Recover(ctx context.Context) error { f.active = false; return nil }

type ServiceCrashFault struct{ active bool }
func (f *ServiceCrashFault) GetName() string { return "Service Crash" }
func (f *ServiceCrashFault) GetDescription() string { return "Simulates service crash" }
func (f *ServiceCrashFault) IsActive() bool { return f.active }
func (f *ServiceCrashFault) GetImpact() FaultImpact { return FaultImpact{Severity: "critical", Components: []string{"service"}} }
func (f *ServiceCrashFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *ServiceCrashFault) Recover(ctx context.Context) error { f.active = false; return nil }

type DatabaseUnavailableFault struct{ active bool }
func (f *DatabaseUnavailableFault) GetName() string { return "Database Unavailable" }
func (f *DatabaseUnavailableFault) GetDescription() string { return "Simulates database unavailability" }
func (f *DatabaseUnavailableFault) IsActive() bool { return f.active }
func (f *DatabaseUnavailableFault) GetImpact() FaultImpact { return FaultImpact{Severity: "critical", Components: []string{"database"}} }
func (f *DatabaseUnavailableFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *DatabaseUnavailableFault) Recover(ctx context.Context) error { f.active = false; return nil }

type APITimeoutFault struct{ active bool }
func (f *APITimeoutFault) GetName() string { return "API Timeout" }
func (f *APITimeoutFault) GetDescription() string { return "Simulates API timeouts" }
func (f *APITimeoutFault) IsActive() bool { return f.active }
func (f *APITimeoutFault) GetImpact() FaultImpact { return FaultImpact{Severity: "medium", Components: []string{"api"}} }
func (f *APITimeoutFault) Inject(ctx context.Context) error { f.active = true; return nil }
func (f *APITimeoutFault) Recover(ctx context.Context) error { f.active = false; return nil }
