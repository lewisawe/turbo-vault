package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileAuditLogger(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := os.MkdirTemp("", "vault_audit_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultAuditConfig(tempDir)
	logger, err := NewFileAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	t.Run("LogAccessEvent", func(t *testing.T) {
		event := CreateAuthenticationEvent("vault-1", "user-1", "john", "api_key", ResultSuccess, "192.168.1.1")
		
		err := logger.LogAccess(ctx, event)
		if err != nil {
			t.Fatalf("Failed to log access event: %v", err)
		}

		// Force flush to ensure event is written
		err = logger.flushBuffer()
		if err != nil {
			t.Fatalf("Failed to flush buffer: %v", err)
		}
	})

	t.Run("LogOperationEvent", func(t *testing.T) {
		event := CreateSecretCreateEvent("vault-1", "user-1", "secret-1", "my-secret", ResultSuccess)
		
		err := logger.LogOperation(ctx, event)
		if err != nil {
			t.Fatalf("Failed to log operation event: %v", err)
		}

		// Force flush
		err = logger.flushBuffer()
		if err != nil {
			t.Fatalf("Failed to flush buffer: %v", err)
		}
	})

	t.Run("LogSecurityEvent", func(t *testing.T) {
		event := CreatePolicyViolationEvent("vault-1", "user-1", "policy-1", "unauthorized access", ThreatLevelMedium)
		
		err := logger.LogSecurityEvent(ctx, event)
		if err != nil {
			t.Fatalf("Failed to log security event: %v", err)
		}

		// Force flush
		err = logger.flushBuffer()
		if err != nil {
			t.Fatalf("Failed to flush buffer: %v", err)
		}
	})

	t.Run("QueryLogs", func(t *testing.T) {
		// Log some test events
		events := []*OperationEvent{
			CreateSecretAccessEvent("vault-1", "user-1", "secret-1", ResultSuccess),
			CreateSecretAccessEvent("vault-1", "user-2", "secret-2", ResultFailure),
			CreateSecretCreateEvent("vault-1", "user-1", "secret-3", "new-secret", ResultSuccess),
		}

		for _, event := range events {
			logger.LogOperation(ctx, event)
		}
		logger.flushBuffer()

		// Query all events
		query := &LogQuery{}
		results, err := logger.QueryLogs(ctx, query)
		if err != nil {
			t.Fatalf("Failed to query logs: %v", err)
		}

		if len(results) < 3 {
			t.Errorf("Expected at least 3 events, got %d", len(results))
		}
	})

	t.Run("QueryLogsWithFilters", func(t *testing.T) {
		// Query events by actor
		query := &LogQuery{
			ActorID: "user-1",
		}
		results, err := logger.QueryLogs(ctx, query)
		if err != nil {
			t.Fatalf("Failed to query logs with filters: %v", err)
		}

		// Verify all results have the correct actor
		for _, event := range results {
			if event.Actor.ID != "user-1" {
				t.Errorf("Expected actor ID 'user-1', got '%s'", event.Actor.ID)
			}
		}
	})

	t.Run("QueryLogsWithTimeRange", func(t *testing.T) {
		now := time.Now()
		startTime := now.Add(-1 * time.Hour)
		endTime := now.Add(1 * time.Hour)

		query := &LogQuery{
			StartTime: &startTime,
			EndTime:   &endTime,
		}
		results, err := logger.QueryLogs(ctx, query)
		if err != nil {
			t.Fatalf("Failed to query logs with time range: %v", err)
		}

		// Verify all results are within the time range
		for _, event := range results {
			if event.Timestamp.Before(startTime) || event.Timestamp.After(endTime) {
				t.Errorf("Event timestamp %v is outside range [%v, %v]", 
					event.Timestamp, startTime, endTime)
			}
		}
	})

	t.Run("LogRotation", func(t *testing.T) {
		// Test manual log rotation
		err := logger.RotateLogs(ctx)
		if err != nil {
			t.Fatalf("Failed to rotate logs: %v", err)
		}

		// Verify new log file is created
		entries, err := os.ReadDir(tempDir)
		if err != nil {
			t.Fatalf("Failed to read log directory: %v", err)
		}

		logFileCount := 0
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".log" {
				logFileCount++
			}
		}

		if logFileCount == 0 {
			t.Error("Expected at least one log file after rotation")
		}
	})
}

func TestEventBuilder(t *testing.T) {
	t.Run("BuildAccessEvent", func(t *testing.T) {
		event := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "john").
			WithActorDetails("192.168.1.1", "Mozilla/5.0", "session-123").
			WithAction("authenticate").
			WithResult(ResultSuccess).
			BuildAccessEvent("api_key", []string{"read", "write"})

		if event.VaultID != "vault-1" {
			t.Errorf("Expected vault ID 'vault-1', got '%s'", event.VaultID)
		}

		if event.Actor.ID != "user-1" {
			t.Errorf("Expected actor ID 'user-1', got '%s'", event.Actor.ID)
		}

		if event.Actor.Username != "john" {
			t.Errorf("Expected username 'john', got '%s'", event.Actor.Username)
		}

		if event.Actor.IPAddress != "192.168.1.1" {
			t.Errorf("Expected IP address '192.168.1.1', got '%s'", event.Actor.IPAddress)
		}

		if event.Action != "authenticate" {
			t.Errorf("Expected action 'authenticate', got '%s'", event.Action)
		}

		if event.Result != ResultSuccess {
			t.Errorf("Expected result 'success', got '%s'", event.Result)
		}

		if event.EventType != EventTypeAccess {
			t.Errorf("Expected event type 'access', got '%s'", event.EventType)
		}

		if event.AuthMethod != "api_key" {
			t.Errorf("Expected auth method 'api_key', got '%s'", event.AuthMethod)
		}

		if len(event.Permissions) != 2 {
			t.Errorf("Expected 2 permissions, got %d", len(event.Permissions))
		}
	})

	t.Run("BuildOperationEvent", func(t *testing.T) {
		changes := map[string]interface{}{
			"name":  "new-secret",
			"value": "updated",
		}

		event := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "").
			WithResource(ResourceTypeSecret, "secret-1", "my-secret").
			WithAction("update").
			WithResult(ResultSuccess).
			WithDuration(100 * time.Millisecond).
			BuildOperationEvent("v2", changes)

		if event.EventType != EventTypeOperation {
			t.Errorf("Expected event type 'operation', got '%s'", event.EventType)
		}

		if event.Resource.Type != ResourceTypeSecret {
			t.Errorf("Expected resource type 'secret', got '%s'", event.Resource.Type)
		}

		if event.Resource.ID != "secret-1" {
			t.Errorf("Expected resource ID 'secret-1', got '%s'", event.Resource.ID)
		}

		if event.ResourceVersion != "v2" {
			t.Errorf("Expected resource version 'v2', got '%s'", event.ResourceVersion)
		}

		if event.Duration != 100*time.Millisecond {
			t.Errorf("Expected duration 100ms, got %v", event.Duration)
		}

		if len(event.Changes) != 2 {
			t.Errorf("Expected 2 changes, got %d", len(event.Changes))
		}
	})

	t.Run("BuildSecurityEvent", func(t *testing.T) {
		indicators := []string{"multiple_failed_attempts", "suspicious_ip"}

		event := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "").
			WithAction("suspicious_activity").
			WithResult(ResultFailure).
			WithSeverity(SeverityCritical).
			WithContext("attempt_count", 5).
			BuildSecurityEvent(ThreatLevelHigh, indicators)

		if event.EventType != EventTypeSecurity {
			t.Errorf("Expected event type 'security', got '%s'", event.EventType)
		}

		if event.ThreatLevel != ThreatLevelHigh {
			t.Errorf("Expected threat level 'high', got '%s'", event.ThreatLevel)
		}

		if len(event.Indicators) != 2 {
			t.Errorf("Expected 2 indicators, got %d", len(event.Indicators))
		}

		if !event.AlertTriggered {
			t.Error("Expected alert to be triggered for high threat level")
		}

		if event.Severity != SeverityCritical {
			t.Errorf("Expected severity 'critical', got '%s'", event.Severity)
		}

		if event.Context["attempt_count"] != 5 {
			t.Errorf("Expected attempt_count 5, got %v", event.Context["attempt_count"])
		}
	})

	t.Run("WithError", func(t *testing.T) {
		event := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "").
			WithAction("test").
			WithError("Something went wrong").
			Build()

		if event.Result != ResultError {
			t.Errorf("Expected result 'error', got '%s'", event.Result)
		}

		if event.ErrorMsg != "Something went wrong" {
			t.Errorf("Expected error message 'Something went wrong', got '%s'", event.ErrorMsg)
		}

		if event.Severity != SeverityError {
			t.Errorf("Expected severity 'error', got '%s'", event.Severity)
		}
	})
}

func TestPredefinedEvents(t *testing.T) {
	t.Run("CreateSecretAccessEvent", func(t *testing.T) {
		event := CreateSecretAccessEvent("vault-1", "user-1", "secret-1", ResultSuccess)

		if event.EventType != EventTypeOperation {
			t.Errorf("Expected event type 'operation', got '%s'", event.EventType)
		}

		if event.Action != "read" {
			t.Errorf("Expected action 'read', got '%s'", event.Action)
		}

		if event.Resource.Type != ResourceTypeSecret {
			t.Errorf("Expected resource type 'secret', got '%s'", event.Resource.Type)
		}

		if event.Resource.ID != "secret-1" {
			t.Errorf("Expected resource ID 'secret-1', got '%s'", event.Resource.ID)
		}
	})

	t.Run("CreateAuthenticationEvent", func(t *testing.T) {
		event := CreateAuthenticationEvent("vault-1", "user-1", "john", "password", ResultFailure, "192.168.1.1")

		if event.EventType != EventTypeAccess {
			t.Errorf("Expected event type 'access', got '%s'", event.EventType)
		}

		if event.Action != "authenticate" {
			t.Errorf("Expected action 'authenticate', got '%s'", event.Action)
		}

		if event.Result != ResultFailure {
			t.Errorf("Expected result 'failure', got '%s'", event.Result)
		}

		if event.Severity != SeverityWarning {
			t.Errorf("Expected severity 'warning' for failed auth, got '%s'", event.Severity)
		}

		if event.AuthMethod != "password" {
			t.Errorf("Expected auth method 'password', got '%s'", event.AuthMethod)
		}
	})

	t.Run("CreatePolicyViolationEvent", func(t *testing.T) {
		event := CreatePolicyViolationEvent("vault-1", "user-1", "policy-1", "unauthorized access", ThreatLevelMedium)

		if event.EventType != EventTypeSecurity {
			t.Errorf("Expected event type 'security', got '%s'", event.EventType)
		}

		if event.Action != "violate" {
			t.Errorf("Expected action 'violate', got '%s'", event.Action)
		}

		if event.Result != ResultDenied {
			t.Errorf("Expected result 'denied', got '%s'", event.Result)
		}

		if event.ThreatLevel != ThreatLevelMedium {
			t.Errorf("Expected threat level 'medium', got '%s'", event.ThreatLevel)
		}

		if len(event.Indicators) == 0 {
			t.Error("Expected indicators to be present")
		}
	})
}

func TestAuditConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultAuditConfig("/tmp/audit")

		if !config.Enabled {
			t.Error("Expected audit to be enabled by default")
		}

		if config.LogLevel != SeverityInfo {
			t.Errorf("Expected log level 'info', got '%s'", config.LogLevel)
		}

		if config.StoragePath != "/tmp/audit" {
			t.Errorf("Expected storage path '/tmp/audit', got '%s'", config.StoragePath)
		}

		if !config.IntegrityChecking {
			t.Error("Expected integrity checking to be enabled by default")
		}

		if config.RotationPolicy.MaxFiles != 10 {
			t.Errorf("Expected max files 10, got %d", config.RotationPolicy.MaxFiles)
		}
	})
}

func TestLogFiltering(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault_audit_filter_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create config with warning level filtering
	config := DefaultAuditConfig(tempDir)
	config.LogLevel = SeverityWarning

	logger, err := NewFileAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	t.Run("FilterByLogLevel", func(t *testing.T) {
		// Log events with different severity levels
		infoEvent := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "").
			WithAction("test").
			WithSeverity(SeverityInfo).
			Build()

		warningEvent := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "").
			WithAction("test").
			WithSeverity(SeverityWarning).
			Build()

		errorEvent := NewEventBuilder().
			WithVaultID("vault-1").
			WithActor(ActorTypeUser, "user-1", "").
			WithAction("test").
			WithSeverity(SeverityError).
			Build()

		// Log all events
		logger.logEvent(ctx, infoEvent)
		logger.logEvent(ctx, warningEvent)
		logger.logEvent(ctx, errorEvent)
		logger.flushBuffer()

		// Query all events
		query := &LogQuery{}
		results, err := logger.QueryLogs(ctx, query)
		if err != nil {
			t.Fatalf("Failed to query logs: %v", err)
		}

		// Should only have warning and error events (info filtered out)
		if len(results) != 2 {
			t.Errorf("Expected 2 events (warning and error), got %d", len(results))
		}

		for _, event := range results {
			if event.Severity == SeverityInfo {
				t.Error("Info event should have been filtered out")
			}
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkAuditLogging(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "vault_audit_bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultAuditConfig(tempDir)
	logger, err := NewFileAuditLogger(config)
	if err != nil {
		b.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			event := CreateSecretAccessEvent("vault-1", "user-1", "secret-1", ResultSuccess)
			logger.LogOperation(ctx, event)
		}
	})
}

func BenchmarkEventBuilding(b *testing.B) {
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = NewEventBuilder().
				WithVaultID("vault-1").
				WithActor(ActorTypeUser, "user-1", "john").
				WithResource(ResourceTypeSecret, "secret-1", "my-secret").
				WithAction("read").
				WithResult(ResultSuccess).
				BuildOperationEvent("v1", nil)
		}
	})
}