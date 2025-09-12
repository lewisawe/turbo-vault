package main

import (
	"context"
	"fmt"
	"log"
	"time"

	vaultagent "github.com/vault-agent/go-sdk"
)

func cloudIntegrationExample() {
	fmt.Println("=== Cloud Integration Example ===")
	
	// Configure cloud providers
	cloudConfigs := []vaultagent.CloudConfig{
		{
			Provider: "aws",
			Region:   "us-east-1",
			Credentials: map[string]string{
				"access_key_id":     "your-access-key",
				"secret_access_key": "your-secret-key",
			},
			SyncEnabled: true,
			Tags: map[string]string{
				"source":      "vault-agent",
				"environment": "production",
			},
		},
		{
			Provider: "azure",
			Credentials: map[string]string{
				"vault_url": "https://your-vault.vault.azure.net/",
			},
			SyncEnabled: true,
			Tags: map[string]string{
				"source": "vault-agent",
			},
		},
	}
	
	// Initialize cloud integration
	cloudIntegration, err := vaultagent.NewCloudIntegration(cloudConfigs)
	if err != nil {
		log.Printf("Failed to initialize cloud integration: %v", err)
		return
	}
	
	// Initialize client
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithCache(true, 5*time.Minute, 1000),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	// Enable cloud integration
	hybridConfig := vaultagent.HybridConfig{
		CloudConfigs: cloudConfigs,
	}
	if err := client.EnableCloudIntegration(hybridConfig); err != nil {
		log.Printf("Failed to enable cloud integration: %v", err)
		return
	}
	
	ctx := context.Background()
	
	// Create a secret (will automatically sync to cloud providers)
	secret, err := client.CreateSecret(ctx, vaultagent.CreateSecretRequest{
		Name:  "database-connection",
		Value: "postgresql://user:pass@localhost:5432/db",
		Metadata: map[string]interface{}{
			"environment":        "production",
			"service":           "api-server",
			"rotation_interval": "30d",
		},
		Tags: []string{"database", "production", "critical"},
	})
	if err != nil {
		log.Printf("Failed to create secret: %v", err)
		return
	}
	fmt.Printf("Created secret %s with cloud sync\n", secret.ID)
	
	// Verify cloud sync status
	syncResults := cloudIntegration.SyncSecret(ctx, secret.Name, secret.Value, map[string]interface{}{
		"environment": "production",
		"service":     "api-server",
	})
	fmt.Printf("Cloud sync results: %v\n", syncResults)
	
	// List secrets from cloud providers
	for _, provider := range []string{"aws", "azure"} {
		cloudSecrets, err := cloudIntegration.ListSecretsFromProvider(ctx, provider)
		if err != nil {
			log.Printf("Failed to list secrets from %s: %v", provider, err)
			continue
		}
		fmt.Printf("Secrets in %s: %v\n", provider, cloudSecrets)
	}
	
	fmt.Println()
}

func policyManagementExample() {
	fmt.Println("=== Policy Management Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Create a comprehensive access policy
	policy := vaultagent.Policy{
		Name:        "production-database-policy",
		Description: "Access policy for production database secrets",
		Rules: []vaultagent.PolicyRule{
			{
				Resource: "secrets",
				Actions:  []string{"read", "list"},
				Conditions: []vaultagent.PolicyCondition{
					{
						Field:    "tags",
						Operator: "contains",
						Value:    "database",
					},
					{
						Field:    "metadata.environment",
						Operator: "equals",
						Value:    "production",
					},
				},
			},
			{
				Resource: "secrets",
				Actions:  []string{"create", "update", "delete"},
				Conditions: []vaultagent.PolicyCondition{
					{
						Field:    "user.role",
						Operator: "in",
						Value:    []string{"admin", "database-admin"},
					},
					{
						Field:    "time.hour",
						Operator: "between",
						Value:    []int{9, 17}, // Business hours only
					},
				},
			},
		},
		Priority: 100,
		Enabled:  true,
	}
	
	createdPolicy, err := client.CreatePolicy(ctx, policy)
	if err != nil {
		log.Printf("Failed to create policy: %v", err)
		return
	}
	fmt.Printf("Created policy: %s\n", createdPolicy.ID)
	
	// List all policies
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		log.Printf("Failed to list policies: %v", err)
		return
	}
	fmt.Printf("Total policies: %d\n", len(policies))
	
	fmt.Println()
}

func secretRotationExample() {
	fmt.Println("=== Secret Rotation Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Create a secret with rotation policy
	secret, err := client.CreateSecret(ctx, vaultagent.CreateSecretRequest{
		Name:  "api-key-service-a",
		Value: "initial-api-key-value",
		Metadata: map[string]interface{}{
			"service":           "service-a",
			"rotation_enabled":  "true",
			"rotation_interval": "7d",
			"last_rotated":      time.Now().Format(time.RFC3339),
		},
		Tags: []string{"api-key", "auto-rotate"},
	})
	if err != nil {
		log.Printf("Failed to create secret: %v", err)
		return
	}
	fmt.Printf("Created secret with rotation: %s\n", secret.ID)
	
	// Simulate rotation
	rotatedSecret, err := client.RotateSecret(ctx, secret.ID)
	if err != nil {
		log.Printf("Failed to rotate secret: %v", err)
		return
	}
	fmt.Printf("Rotated secret to version %d\n", rotatedSecret.Version)
	
	// Get version history
	versions, err := client.GetSecretVersions(ctx, secret.ID)
	if err != nil {
		log.Printf("Failed to get secret versions: %v", err)
		return
	}
	fmt.Printf("Secret has %d versions\n", len(versions))
	
	// Rollback to previous version if needed
	if len(versions) > 1 {
		previousVersion := versions[len(versions)-2].Version
		rolledBack, err := client.RollbackSecret(ctx, secret.ID, previousVersion)
		if err != nil {
			log.Printf("Failed to rollback secret: %v", err)
			return
		}
		fmt.Printf("Rolled back to version %d\n", rolledBack.Version)
	}
	
	fmt.Println()
}

func backupAndRecoveryExample() {
	fmt.Println("=== Backup and Recovery Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Create a backup
	backupName := fmt.Sprintf("backup-%s", time.Now().Format("20060102-150405"))
	backup, err := client.CreateBackup(ctx, backupName, map[string]interface{}{
		"include_secrets":     true,
		"include_policies":    true,
		"include_audit_logs":  true,
		"compression":         true,
		"encryption":          true,
	})
	if err != nil {
		log.Printf("Failed to create backup: %v", err)
		return
	}
	fmt.Printf("Created backup: %s\n", backup.ID)
	
	// List all backups
	backups, err := client.ListBackups(ctx)
	if err != nil {
		log.Printf("Failed to list backups: %v", err)
		return
	}
	fmt.Printf("Available backups: %d\n", len(backups))
	
	// Show backup metadata for last 3 backups
	start := len(backups) - 3
	if start < 0 {
		start = 0
	}
	
	for _, backupInfo := range backups[start:] {
		fmt.Printf("Backup %s: %d bytes, created %s\n", 
			backupInfo.Name, backupInfo.Size, backupInfo.CreatedAt.Format(time.RFC3339))
	}
	
	fmt.Println()
}

func monitoringAndMetricsExample() {
	fmt.Println("=== Monitoring and Metrics Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Health check
	health, err := client.HealthCheck(ctx)
	if err != nil {
		log.Printf("Failed to perform health check: %v", err)
		return
	}
	fmt.Printf("Vault status: %s\n", health.Status)
	fmt.Printf("Version: %s\n", health.Version)
	fmt.Printf("Uptime: %d seconds\n", health.Uptime)
	
	// Get Prometheus metrics
	metrics, err := client.GetMetrics(ctx)
	if err != nil {
		log.Printf("Failed to get metrics: %v", err)
		return
	}
	fmt.Printf("Metrics data length: %d characters\n", len(metrics))
	
	// Parse some key metrics (simplified)
	lines := strings.Split(metrics, "\n")
	for _, line := range lines {
		if strings.Contains(line, "vault_secrets_total") && !strings.HasPrefix(line, "#") {
			fmt.Printf("Secrets metric: %s\n", line)
		} else if strings.Contains(line, "vault_requests_total") && !strings.HasPrefix(line, "#") {
			fmt.Printf("Requests metric: %s\n", line)
		}
	}
	
	// Get cache statistics
	cacheStats := client.GetCacheStats()
	if cacheStats != nil {
		fmt.Printf("Cache statistics: %v\n", cacheStats)
	}
	
	fmt.Println()
}

func auditAndComplianceExample() {
	fmt.Println("=== Audit and Compliance Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Get recent audit events
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)
	
	startTimeStr := startTime.Format(time.RFC3339)
	endTimeStr := endTime.Format(time.RFC3339)
	limit := 50
	
	auditEvents, err := client.GetAuditEvents(ctx, vaultagent.AuditQueryOptions{
		StartTime: &startTimeStr,
		EndTime:   &endTimeStr,
		Limit:     &limit,
	})
	if err != nil {
		log.Printf("Failed to get audit events: %v", err)
		return
	}
	
	fmt.Printf("Found %d audit events in last 24 hours\n", len(auditEvents))
	
	// Analyze events by type
	eventTypes := make(map[string]int)
	for _, event := range auditEvents {
		eventTypes[string(event.EventType)]++
	}
	
	fmt.Println("Event types distribution:")
	for eventType, count := range eventTypes {
		fmt.Printf("  %s: %d\n", eventType, count)
	}
	
	// Show recent security events
	var securityEvents []vaultagent.AuditEvent
	for _, event := range auditEvents {
		if event.EventType == "security" {
			securityEvents = append(securityEvents, event)
		}
	}
	
	if len(securityEvents) > 0 {
		fmt.Printf("Recent security events: %d\n", len(securityEvents))
		
		// Show last 5 security events
		start := len(securityEvents) - 5
		if start < 0 {
			start = 0
		}
		
		for _, event := range securityEvents[start:] {
			fmt.Printf("  %s: %s by %s\n", 
				event.Timestamp.Format(time.RFC3339), event.Action, event.Actor.ID)
		}
	}
	
	fmt.Println()
}

func jwtAuthenticationExample() {
	fmt.Println("=== JWT Authentication Example ===")
	
	// JWT token (in real usage, this would be obtained from your auth system)
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	
	auth := vaultagent.NewJWTAuth(jwtToken)
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Test authentication
	health, err := client.HealthCheck(ctx)
	if err != nil {
		log.Printf("JWT authentication failed: %v", err)
		return
	}
	fmt.Printf("JWT authentication successful: %s\n", health.Status)
	
	fmt.Println()
}

func errorHandlingAndRetryExample() {
	fmt.Println("=== Error Handling and Retry Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithRetry(3, 1*time.Second, 10*time.Second, 2.0, []int{500, 502, 503, 504}),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Try to get a non-existent secret
	_, err = client.GetSecret(ctx, "non-existent-secret")
	if err != nil {
		fmt.Printf("Expected error for non-existent secret: %T: %v\n", err, err)
	}
	
	// Try with invalid authentication
	invalidAuth := vaultagent.NewAPIKeyAuth("invalid-key")
	invalidClient, err := vaultagent.NewClient(
		"https://localhost:8200",
		invalidAuth,
		vaultagent.WithTimeout(10*time.Second),
		vaultagent.WithLogLevel("error"),
	)
	if err != nil {
		log.Printf("Failed to create invalid client: %v", err)
		return
	}
	defer invalidClient.Close()
	
	_, err = invalidClient.ListSecrets(ctx, vaultagent.ListSecretsOptions{})
	if err != nil {
		fmt.Printf("Expected authentication error: %T: %v\n", err, err)
	}
	
	fmt.Println()
}

func performanceOptimizationExample() {
	fmt.Println("=== Performance Optimization Example ===")
	
	auth := vaultagent.NewAPIKeyAuth("your-api-key-here")
	client, err := vaultagent.NewClient(
		"https://localhost:8200",
		auth,
		vaultagent.WithTimeout(30*time.Second),
		vaultagent.WithCache(true, 5*time.Minute, 1000),
		vaultagent.WithLogLevel("info"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx := context.Background()
	
	// Demonstrate caching performance
	secretID := "performance-test-secret"
	
	// First request (cache miss)
	start1 := time.Now()
	_, err = client.GetSecret(ctx, secretID)
	time1 := time.Since(start1)
	// Secret might not exist, that's ok for this example
	
	// Second request (cache hit)
	start2 := time.Now()
	_, err = client.GetSecret(ctx, secretID)
	time2 := time.Since(start2)
	// Secret might not exist, that's ok for this example
	
	fmt.Printf("First request: %v, Second request: %v\n", time1, time2)
	
	// Batch operations for better performance
	secretNames := []string{"secret1", "secret2", "secret3", "secret4", "secret5"}
	batchStart := time.Now()
	
	// Use goroutines for concurrent requests
	type result struct {
		name   string
		secret *vaultagent.Secret
		err    error
	}
	
	results := make(chan result, len(secretNames))
	
	for _, name := range secretNames {
		go func(secretName string) {
			secret, err := client.GetSecret(ctx, secretName)
			results <- result{name: secretName, secret: secret, err: err}
		}(name)
	}
	
	// Collect results
	for i := 0; i < len(secretNames); i++ {
		<-results
	}
	
	batchTime := time.Since(batchStart)
	fmt.Printf("Batch operation for %d secrets: %v\n", len(secretNames), batchTime)
	
	// Cache statistics
	cacheStats := client.GetCacheStats()
	if cacheStats != nil {
		fmt.Printf("Final cache statistics: %v\n", cacheStats)
	}
	
	fmt.Println()
}

func main() {
	examples := []func(){
		cloudIntegrationExample,
		policyManagementExample,
		secretRotationExample,
		backupAndRecoveryExample,
		monitoringAndMetricsExample,
		auditAndComplianceExample,
		jwtAuthenticationExample,
		errorHandlingAndRetryExample,
		performanceOptimizationExample,
	}
	
	for _, example := range examples {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Example panicked: %v", r)
				}
			}()
			
			example()
		}()
	}
}