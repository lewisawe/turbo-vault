package main

import (
	"context"
	"fmt"
	"log"

	vaultagent "github.com/vault-agent/go-sdk"
)

func main() {
	// Initialize client with API key authentication
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

	// Create a secret
	secret, err := client.CreateSecret(ctx, vaultagent.CreateSecretRequest{
		Name:  "database-password",
		Value: "super-secret-password",
		Metadata: map[string]interface{}{
			"environment": "production",
		},
		Tags: []string{"database", "production"},
	})
	if err != nil {
		log.Fatalf("Failed to create secret: %v", err)
	}
	fmt.Printf("Created secret: %s\n", secret.ID)

	// Retrieve the secret
	retrieved, err := client.GetSecret(ctx, secret.ID)
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	fmt.Printf("Retrieved secret value: %s\n", retrieved.Value)

	// List secrets
	secrets, err := client.ListSecrets(ctx, vaultagent.ListSecretsOptions{
		Tags: []string{"production"},
	})
	if err != nil {
		log.Fatalf("Failed to list secrets: %v", err)
	}
	fmt.Printf("Found %d production secrets\n", len(secrets))

	// Update secret
	newValue := "new-password"
	updated, err := client.UpdateSecret(ctx, secret.ID, vaultagent.UpdateSecretRequest{
		Value: &newValue,
		Metadata: map[string]interface{}{
			"environment": "production",
			"updated":     "true",
		},
	})
	if err != nil {
		log.Fatalf("Failed to update secret: %v", err)
	}
	fmt.Printf("Updated secret to version %d\n", updated.Version)

	// Health check
	health, err := client.HealthCheck(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}
	fmt.Printf("Vault status: %s\n", health.Status)
}