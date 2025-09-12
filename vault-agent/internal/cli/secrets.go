package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage secrets",
	Long:  "Create, read, update, and delete secrets in the vault",
}

var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  "List all secrets with their metadata (values are not displayed)",
	RunE:  runSecretsList,
}

var secretsGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a secret",
	Long:  "Retrieve a secret by name. Use --show-value to display the actual value.",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsGet,
}

var secretsCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new secret",
	Long:  "Create a new secret with the specified name and value",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsCreate,
}

var secretsUpdateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update an existing secret",
	Long:  "Update the value of an existing secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsUpdate,
}

var secretsDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a secret",
	Long:  "Delete a secret permanently",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsDelete,
}

var secretsRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Rotate a secret",
	Long:  "Trigger rotation of a secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsRotate,
}

var secretsHistoryCmd = &cobra.Command{
	Use:   "history <name>",
	Short: "Show secret version history",
	Long:  "Display the version history of a secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsHistory,
}

func init() {
	rootCmd.AddCommand(secretsCmd)
	
	secretsCmd.AddCommand(secretsListCmd)
	secretsCmd.AddCommand(secretsGetCmd)
	secretsCmd.AddCommand(secretsCreateCmd)
	secretsCmd.AddCommand(secretsUpdateCmd)
	secretsCmd.AddCommand(secretsDeleteCmd)
	secretsCmd.AddCommand(secretsRotateCmd)
	secretsCmd.AddCommand(secretsHistoryCmd)

	// List command flags
	secretsListCmd.Flags().StringP("filter", "f", "", "filter secrets by name pattern")
	secretsListCmd.Flags().StringSliceP("tags", "t", []string{}, "filter by tags")
	secretsListCmd.Flags().String("status", "", "filter by status (active, expired, rotating)")

	// Get command flags
	secretsGetCmd.Flags().Bool("show-value", false, "display the actual secret value")
	secretsGetCmd.Flags().IntP("version", "v", 0, "get specific version (0 for latest)")

	// Create command flags
	secretsCreateCmd.Flags().StringP("value", "V", "", "secret value (will prompt if not provided)")
	secretsCreateCmd.Flags().StringSliceP("tags", "t", []string{}, "tags for the secret")
	secretsCreateCmd.Flags().StringToStringP("metadata", "m", map[string]string{}, "metadata key-value pairs")
	secretsCreateCmd.Flags().String("expires", "", "expiration date (RFC3339 format)")
	secretsCreateCmd.Flags().String("rotation-policy", "", "rotation policy name")
	secretsCreateCmd.Flags().Bool("from-file", false, "read value from file")

	// Update command flags
	secretsUpdateCmd.Flags().StringP("value", "V", "", "new secret value (will prompt if not provided)")
	secretsUpdateCmd.Flags().StringSliceP("tags", "t", []string{}, "update tags")
	secretsUpdateCmd.Flags().StringToStringP("metadata", "m", map[string]string{}, "update metadata")
	secretsUpdateCmd.Flags().String("expires", "", "update expiration date")
	secretsUpdateCmd.Flags().Bool("from-file", false, "read value from file")

	// Delete command flags
	secretsDeleteCmd.Flags().BoolP("force", "f", false, "force deletion without confirmation")

	// History command flags
	secretsHistoryCmd.Flags().IntP("limit", "l", 10, "limit number of versions to show")
}

func runSecretsList(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Build query parameters
	params := make(map[string]interface{})
	
	if filter, _ := cmd.Flags().GetString("filter"); filter != "" {
		params["filter"] = filter
	}
	
	if tags, _ := cmd.Flags().GetStringSlice("tags"); len(tags) > 0 {
		params["tags"] = tags
	}
	
	if status, _ := cmd.Flags().GetString("status"); status != "" {
		params["status"] = status
	}

	resp, err := client.Get("/api/v1/secrets")
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	var result struct {
		Secrets []map[string]interface{} `json:"secrets"`
		Total   int                      `json:"total"`
	}

	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	printer := NewPrinter()
	if len(result.Secrets) == 0 {
		fmt.Println("No secrets found")
		return nil
	}

	return printer.Print(result.Secrets)
}

func runSecretsGet(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	showValue, _ := cmd.Flags().GetBool("show-value")
	version, _ := cmd.Flags().GetInt("version")

	path := fmt.Sprintf("/api/v1/secrets/%s", name)
	if version > 0 {
		path += fmt.Sprintf("?version=%d", version)
	}

	resp, err := client.Get(path)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	var secret map[string]interface{}
	if err := client.ParseResponse(resp, &secret); err != nil {
		return err
	}

	// Remove value if not requested
	if !showValue {
		delete(secret, "value")
		secret["value"] = "[HIDDEN - use --show-value to display]"
	}

	printer := NewPrinter()
	return printer.Print(secret)
}

func runSecretsCreate(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	
	// Get secret value
	value, err := getSecretValue(cmd, "value", "Enter secret value: ")
	if err != nil {
		return err
	}

	// Build secret data
	secretData := map[string]interface{}{
		"name":  name,
		"value": value,
	}

	if tags, _ := cmd.Flags().GetStringSlice("tags"); len(tags) > 0 {
		secretData["tags"] = tags
	}

	if metadata, _ := cmd.Flags().GetStringToString("metadata"); len(metadata) > 0 {
		secretData["metadata"] = metadata
	}

	if expires, _ := cmd.Flags().GetString("expires"); expires != "" {
		secretData["expires_at"] = expires
	}

	if rotationPolicy, _ := cmd.Flags().GetString("rotation-policy"); rotationPolicy != "" {
		secretData["rotation_policy"] = rotationPolicy
	}

	resp, err := client.Post("/api/v1/secrets", secretData)
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Secret '%s' created successfully", name))
	
	if viper.GetBool("verbose") {
		printer := NewPrinter()
		return printer.Print(result)
	}

	return nil
}

func runSecretsUpdate(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]

	// Get current secret first
	resp, err := client.Get(fmt.Sprintf("/api/v1/secrets/%s", name))
	if err != nil {
		return fmt.Errorf("failed to get current secret: %w", err)
	}

	var currentSecret map[string]interface{}
	if err := client.ParseResponse(resp, &currentSecret); err != nil {
		return err
	}

	// Build update data
	updateData := make(map[string]interface{})

	// Get new value if provided
	if cmd.Flags().Changed("value") || cmd.Flags().Changed("from-file") {
		value, err := getSecretValue(cmd, "value", "Enter new secret value: ")
		if err != nil {
			return err
		}
		updateData["value"] = value
	}

	if cmd.Flags().Changed("tags") {
		tags, _ := cmd.Flags().GetStringSlice("tags")
		updateData["tags"] = tags
	}

	if cmd.Flags().Changed("metadata") {
		metadata, _ := cmd.Flags().GetStringToString("metadata")
		updateData["metadata"] = metadata
	}

	if cmd.Flags().Changed("expires") {
		expires, _ := cmd.Flags().GetString("expires")
		updateData["expires_at"] = expires
	}

	if len(updateData) == 0 {
		return fmt.Errorf("no updates specified")
	}

	resp, err = client.Put(fmt.Sprintf("/api/v1/secrets/%s", name), updateData)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Secret '%s' updated successfully", name))
	
	if viper.GetBool("verbose") {
		printer := NewPrinter()
		return printer.Print(result)
	}

	return nil
}

func runSecretsDelete(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	force, _ := cmd.Flags().GetBool("force")

	// Confirm deletion unless forced
	if !force && !viper.GetBool("interactive") {
		fmt.Printf("Are you sure you want to delete secret '%s'? (y/N): ", name)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		
		if response != "y" && response != "yes" {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	resp, err := client.Delete(fmt.Sprintf("/api/v1/secrets/%s", name))
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if err := client.ParseResponse(resp, nil); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Secret '%s' deleted successfully", name))
	return nil
}

func runSecretsRotate(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]

	resp, err := client.Post(fmt.Sprintf("/api/v1/secrets/%s/rotate", name), nil)
	if err != nil {
		return fmt.Errorf("failed to rotate secret: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Secret '%s' rotation initiated", name))
	
	if viper.GetBool("verbose") {
		printer := NewPrinter()
		return printer.Print(result)
	}

	return nil
}

func runSecretsHistory(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	limit, _ := cmd.Flags().GetInt("limit")

	path := fmt.Sprintf("/api/v1/secrets/%s/versions", name)
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}

	resp, err := client.Get(path)
	if err != nil {
		return fmt.Errorf("failed to get secret history: %w", err)
	}

	var result struct {
		Versions []map[string]interface{} `json:"versions"`
	}

	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	printer := NewPrinter()
	if len(result.Versions) == 0 {
		fmt.Println("No version history found")
		return nil
	}

	return printer.Print(result.Versions)
}

// getSecretValue gets the secret value from flag, file, or interactive input
func getSecretValue(cmd *cobra.Command, flagName, prompt string) (string, error) {
	// Check if reading from file
	if fromFile, _ := cmd.Flags().GetBool("from-file"); fromFile {
		fmt.Print("Enter file path: ")
		reader := bufio.NewReader(os.Stdin)
		filePath, _ := reader.ReadString('\n')
		filePath = strings.TrimSpace(filePath)
		
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}
		return string(data), nil
	}

	// Check if value provided via flag
	if value, _ := cmd.Flags().GetString(flagName); value != "" {
		return value, nil
	}

	// Interactive input
	if viper.GetBool("interactive") || interactive {
		fmt.Print(prompt)
		
		// Use secure input for passwords
		byteValue, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println() // Add newline after password input
		
		return string(byteValue), nil
	}

	return "", fmt.Errorf("secret value is required (use -V flag, --from-file, or --interactive)")
}