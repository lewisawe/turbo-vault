package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "Manage access policies",
	Long:  "Create, read, update, and delete access control policies",
}

var policiesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all policies",
	Long:  "List all access control policies",
	RunE:  runPoliciesList,
}

var policiesGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a policy",
	Long:  "Retrieve a policy by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runPoliciesGet,
}

var policiesCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new policy",
	Long:  "Create a new access control policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runPoliciesCreate,
}

var policiesUpdateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update an existing policy",
	Long:  "Update an existing access control policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runPoliciesUpdate,
}

var policiesDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a policy",
	Long:  "Delete an access control policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runPoliciesDelete,
}

var policiesValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a policy file",
	Long:  "Validate the syntax and structure of a policy file",
	Args:  cobra.ExactArgs(1),
	RunE:  runPoliciesValidate,
}

func init() {
	rootCmd.AddCommand(policiesCmd)
	
	policiesCmd.AddCommand(policiesListCmd)
	policiesCmd.AddCommand(policiesGetCmd)
	policiesCmd.AddCommand(policiesCreateCmd)
	policiesCmd.AddCommand(policiesUpdateCmd)
	policiesCmd.AddCommand(policiesDeleteCmd)
	policiesCmd.AddCommand(policiesValidateCmd)

	// Create command flags
	policiesCreateCmd.Flags().StringP("file", "f", "", "policy file (JSON or YAML)")
	policiesCreateCmd.Flags().String("description", "", "policy description")
	policiesCreateCmd.Flags().Int("priority", 100, "policy priority")
	policiesCreateCmd.Flags().Bool("enabled", true, "enable policy")

	// Update command flags
	policiesUpdateCmd.Flags().StringP("file", "f", "", "policy file (JSON or YAML)")
	policiesUpdateCmd.Flags().String("description", "", "policy description")
	policiesUpdateCmd.Flags().Int("priority", 0, "policy priority")
	policiesUpdateCmd.Flags().String("enabled", "", "enable/disable policy (true/false)")

	// Delete command flags
	policiesDeleteCmd.Flags().BoolP("force", "f", false, "force deletion without confirmation")
}

func runPoliciesList(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	resp, err := client.Get("/api/v1/policies")
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	var result struct {
		Policies []map[string]interface{} `json:"policies"`
		Total    int                      `json:"total"`
	}

	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	printer := NewPrinter()
	if len(result.Policies) == 0 {
		fmt.Println("No policies found")
		return nil
	}

	return printer.Print(result.Policies)
}

func runPoliciesGet(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	resp, err := client.Get(fmt.Sprintf("/api/v1/policies/%s", name))
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}

	var policy map[string]interface{}
	if err := client.ParseResponse(resp, &policy); err != nil {
		return err
	}

	printer := NewPrinter()
	return printer.Print(policy)
}

func runPoliciesCreate(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	
	policyData := map[string]interface{}{
		"name": name,
	}

	// Add optional fields
	if description, _ := cmd.Flags().GetString("description"); description != "" {
		policyData["description"] = description
	}

	if priority, _ := cmd.Flags().GetInt("priority"); priority != 100 {
		policyData["priority"] = priority
	}

	if enabled, _ := cmd.Flags().GetBool("enabled"); !enabled {
		policyData["enabled"] = enabled
	}

	// Load policy from file if specified
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		policyContent, err := loadPolicyFromFile(file)
		if err != nil {
			return fmt.Errorf("failed to load policy file: %w", err)
		}
		
		// Merge file content with command data
		for key, value := range policyContent {
			if key != "name" { // Don't override name from command
				policyData[key] = value
			}
		}
	}

	resp, err := client.Post("/api/v1/policies", policyData)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Policy '%s' created successfully", name))
	return nil
}

func runPoliciesUpdate(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	updateData := make(map[string]interface{})

	// Add changed fields
	if cmd.Flags().Changed("description") {
		description, _ := cmd.Flags().GetString("description")
		updateData["description"] = description
	}

	if cmd.Flags().Changed("priority") {
		priority, _ := cmd.Flags().GetInt("priority")
		updateData["priority"] = priority
	}

	if cmd.Flags().Changed("enabled") {
		enabled, _ := cmd.Flags().GetString("enabled")
		updateData["enabled"] = enabled == "true"
	}

	// Load policy from file if specified
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		policyContent, err := loadPolicyFromFile(file)
		if err != nil {
			return fmt.Errorf("failed to load policy file: %w", err)
		}
		
		// Merge file content with command data
		for key, value := range policyContent {
			updateData[key] = value
		}
	}

	if len(updateData) == 0 {
		return fmt.Errorf("no updates specified")
	}

	resp, err := client.Put(fmt.Sprintf("/api/v1/policies/%s", name), updateData)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Policy '%s' updated successfully", name))
	return nil
}

func runPoliciesDelete(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	name := args[0]
	force, _ := cmd.Flags().GetBool("force")

	// Confirm deletion unless forced
	if !force {
		fmt.Printf("Are you sure you want to delete policy '%s'? (y/N): ", name)
		var response string
		fmt.Scanln(&response)
		
		if response != "y" && response != "yes" {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	resp, err := client.Delete(fmt.Sprintf("/api/v1/policies/%s", name))
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	if err := client.ParseResponse(resp, nil); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Policy '%s' deleted successfully", name))
	return nil
}

func runPoliciesValidate(cmd *cobra.Command, args []string) error {
	file := args[0]
	
	policyContent, err := loadPolicyFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to load policy file: %w", err)
	}

	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	resp, err := client.Post("/api/v1/policies/validate", policyContent)
	if err != nil {
		return fmt.Errorf("failed to validate policy: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	if valid, ok := result["valid"].(bool); ok && valid {
		PrintSuccess("Policy is valid")
	} else {
		PrintError("Policy validation failed")
		if errors, ok := result["errors"].([]interface{}); ok {
			for _, err := range errors {
				fmt.Printf("  - %v\n", err)
			}
		}
	}

	return nil
}

// loadPolicyFromFile loads a policy from a JSON or YAML file
func loadPolicyFromFile(filename string) (map[string]interface{}, error) {
	// This would implement file loading logic
	// For now, return a placeholder
	return map[string]interface{}{
		"rules": []map[string]interface{}{
			{
				"effect":    "allow",
				"actions":   []string{"read"},
				"resources": []string{"secrets/*"},
			},
		},
	}, nil
}