package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Start interactive mode",
	Long:  "Start an interactive shell for vault operations",
	RunE:  runInteractive,
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}

func runInteractive(cmd *cobra.Command, args []string) error {
	fmt.Println("Vault CLI Interactive Mode")
	fmt.Println("Type 'help' for available commands or 'exit' to quit")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("vault> ")
		
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Handle special commands
		switch input {
		case "exit", "quit":
			fmt.Println("Goodbye!")
			return nil
		case "help":
			showInteractiveHelp()
			continue
		case "clear":
			fmt.Print("\033[2J\033[H") // Clear screen
			continue
		}

		// Parse and execute command
		if err := executeInteractiveCommand(input); err != nil {
			PrintError(err.Error())
		}
	}
}

func showInteractiveHelp() {
	fmt.Println("Available commands:")
	fmt.Println()
	fmt.Println("Secrets:")
	fmt.Println("  secrets list                    - List all secrets")
	fmt.Println("  secrets get <name>              - Get a secret")
	fmt.Println("  secrets create <name>           - Create a new secret")
	fmt.Println("  secrets update <name>           - Update a secret")
	fmt.Println("  secrets delete <name>           - Delete a secret")
	fmt.Println("  secrets rotate <name>           - Rotate a secret")
	fmt.Println()
	fmt.Println("Policies:")
	fmt.Println("  policies list                   - List all policies")
	fmt.Println("  policies get <name>             - Get a policy")
	fmt.Println("  policies create <name>          - Create a new policy")
	fmt.Println("  policies delete <name>          - Delete a policy")
	fmt.Println()
	fmt.Println("System:")
	fmt.Println("  system status                   - Show system status")
	fmt.Println("  system health                   - Check system health")
	fmt.Println("  system info                     - Show system information")
	fmt.Println("  system metrics                  - Show system metrics")
	fmt.Println("  system backup                   - Create a backup")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println("  config list                     - List configuration")
	fmt.Println("  config set <key> <value>        - Set configuration value")
	fmt.Println("  config get <key>                - Get configuration value")
	fmt.Println()
	fmt.Println("Special commands:")
	fmt.Println("  help                            - Show this help")
	fmt.Println("  clear                           - Clear screen")
	fmt.Println("  exit, quit                      - Exit interactive mode")
	fmt.Println()
}

func executeInteractiveCommand(input string) error {
	// Split input into arguments
	args := strings.Fields(input)
	if len(args) == 0 {
		return nil
	}

	// Create a new root command for this execution
	cmd := &cobra.Command{
		Use: "vault-cli",
	}

	// Add all subcommands
	cmd.AddCommand(secretsCmd)
	cmd.AddCommand(policiesCmd)
	cmd.AddCommand(systemCmd)
	cmd.AddCommand(configCmd)

	// Set arguments and execute
	cmd.SetArgs(args)
	
	// Capture output for better formatting in interactive mode
	return cmd.Execute()
}

// Interactive helpers for complex operations

func interactiveSecretCreate() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Secret name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	if name == "" {
		return fmt.Errorf("secret name is required")
	}

	fmt.Print("Secret value: ")
	value, _ := reader.ReadString('\n')
	value = strings.TrimSpace(value)

	if value == "" {
		return fmt.Errorf("secret value is required")
	}

	fmt.Print("Tags (comma-separated, optional): ")
	tagsInput, _ := reader.ReadString('\n')
	tagsInput = strings.TrimSpace(tagsInput)

	var tags []string
	if tagsInput != "" {
		tags = strings.Split(tagsInput, ",")
		for i, tag := range tags {
			tags[i] = strings.TrimSpace(tag)
		}
	}

	fmt.Print("Description (optional): ")
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)

	// Create the secret
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	secretData := map[string]interface{}{
		"name":  name,
		"value": value,
	}

	if len(tags) > 0 {
		secretData["tags"] = tags
	}

	if description != "" {
		secretData["metadata"] = map[string]string{
			"description": description,
		}
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
	return nil
}

func interactivePolicyCreate() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Policy name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	if name == "" {
		return fmt.Errorf("policy name is required")
	}

	fmt.Print("Description (optional): ")
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)

	fmt.Println("Policy rules (enter 'done' when finished):")
	var rules []map[string]interface{}

	for {
		fmt.Print("Effect (allow/deny): ")
		effect, _ := reader.ReadString('\n')
		effect = strings.TrimSpace(effect)

		if effect == "done" {
			break
		}

		if effect != "allow" && effect != "deny" {
			fmt.Println("Effect must be 'allow' or 'deny'")
			continue
		}

		fmt.Print("Actions (comma-separated): ")
		actionsInput, _ := reader.ReadString('\n')
		actionsInput = strings.TrimSpace(actionsInput)

		if actionsInput == "" {
			fmt.Println("Actions are required")
			continue
		}

		actions := strings.Split(actionsInput, ",")
		for i, action := range actions {
			actions[i] = strings.TrimSpace(action)
		}

		fmt.Print("Resources (comma-separated): ")
		resourcesInput, _ := reader.ReadString('\n')
		resourcesInput = strings.TrimSpace(resourcesInput)

		if resourcesInput == "" {
			fmt.Println("Resources are required")
			continue
		}

		resources := strings.Split(resourcesInput, ",")
		for i, resource := range resources {
			resources[i] = strings.TrimSpace(resource)
		}

		rule := map[string]interface{}{
			"effect":    effect,
			"actions":   actions,
			"resources": resources,
		}

		rules = append(rules, rule)
		fmt.Printf("Rule added: %s %v on %v\n", effect, actions, resources)
	}

	if len(rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	// Create the policy
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	policyData := map[string]interface{}{
		"name":  name,
		"rules": rules,
	}

	if description != "" {
		policyData["description"] = description
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