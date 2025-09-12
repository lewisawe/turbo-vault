package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
	Long:  "Manage CLI configuration profiles and settings",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long:  "Initialize CLI configuration with default settings",
	RunE:  runConfigInit,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set configuration value",
	Long:  "Set a configuration value for the current profile",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get configuration value",
	Long:  "Get a configuration value from the current profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration",
	Long:  "List all configuration values for the current profile",
	RunE:  runConfigList,
}

var configProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage configuration profiles",
	Long:  "Create, switch, and manage configuration profiles",
}

var configProfileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List profiles",
	Long:  "List all available configuration profiles",
	RunE:  runConfigProfileList,
}

var configProfileCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create profile",
	Long:  "Create a new configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigProfileCreate,
}

var configProfileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete profile",
	Long:  "Delete a configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigProfileDelete,
}

var configProfileSwitchCmd = &cobra.Command{
	Use:   "switch <name>",
	Short: "Switch profile",
	Long:  "Switch to a different configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigProfileSwitch,
}

func init() {
	rootCmd.AddCommand(configCmd)
	
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configProfileCmd)

	configProfileCmd.AddCommand(configProfileListCmd)
	configProfileCmd.AddCommand(configProfileCreateCmd)
	configProfileCmd.AddCommand(configProfileDeleteCmd)
	configProfileCmd.AddCommand(configProfileSwitchCmd)

	// Profile create flags
	configProfileCreateCmd.Flags().String("server-url", "http://localhost:8080", "vault agent server URL")
	configProfileCreateCmd.Flags().String("api-key", "", "API key for authentication")
	configProfileCreateCmd.Flags().String("token", "", "JWT token for authentication")
	configProfileCreateCmd.Flags().Bool("insecure", false, "skip TLS verification")
	configProfileCreateCmd.Flags().Int("timeout", 30, "request timeout in seconds")

	// Profile delete flags
	configProfileDeleteCmd.Flags().BoolP("force", "f", false, "force deletion without confirmation")
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	configDir := getConfigDir()
	if err := ensureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFile := filepath.Join(configDir, "config.yaml")
	
	// Check if config already exists
	if _, err := os.Stat(configFile); err == nil {
		fmt.Printf("Configuration already exists at %s\n", configFile)
		return nil
	}

	// Create default configuration
	defaultConfig := map[string]interface{}{
		"current_profile": "default",
		"profiles": map[string]interface{}{
			"default": map[string]interface{}{
				"server": map[string]interface{}{
					"url":      "http://localhost:8080",
					"insecure": false,
				},
				"client": map[string]interface{}{
					"timeout": 30,
				},
				"auth": map[string]interface{}{
					"api_key": "",
					"token":   "",
				},
				"output": "table",
			},
		},
	}

	// Write configuration file
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Configuration initialized at %s", configFile))
	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	// Set the value in the current profile
	profileKey := fmt.Sprintf("profiles.%s.%s", profile, key)
	viper.Set(profileKey, value)

	// Write configuration
	if err := writeConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Set %s = %s", key, value))
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]
	
	profileKey := fmt.Sprintf("profiles.%s.%s", profile, key)
	value := viper.Get(profileKey)
	
	if value == nil {
		return fmt.Errorf("configuration key '%s' not found", key)
	}

	printer := NewPrinter()
	return printer.Print(map[string]interface{}{
		"key":   key,
		"value": value,
	})
}

func runConfigList(cmd *cobra.Command, args []string) error {
	profileKey := fmt.Sprintf("profiles.%s", profile)
	profileConfig := viper.GetStringMap(profileKey)
	
	if len(profileConfig) == 0 {
		fmt.Printf("No configuration found for profile '%s'\n", profile)
		return nil
	}

	printer := NewPrinter()
	return printer.Print(profileConfig)
}

func runConfigProfileList(cmd *cobra.Command, args []string) error {
	profiles := viper.GetStringMap("profiles")
	currentProfile := viper.GetString("current_profile")
	
	if len(profiles) == 0 {
		fmt.Println("No profiles found")
		return nil
	}

	var profileList []map[string]interface{}
	for name := range profiles {
		isCurrent := name == currentProfile
		profileList = append(profileList, map[string]interface{}{
			"name":    name,
			"current": isCurrent,
		})
	}

	printer := NewPrinter()
	return printer.Print(profileList)
}

func runConfigProfileCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	
	// Check if profile already exists
	profileKey := fmt.Sprintf("profiles.%s", name)
	if viper.IsSet(profileKey) {
		return fmt.Errorf("profile '%s' already exists", name)
	}

	// Get flags
	serverURL, _ := cmd.Flags().GetString("server-url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	token, _ := cmd.Flags().GetString("token")
	insecure, _ := cmd.Flags().GetBool("insecure")
	timeout, _ := cmd.Flags().GetInt("timeout")

	// Create profile configuration
	profileConfig := map[string]interface{}{
		"server": map[string]interface{}{
			"url":      serverURL,
			"insecure": insecure,
		},
		"client": map[string]interface{}{
			"timeout": timeout,
		},
		"auth": map[string]interface{}{
			"api_key": apiKey,
			"token":   token,
		},
		"output": "table",
	}

	viper.Set(profileKey, profileConfig)

	// Write configuration
	if err := writeConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Profile '%s' created successfully", name))
	return nil
}

func runConfigProfileDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	force, _ := cmd.Flags().GetBool("force")
	
	// Check if profile exists
	profileKey := fmt.Sprintf("profiles.%s", name)
	if !viper.IsSet(profileKey) {
		return fmt.Errorf("profile '%s' does not exist", name)
	}

	// Prevent deletion of current profile
	currentProfile := viper.GetString("current_profile")
	if name == currentProfile {
		return fmt.Errorf("cannot delete current profile '%s'", name)
	}

	// Confirm deletion unless forced
	if !force {
		fmt.Printf("Are you sure you want to delete profile '%s'? (y/N): ", name)
		var response string
		fmt.Scanln(&response)
		
		if response != "y" && response != "yes" {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	// Get all profiles and remove the specified one
	profiles := viper.GetStringMap("profiles")
	delete(profiles, name)
	viper.Set("profiles", profiles)

	// Write configuration
	if err := writeConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Profile '%s' deleted successfully", name))
	return nil
}

func runConfigProfileSwitch(cmd *cobra.Command, args []string) error {
	name := args[0]
	
	// Check if profile exists
	profileKey := fmt.Sprintf("profiles.%s", name)
	if !viper.IsSet(profileKey) {
		return fmt.Errorf("profile '%s' does not exist", name)
	}

	// Set as current profile
	viper.Set("current_profile", name)

	// Write configuration
	if err := writeConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Switched to profile '%s'", name))
	return nil
}

// writeConfig writes the current viper configuration to file
func writeConfig() error {
	configDir := getConfigDir()
	if err := ensureConfigDir(); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, "config.yaml")
	
	// Get all settings
	settings := viper.AllSettings()
	
	// Marshal to YAML
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}