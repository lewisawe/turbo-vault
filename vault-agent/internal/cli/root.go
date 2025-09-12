package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	profile     string
	output      string
	verbose     bool
	interactive bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault-cli",
	Short: "Vault Agent CLI - Secure secret management tool",
	Long: `Vault Agent CLI is a comprehensive command-line interface for managing secrets,
API keys, and sensitive configuration data in your vault agent.

This tool provides full access to all vault operations including:
- Secret management (create, read, update, delete)
- Policy management and enforcement
- User and authentication management
- Backup and restore operations
- Monitoring and analytics
- Configuration management`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-cli.yaml)")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "default", "configuration profile to use")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "table", "output format (json, yaml, table)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&interactive, "interactive", "i", false, "interactive mode")

	// Bind flags to viper
	viper.BindPFlag("profile", rootCmd.PersistentFlags().Lookup("profile"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("interactive", rootCmd.PersistentFlags().Lookup("interactive"))

	// Register completion functions
	registerCompletions()
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".vault-cli" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Load profile-specific configuration
	loadProfile()
}

// loadProfile loads profile-specific configuration
func loadProfile() {
	profileKey := fmt.Sprintf("profiles.%s", profile)
	if viper.IsSet(profileKey) {
		profileConfig := viper.GetStringMap(profileKey)
		for key, value := range profileConfig {
			viper.Set(key, value)
		}
	}
}

// getConfigDir returns the configuration directory
func getConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".vault-cli")
}

// ensureConfigDir ensures the configuration directory exists
func ensureConfigDir() error {
	configDir := getConfigDir()
	return os.MkdirAll(configDir, 0755)
}