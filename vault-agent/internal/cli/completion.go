package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:

Bash:

  $ source <(vault-cli completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ vault-cli completion bash > /etc/bash_completion.d/vault-cli
  # macOS:
  $ vault-cli completion bash > /usr/local/etc/bash_completion.d/vault-cli

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ vault-cli completion zsh > "${fpath[1]}/_vault-cli"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ vault-cli completion fish | source

  # To load completions for each session, execute once:
  $ vault-cli completion fish > ~/.config/fish/completions/vault-cli.fish

PowerShell:

  PS> vault-cli completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> vault-cli completion powershell > vault-cli.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

// Custom completion functions for dynamic values

// completeSecretNames provides completion for secret names
func completeSecretNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	client, err := NewClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	resp, err := client.Get("/api/v1/secrets")
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var result struct {
		Secrets []map[string]interface{} `json:"secrets"`
	}

	if err := client.ParseResponse(resp, &result); err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var names []string
	for _, secret := range result.Secrets {
		if name, ok := secret["name"].(string); ok {
			names = append(names, name)
		}
	}

	return names, cobra.ShellCompDirectiveNoFileComp
}

// completePolicyNames provides completion for policy names
func completePolicyNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	client, err := NewClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	resp, err := client.Get("/api/v1/policies")
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var result struct {
		Policies []map[string]interface{} `json:"policies"`
	}

	if err := client.ParseResponse(resp, &result); err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var names []string
	for _, policy := range result.Policies {
		if name, ok := policy["name"].(string); ok {
			names = append(names, name)
		}
	}

	return names, cobra.ShellCompDirectiveNoFileComp
}

// completeProfiles provides completion for configuration profiles
func completeProfiles(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// This would read from the config file to get available profiles
	// For now, return common profile names
	return []string{"default", "production", "staging", "development"}, cobra.ShellCompDirectiveNoFileComp
}

// completeOutputFormats provides completion for output formats
func completeOutputFormats(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"json", "yaml", "table"}, cobra.ShellCompDirectiveNoFileComp
}

// Register completion functions
func registerCompletions() {
	// Secret name completions
	secretsGetCmd.RegisterFlagCompletionFunc("version", cobra.NoFileCompletions)
	secretsGetCmd.ValidArgsFunction = completeSecretNames
	secretsUpdateCmd.ValidArgsFunction = completeSecretNames
	secretsDeleteCmd.ValidArgsFunction = completeSecretNames
	secretsRotateCmd.ValidArgsFunction = completeSecretNames
	secretsHistoryCmd.ValidArgsFunction = completeSecretNames

	// Policy name completions
	policiesGetCmd.ValidArgsFunction = completePolicyNames
	policiesUpdateCmd.ValidArgsFunction = completePolicyNames
	policiesDeleteCmd.ValidArgsFunction = completePolicyNames

	// Profile completions
	configProfileDeleteCmd.ValidArgsFunction = completeProfiles
	configProfileSwitchCmd.ValidArgsFunction = completeProfiles

	// Output format completions
	rootCmd.RegisterFlagCompletionFunc("output", completeOutputFormats)

	// File completions
	secretsCreateCmd.RegisterFlagCompletionFunc("from-file", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	})

	policiesCreateCmd.RegisterFlagCompletionFunc("file", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterFileExt
	})
}