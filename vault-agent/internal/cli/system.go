package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "System operations",
	Long:  "System-level operations and information",
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status",
	Long:  "Display the current status of the vault agent",
	RunE:  runSystemStatus,
}

var systemHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check system health",
	Long:  "Perform health checks on the vault agent",
	RunE:  runSystemHealth,
}

var systemInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show system information",
	Long:  "Display detailed system information",
	RunE:  runSystemInfo,
}

var systemMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show system metrics",
	Long:  "Display performance and usage metrics",
	RunE:  runSystemMetrics,
}

var systemBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create system backup",
	Long:  "Create a backup of the vault data",
	RunE:  runSystemBackup,
}

var systemRestoreCmd = &cobra.Command{
	Use:   "restore <backup-id>",
	Short: "Restore from backup",
	Long:  "Restore vault data from a backup",
	Args:  cobra.ExactArgs(1),
	RunE:  runSystemRestore,
}

var systemLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show system logs",
	Long:  "Display system and audit logs",
	RunE:  runSystemLogs,
}

func init() {
	rootCmd.AddCommand(systemCmd)
	
	systemCmd.AddCommand(systemStatusCmd)
	systemCmd.AddCommand(systemHealthCmd)
	systemCmd.AddCommand(systemInfoCmd)
	systemCmd.AddCommand(systemMetricsCmd)
	systemCmd.AddCommand(systemBackupCmd)
	systemCmd.AddCommand(systemRestoreCmd)
	systemCmd.AddCommand(systemLogsCmd)

	// Backup command flags
	systemBackupCmd.Flags().String("name", "", "backup name")
	systemBackupCmd.Flags().Bool("include-secrets", true, "include secrets in backup")
	systemBackupCmd.Flags().Bool("include-logs", false, "include audit logs in backup")
	systemBackupCmd.Flags().Bool("compress", true, "compress backup file")

	// Restore command flags
	systemRestoreCmd.Flags().Bool("force", false, "force restore without confirmation")
	systemRestoreCmd.Flags().Bool("verify", true, "verify backup integrity before restore")

	// Logs command flags
	systemLogsCmd.Flags().StringP("level", "l", "", "filter by log level")
	systemLogsCmd.Flags().StringP("since", "s", "", "show logs since timestamp")
	systemLogsCmd.Flags().IntP("lines", "n", 100, "number of lines to show")
	systemLogsCmd.Flags().BoolP("follow", "f", false, "follow log output")
	systemLogsCmd.Flags().Bool("audit", false, "show audit logs instead of system logs")

	// Metrics command flags
	systemMetricsCmd.Flags().String("format", "prometheus", "metrics format (prometheus, json)")
	systemMetricsCmd.Flags().Bool("live", false, "show live metrics")
}

func runSystemStatus(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	resp, err := client.Get("/api/v1/system/status")
	if err != nil {
		return fmt.Errorf("failed to get system status: %w", err)
	}

	var status map[string]interface{}
	if err := client.ParseResponse(resp, &status); err != nil {
		return err
	}

	printer := NewPrinter()
	return printer.Print(status)
}

func runSystemHealth(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	if err := client.Health(); err != nil {
		PrintError(fmt.Sprintf("Health check failed: %v", err))
		return err
	}

	resp, err := client.Get("/api/v1/system/health")
	if err != nil {
		return fmt.Errorf("failed to get detailed health: %w", err)
	}

	var health map[string]interface{}
	if err := client.ParseResponse(resp, &health); err != nil {
		return err
	}

	PrintSuccess("Vault agent is healthy")
	
	if viper.GetBool("verbose") {
		printer := NewPrinter()
		return printer.Print(health)
	}

	return nil
}

func runSystemInfo(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	resp, err := client.Get("/api/v1/system/info")
	if err != nil {
		return fmt.Errorf("failed to get system info: %w", err)
	}

	var info map[string]interface{}
	if err := client.ParseResponse(resp, &info); err != nil {
		return err
	}

	printer := NewPrinter()
	return printer.Print(info)
}

func runSystemMetrics(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	format, _ := cmd.Flags().GetString("format")
	live, _ := cmd.Flags().GetBool("live")

	path := "/api/v1/system/metrics"
	if format == "prometheus" {
		path = "/metrics"
	}

	if live {
		// For live metrics, we would implement streaming
		PrintInfo("Live metrics not implemented in this version")
	}

	resp, err := client.Get(path)
	if err != nil {
		return fmt.Errorf("failed to get metrics: %w", err)
	}

	if format == "prometheus" {
		// For Prometheus format, just print raw response
		defer resp.Body.Close()
		buf := make([]byte, 1024*1024) // 1MB buffer
		n, err := resp.Body.Read(buf)
		if err != nil && n == 0 {
			return fmt.Errorf("failed to read metrics: %w", err)
		}
		fmt.Print(string(buf[:n]))
		return nil
	}

	var metrics map[string]interface{}
	if err := client.ParseResponse(resp, &metrics); err != nil {
		return err
	}

	printer := NewPrinter()
	return printer.Print(metrics)
}

func runSystemBackup(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	backupData := make(map[string]interface{})

	if name, _ := cmd.Flags().GetString("name"); name != "" {
		backupData["name"] = name
	}

	if includeSecrets, _ := cmd.Flags().GetBool("include-secrets"); !includeSecrets {
		backupData["include_secrets"] = includeSecrets
	}

	if includeLogs, _ := cmd.Flags().GetBool("include-logs"); includeLogs {
		backupData["include_logs"] = includeLogs
	}

	if compress, _ := cmd.Flags().GetBool("compress"); !compress {
		backupData["compress"] = compress
	}

	resp, err := client.Post("/api/v1/system/backup", backupData)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess("Backup created successfully")
	
	if viper.GetBool("verbose") {
		printer := NewPrinter()
		return printer.Print(result)
	}

	return nil
}

func runSystemRestore(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	backupID := args[0]
	force, _ := cmd.Flags().GetBool("force")
	verify, _ := cmd.Flags().GetBool("verify")

	// Confirm restore unless forced
	if !force {
		fmt.Printf("Are you sure you want to restore from backup '%s'? This will overwrite current data. (y/N): ", backupID)
		var response string
		fmt.Scanln(&response)
		
		if response != "y" && response != "yes" {
			fmt.Println("Restore cancelled")
			return nil
		}
	}

	restoreData := map[string]interface{}{
		"backup_id": backupID,
		"verify":    verify,
	}

	resp, err := client.Post("/api/v1/system/restore", restoreData)
	if err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	var result map[string]interface{}
	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	PrintSuccess("Restore completed successfully")
	
	if viper.GetBool("verbose") {
		printer := NewPrinter()
		return printer.Print(result)
	}

	return nil
}

func runSystemLogs(cmd *cobra.Command, args []string) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Build query parameters
	params := "?"
	
	if level, _ := cmd.Flags().GetString("level"); level != "" {
		params += fmt.Sprintf("level=%s&", level)
	}
	
	if since, _ := cmd.Flags().GetString("since"); since != "" {
		params += fmt.Sprintf("since=%s&", since)
	}
	
	if lines, _ := cmd.Flags().GetInt("lines"); lines != 100 {
		params += fmt.Sprintf("lines=%d&", lines)
	}

	audit, _ := cmd.Flags().GetBool("audit")
	follow, _ := cmd.Flags().GetBool("follow")

	path := "/api/v1/system/logs"
	if audit {
		path = "/api/v1/system/audit-logs"
	}
	
	if params != "?" {
		path += params[:len(params)-1] // Remove trailing &
	}

	if follow {
		PrintInfo("Follow mode not implemented in this version")
	}

	resp, err := client.Get(path)
	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}

	var result struct {
		Logs []map[string]interface{} `json:"logs"`
	}

	if err := client.ParseResponse(resp, &result); err != nil {
		return err
	}

	printer := NewPrinter()
	if len(result.Logs) == 0 {
		fmt.Println("No logs found")
		return nil
	}

	return printer.Print(result.Logs)
}