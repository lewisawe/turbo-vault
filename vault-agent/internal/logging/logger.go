package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/keyvault/agent/internal/config"
)

// Logger wraps logrus with additional functionality
type Logger struct {
	*logrus.Logger
	config *config.LoggingConfig
}

// NewLogger creates a new logger instance based on configuration
func NewLogger(cfg *config.LoggingConfig) (*Logger, error) {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %s: %w", cfg.Level, err)
	}
	logger.SetLevel(level)

	// Set formatter
	if err := setFormatter(logger, cfg); err != nil {
		return nil, fmt.Errorf("failed to set formatter: %w", err)
	}

	// Set output destinations
	if err := setOutput(logger, cfg); err != nil {
		return nil, fmt.Errorf("failed to set output: %w", err)
	}

	// Add default fields
	if len(cfg.Fields) > 0 {
		fields := make(logrus.Fields)
		for k, v := range cfg.Fields {
			fields[k] = v
		}
		logger = logger.WithFields(fields).Logger
	}

	return &Logger{
		Logger: logger,
		config: cfg,
	}, nil
}

// setFormatter configures the log formatter
func setFormatter(logger *logrus.Logger, cfg *config.LoggingConfig) error {
	switch strings.ToLower(cfg.Format) {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function",
			},
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
			DisableColors:   !isTerminal(),
		})
	case "structured":
		if cfg.Structured {
			logger.SetFormatter(&StructuredFormatter{
				TimestampFormat: time.RFC3339,
			})
		} else {
			logger.SetFormatter(&logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: time.RFC3339,
			})
		}
	default:
		return fmt.Errorf("unsupported log format: %s", cfg.Format)
	}

	return nil
}

// setOutput configures log output destinations
func setOutput(logger *logrus.Logger, cfg *config.LoggingConfig) error {
	var writers []io.Writer

	for _, output := range cfg.Output {
		switch strings.ToLower(output) {
		case "stdout":
			writers = append(writers, os.Stdout)
		case "stderr":
			writers = append(writers, os.Stderr)
		case "file":
			fileWriter, err := createFileWriter(cfg.File)
			if err != nil {
				return fmt.Errorf("failed to create file writer: %w", err)
			}
			writers = append(writers, fileWriter)
		default:
			return fmt.Errorf("unsupported output destination: %s", output)
		}
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	if len(writers) == 1 {
		logger.SetOutput(writers[0])
	} else {
		logger.SetOutput(io.MultiWriter(writers...))
	}

	return nil
}

// createFileWriter creates a file writer with rotation support
func createFileWriter(cfg config.LogFileConfig) (io.Writer, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// For now, just create a simple file writer
	// In production, you'd want to use a rotating file writer like lumberjack
	file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return file, nil
}

// isTerminal checks if the output is a terminal
func isTerminal() bool {
	// Simple check - in production you'd use a proper terminal detection library
	return os.Getenv("TERM") != ""
}

// StructuredFormatter is a custom formatter for structured logging
type StructuredFormatter struct {
	TimestampFormat string
}

// Format formats the log entry
func (f *StructuredFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := entry.Time.Format(f.TimestampFormat)
	
	// Build structured log line
	var parts []string
	parts = append(parts, fmt.Sprintf("time=%s", timestamp))
	parts = append(parts, fmt.Sprintf("level=%s", entry.Level.String()))
	parts = append(parts, fmt.Sprintf("msg=\"%s\"", entry.Message))

	// Add fields
	for key, value := range entry.Data {
		parts = append(parts, fmt.Sprintf("%s=%v", key, value))
	}

	return []byte(strings.Join(parts, " ") + "\n"), nil
}

// WithVaultID adds vault ID to log context
func (l *Logger) WithVaultID(vaultID string) *logrus.Entry {
	return l.WithField("vault_id", vaultID)
}

// WithUserID adds user ID to log context
func (l *Logger) WithUserID(userID string) *logrus.Entry {
	return l.WithField("user_id", userID)
}

// WithRequestID adds request ID to log context
func (l *Logger) WithRequestID(requestID string) *logrus.Entry {
	return l.WithField("request_id", requestID)
}

// WithComponent adds component name to log context
func (l *Logger) WithComponent(component string) *logrus.Entry {
	return l.WithField("component", component)
}

// WithOperation adds operation name to log context
func (l *Logger) WithOperation(operation string) *logrus.Entry {
	return l.WithField("operation", operation)
}

// WithDuration adds operation duration to log context
func (l *Logger) WithDuration(duration time.Duration) *logrus.Entry {
	return l.WithField("duration_ms", duration.Milliseconds())
}

// WithError adds error to log context
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// Security logging methods

// LogSecurityEvent logs a security-related event
func (l *Logger) LogSecurityEvent(event string, severity string, details map[string]interface{}) {
	entry := l.WithFields(logrus.Fields{
		"event_type": "security",
		"event":      event,
		"severity":   severity,
	})

	for k, v := range details {
		entry = entry.WithField(k, v)
	}

	switch severity {
	case "critical":
		entry.Error("Security event occurred")
	case "high":
		entry.Warn("Security event occurred")
	default:
		entry.Info("Security event occurred")
	}
}

// LogAuthEvent logs authentication events
func (l *Logger) LogAuthEvent(userID, method, result, ipAddress string) {
	l.WithFields(logrus.Fields{
		"event_type":  "authentication",
		"user_id":     userID,
		"auth_method": method,
		"result":      result,
		"ip_address":  ipAddress,
	}).Info("Authentication attempt")
}

// LogAccessEvent logs resource access events
func (l *Logger) LogAccessEvent(userID, resource, action, result string) {
	l.WithFields(logrus.Fields{
		"event_type": "access",
		"user_id":    userID,
		"resource":   resource,
		"action":     action,
		"result":     result,
	}).Info("Resource access")
}

// Performance logging methods

// LogPerformanceMetric logs performance metrics
func (l *Logger) LogPerformanceMetric(metric string, value float64, unit string) {
	l.WithFields(logrus.Fields{
		"metric_type": "performance",
		"metric":      metric,
		"value":       value,
		"unit":        unit,
	}).Debug("Performance metric")
}

// LogSlowOperation logs operations that exceed expected duration
func (l *Logger) LogSlowOperation(operation string, duration time.Duration, threshold time.Duration) {
	l.WithFields(logrus.Fields{
		"event_type":        "performance",
		"operation":         operation,
		"duration_ms":       duration.Milliseconds(),
		"threshold_ms":      threshold.Milliseconds(),
		"exceeded_by_ms":    (duration - threshold).Milliseconds(),
	}).Warn("Slow operation detected")
}

// System logging methods

// LogSystemEvent logs system-level events
func (l *Logger) LogSystemEvent(event string, component string, details map[string]interface{}) {
	entry := l.WithFields(logrus.Fields{
		"event_type": "system",
		"event":      event,
		"component":  component,
	})

	for k, v := range details {
		entry = entry.WithField(k, v)
	}

	entry.Info("System event")
}

// LogStartup logs application startup
func (l *Logger) LogStartup(version string, config map[string]interface{}) {
	l.WithFields(logrus.Fields{
		"event_type": "startup",
		"version":    version,
		"config":     config,
	}).Info("Application starting")
}

// LogShutdown logs application shutdown
func (l *Logger) LogShutdown(reason string) {
	l.WithFields(logrus.Fields{
		"event_type": "shutdown",
		"reason":     reason,
	}).Info("Application shutting down")
}

// Error handling methods

// LogError logs errors with context
func (l *Logger) LogError(err error, context map[string]interface{}) {
	entry := l.WithError(err)
	
	for k, v := range context {
		entry = entry.WithField(k, v)
	}

	entry.Error("Error occurred")
}

// LogPanic logs panic recovery
func (l *Logger) LogPanic(recovered interface{}, stack []byte) {
	l.WithFields(logrus.Fields{
		"event_type": "panic",
		"panic":      recovered,
		"stack":      string(stack),
	}).Error("Panic recovered")
}

// Configuration methods

// UpdateLevel updates the log level at runtime
func (l *Logger) UpdateLevel(level string) error {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", level, err)
	}

	l.Logger.SetLevel(logLevel)
	l.config.Level = level
	
	l.WithField("new_level", level).Info("Log level updated")
	return nil
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() string {
	return l.Logger.GetLevel().String()
}

// Close closes any file handles or resources
func (l *Logger) Close() error {
	// In a full implementation, you'd close any file handles here
	return nil
}