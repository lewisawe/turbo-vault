package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileAuditLogger implements AuditLogger interface using file-based storage
type FileAuditLogger struct {
	config       *AuditConfig
	currentFile  *os.File
	mutex        sync.RWMutex
	buffer       []*AuditEvent
	bufferMutex  sync.Mutex
	stopCh       chan struct{}
	flushTicker  *time.Ticker
}

// NewFileAuditLogger creates a new file-based audit logger
func NewFileAuditLogger(config *AuditConfig) (*FileAuditLogger, error) {
	if config == nil {
		return nil, fmt.Errorf("audit config cannot be nil")
	}

	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(config.StoragePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	logger := &FileAuditLogger{
		config:  config,
		buffer:  make([]*AuditEvent, 0, 1000), // Buffer up to 1000 events
		stopCh:  make(chan struct{}),
	}

	// Open current log file
	if err := logger.openCurrentLogFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Start background flush routine
	logger.flushTicker = time.NewTicker(5 * time.Second) // Flush every 5 seconds
	go logger.flushRoutine()

	return logger, nil
}

// LogAccess logs access events
func (l *FileAuditLogger) LogAccess(ctx context.Context, event *AccessEvent) error {
	auditEvent := &event.AuditEvent
	auditEvent.EventType = EventTypeAccess
	return l.logEvent(ctx, auditEvent)
}

// LogOperation logs operational events
func (l *FileAuditLogger) LogOperation(ctx context.Context, event *OperationEvent) error {
	auditEvent := &event.AuditEvent
	auditEvent.EventType = EventTypeOperation
	return l.logEvent(ctx, auditEvent)
}

// LogSecurityEvent logs security events
func (l *FileAuditLogger) LogSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	auditEvent := &event.AuditEvent
	auditEvent.EventType = EventTypeSecurity
	return l.logEvent(ctx, auditEvent)
}

// logEvent is the internal method for logging events
func (l *FileAuditLogger) logEvent(ctx context.Context, event *AuditEvent) error {
	// Set event ID and timestamp if not already set
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Check if event meets minimum severity level
	if !l.shouldLogEvent(event) {
		return nil
	}

	// Add to buffer
	l.bufferMutex.Lock()
	l.buffer = append(l.buffer, event)
	shouldFlush := len(l.buffer) >= 100 // Flush when buffer reaches 100 events
	l.bufferMutex.Unlock()

	// Immediate flush for critical events or when buffer is full
	if event.Severity == SeverityCritical || shouldFlush {
		return l.flushBuffer()
	}

	return nil
}

// shouldLogEvent checks if an event should be logged based on configuration
func (l *FileAuditLogger) shouldLogEvent(event *AuditEvent) bool {
	if !l.config.Enabled {
		return false
	}

	// Check severity level
	switch l.config.LogLevel {
	case SeverityInfo:
		return true
	case SeverityWarning:
		return event.Severity != SeverityInfo
	case SeverityError:
		return event.Severity == SeverityError || event.Severity == SeverityCritical
	case SeverityCritical:
		return event.Severity == SeverityCritical
	default:
		return true
	}
}

// flushBuffer writes buffered events to the log file
func (l *FileAuditLogger) flushBuffer() error {
	l.bufferMutex.Lock()
	if len(l.buffer) == 0 {
		l.bufferMutex.Unlock()
		return nil
	}

	// Copy buffer and clear it
	events := make([]*AuditEvent, len(l.buffer))
	copy(events, l.buffer)
	l.buffer = l.buffer[:0]
	l.bufferMutex.Unlock()

	// Write events to file
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for _, event := range events {
		if err := l.writeEvent(event); err != nil {
			// Re-add failed events to buffer
			l.bufferMutex.Lock()
			l.buffer = append(l.buffer, event)
			l.bufferMutex.Unlock()
			return fmt.Errorf("failed to write audit event: %w", err)
		}
	}

	// Sync to disk
	if l.currentFile != nil {
		l.currentFile.Sync()
	}

	return nil
}

// writeEvent writes a single event to the current log file
func (l *FileAuditLogger) writeEvent(event *AuditEvent) error {
	// Check if log rotation is needed
	if err := l.checkRotation(); err != nil {
		return fmt.Errorf("log rotation failed: %w", err)
	}

	// Serialize event to JSON
	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Add integrity hash if enabled
	if l.config.IntegrityChecking {
		hash := sha256.Sum256(eventData)
		logLine := fmt.Sprintf("%s|%s\n", hex.EncodeToString(hash[:]), string(eventData))
		_, err = l.currentFile.WriteString(logLine)
	} else {
		_, err = l.currentFile.WriteString(string(eventData) + "\n")
	}

	return err
}

// flushRoutine runs in the background to periodically flush the buffer
func (l *FileAuditLogger) flushRoutine() {
	for {
		select {
		case <-l.flushTicker.C:
			l.flushBuffer()
		case <-l.stopCh:
			// Final flush before stopping
			l.flushBuffer()
			return
		}
	}
}

// openCurrentLogFile opens the current log file for writing
func (l *FileAuditLogger) openCurrentLogFile() error {
	filename := fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02"))
	filepath := filepath.Join(l.config.StoragePath, filename)

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", filepath, err)
	}

	// Close previous file if exists
	if l.currentFile != nil {
		l.currentFile.Close()
	}

	l.currentFile = file
	return nil
}

// checkRotation checks if log rotation is needed and performs it
func (l *FileAuditLogger) checkRotation() error {
	if l.currentFile == nil {
		return l.openCurrentLogFile()
	}

	// Get current file info
	fileInfo, err := l.currentFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Check if rotation is needed
	needsRotation := false

	// Size-based rotation
	if l.config.RotationPolicy.MaxSize > 0 && fileInfo.Size() >= l.config.RotationPolicy.MaxSize {
		needsRotation = true
	}

	// Time-based rotation
	if l.config.RotationPolicy.RotateDaily {
		fileDate := time.Now().Format("2006-01-02")
		currentDate := fileInfo.ModTime().Format("2006-01-02")
		if fileDate != currentDate {
			needsRotation = true
		}
	}

	if needsRotation {
		return l.rotateLog()
	}

	return nil
}

// rotateLog performs log rotation
func (l *FileAuditLogger) rotateLog() error {
	// Close current file
	if l.currentFile != nil {
		l.currentFile.Close()
		l.currentFile = nil
	}

	// Clean up old log files
	if err := l.cleanupOldLogs(); err != nil {
		return fmt.Errorf("failed to cleanup old logs: %w", err)
	}

	// Open new log file
	return l.openCurrentLogFile()
}

// cleanupOldLogs removes old log files based on retention policy
func (l *FileAuditLogger) cleanupOldLogs() error {
	entries, err := os.ReadDir(l.config.StoragePath)
	if err != nil {
		return fmt.Errorf("failed to read log directory: %w", err)
	}

	// Filter and sort log files by modification time
	var logFiles []os.FileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check if it's an audit log file
		if filepath.Ext(info.Name()) == ".log" && 
		   (info.Name()[:6] == "audit-" || info.Name()[:6] == "audit.") {
			logFiles = append(logFiles, info)
		}
	}

	// Remove files that exceed retention policy
	if l.config.RotationPolicy.MaxFiles > 0 && len(logFiles) > l.config.RotationPolicy.MaxFiles {
		// Sort by modification time (oldest first)
		for i := 0; i < len(logFiles)-1; i++ {
			for j := i + 1; j < len(logFiles); j++ {
				if logFiles[i].ModTime().After(logFiles[j].ModTime()) {
					logFiles[i], logFiles[j] = logFiles[j], logFiles[i]
				}
			}
		}

		// Remove oldest files
		filesToRemove := len(logFiles) - l.config.RotationPolicy.MaxFiles
		for i := 0; i < filesToRemove; i++ {
			filePath := filepath.Join(l.config.StoragePath, logFiles[i].Name())
			os.Remove(filePath)
		}
	}

	// Remove files older than MaxAge
	if l.config.RotationPolicy.MaxAge > 0 {
		cutoff := time.Now().Add(-l.config.RotationPolicy.MaxAge)
		for _, file := range logFiles {
			if file.ModTime().Before(cutoff) {
				filePath := filepath.Join(l.config.StoragePath, file.Name())
				os.Remove(filePath)
			}
		}
	}

	return nil
}

// QueryLogs retrieves audit logs based on query parameters
func (l *FileAuditLogger) QueryLogs(ctx context.Context, query *LogQuery) ([]*AuditEvent, error) {
	// First flush any buffered events
	if err := l.flushBuffer(); err != nil {
		return nil, fmt.Errorf("failed to flush buffer: %w", err)
	}

	var events []*AuditEvent
	
	// Read log files
	entries, err := os.ReadDir(l.config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read log directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".log" {
			continue
		}

		filePath := filepath.Join(l.config.StoragePath, entry.Name())
		fileEvents, err := l.readLogFile(filePath, query)
		if err != nil {
			continue // Skip corrupted files
		}

		events = append(events, fileEvents...)
	}

	// Apply additional filtering and sorting
	events = l.filterEvents(events, query)
	events = l.sortEvents(events, query)

	// Apply limit and offset
	if query.Offset > 0 {
		if query.Offset >= len(events) {
			return []*AuditEvent{}, nil
		}
		events = events[query.Offset:]
	}

	if query.Limit > 0 && len(events) > query.Limit {
		events = events[:query.Limit]
	}

	return events, nil
}

// readLogFile reads events from a single log file
func (l *FileAuditLogger) readLogFile(filePath string, query *LogQuery) ([]*AuditEvent, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []*AuditEvent
	
	// Read file line by line
	// In a production implementation, you'd use a more efficient approach
	// like bufio.Scanner for large files
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := []byte{}
	for _, b := range content {
		if b == '\n' {
			if len(lines) > 0 {
				event, err := l.parseLogLine(lines)
				if err == nil && l.matchesQuery(event, query) {
					events = append(events, event)
				}
			}
			lines = []byte{}
		} else {
			lines = append(lines, b)
		}
	}

	return events, nil
}

// parseLogLine parses a single log line into an AuditEvent
func (l *FileAuditLogger) parseLogLine(line []byte) (*AuditEvent, error) {
	var eventData []byte

	if l.config.IntegrityChecking {
		// Split hash and data
		pipeIndex := -1
		for i, b := range line {
			if b == '|' {
				pipeIndex = i
				break
			}
		}
		
		if pipeIndex == -1 {
			return nil, fmt.Errorf("invalid log line format")
		}

		eventData = line[pipeIndex+1:]
		
		// Verify integrity hash
		expectedHash := line[:pipeIndex]
		actualHash := sha256.Sum256(eventData)
		if hex.EncodeToString(actualHash[:]) != string(expectedHash) {
			return nil, fmt.Errorf("integrity check failed")
		}
	} else {
		eventData = line
	}

	var event AuditEvent
	if err := json.Unmarshal(eventData, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return &event, nil
}

// matchesQuery checks if an event matches the query criteria
func (l *FileAuditLogger) matchesQuery(event *AuditEvent, query *LogQuery) bool {
	if query == nil {
		return true
	}

	// Time range filter
	if query.StartTime != nil && event.Timestamp.Before(*query.StartTime) {
		return false
	}
	if query.EndTime != nil && event.Timestamp.After(*query.EndTime) {
		return false
	}

	// Event type filter
	if len(query.EventTypes) > 0 {
		found := false
		for _, eventType := range query.EventTypes {
			if event.EventType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Actor filter
	if query.ActorID != "" && event.Actor.ID != query.ActorID {
		return false
	}

	// Resource filters
	if query.ResourceType != "" && event.Resource.Type != query.ResourceType {
		return false
	}
	if query.ResourceID != "" && event.Resource.ID != query.ResourceID {
		return false
	}

	// Action filter
	if query.Action != "" && event.Action != query.Action {
		return false
	}

	// Result filter
	if query.Result != "" && event.Result != query.Result {
		return false
	}

	// Severity filter
	if query.Severity != "" && event.Severity != query.Severity {
		return false
	}

	return true
}

// filterEvents applies additional filtering to events
func (l *FileAuditLogger) filterEvents(events []*AuditEvent, query *LogQuery) []*AuditEvent {
	// Additional filtering logic can be added here
	return events
}

// sortEvents sorts events based on query parameters
func (l *FileAuditLogger) sortEvents(events []*AuditEvent, query *LogQuery) []*AuditEvent {
	if query == nil || query.OrderBy == "" {
		// Default sort by timestamp descending
		for i := 0; i < len(events)-1; i++ {
			for j := i + 1; j < len(events); j++ {
				if events[i].Timestamp.Before(events[j].Timestamp) {
					events[i], events[j] = events[j], events[i]
				}
			}
		}
		return events
	}

	// Custom sorting logic based on OrderBy field
	// Implementation would depend on specific requirements
	return events
}

// RotateLogs performs manual log rotation
func (l *FileAuditLogger) RotateLogs(ctx context.Context) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.rotateLog()
}

// ForwardLogs forwards logs to external systems
func (l *FileAuditLogger) ForwardLogs(ctx context.Context, destination string) error {
	// Implementation would depend on the specific forwarding destination
	// This is a placeholder for the forwarding logic
	return fmt.Errorf("log forwarding not implemented yet")
}

// Close releases resources and stops the audit logger
func (l *FileAuditLogger) Close() error {
	// Stop the flush routine
	close(l.stopCh)
	if l.flushTicker != nil {
		l.flushTicker.Stop()
	}

	// Final flush
	l.flushBuffer()

	// Close current file
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.currentFile != nil {
		err := l.currentFile.Close()
		l.currentFile = nil
		return err
	}

	return nil
}

// DefaultAuditConfig returns a default audit configuration
func DefaultAuditConfig(storagePath string) *AuditConfig {
	return &AuditConfig{
		Enabled:     true,
		LogLevel:    SeverityInfo,
		StoragePath: storagePath,
		RotationPolicy: LogRotationPolicy{
			MaxSize:     100 * 1024 * 1024, // 100MB
			MaxAge:      30 * 24 * time.Hour, // 30 days
			MaxFiles:    10,
			CompressOld: true,
			RotateDaily: true,
		},
		ForwardingConfig: LogForwardingConfig{
			Enabled:       false,
			BufferSize:    1000,
			FlushInterval: 30 * time.Second,
		},
		EncryptLogs:       false,
		IntegrityChecking: true,
	}
}