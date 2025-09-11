package notification

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// TemplateManagerImpl implements the TemplateManager interface
type TemplateManagerImpl struct {
	templates map[string]*Template
	compiled  map[string]*template.Template
	logger    *logrus.Logger
	mu        sync.RWMutex
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(logger *logrus.Logger) *TemplateManagerImpl {
	tm := &TemplateManagerImpl{
		templates: make(map[string]*Template),
		compiled:  make(map[string]*template.Template),
		logger:    logger,
	}

	// Register default templates
	tm.registerDefaultTemplates()

	return tm
}

// RegisterTemplate registers a new notification template
func (tm *TemplateManagerImpl) RegisterTemplate(ctx context.Context, template *Template) error {
	if template.ID == "" {
		template.ID = uuid.New().String()
	}

	// Validate template
	if err := tm.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	// Compile template
	compiled, err := tm.compileTemplate(template)
	if err != nil {
		return fmt.Errorf("failed to compile template: %w", err)
	}

	// Set timestamps
	now := time.Now()
	if template.CreatedAt.IsZero() {
		template.CreatedAt = now
	}
	template.UpdatedAt = now

	tm.mu.Lock()
	tm.templates[template.ID] = template
	tm.compiled[template.ID] = compiled
	tm.mu.Unlock()

	tm.logger.Infof("Registered template %s (%s)", template.ID, template.Name)
	return nil
}

// UpdateTemplate updates an existing template
func (tm *TemplateManagerImpl) UpdateTemplate(ctx context.Context, template *Template) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	existing, exists := tm.templates[template.ID]
	if !exists {
		return fmt.Errorf("template %s not found", template.ID)
	}

	// Validate template
	if err := tm.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	// Compile template
	compiled, err := tm.compileTemplate(template)
	if err != nil {
		return fmt.Errorf("failed to compile template: %w", err)
	}

	// Preserve creation time
	template.CreatedAt = existing.CreatedAt
	template.UpdatedAt = time.Now()

	tm.templates[template.ID] = template
	tm.compiled[template.ID] = compiled

	tm.logger.Infof("Updated template %s", template.ID)
	return nil
}

// DeleteTemplate deletes a template
func (tm *TemplateManagerImpl) DeleteTemplate(ctx context.Context, templateID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.templates[templateID]; !exists {
		return fmt.Errorf("template %s not found", templateID)
	}

	delete(tm.templates, templateID)
	delete(tm.compiled, templateID)

	tm.logger.Infof("Deleted template %s", templateID)
	return nil
}

// GetTemplate retrieves a template by ID
func (tm *TemplateManagerImpl) GetTemplate(ctx context.Context, templateID string) (*Template, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	template, exists := tm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template %s not found", templateID)
	}

	// Return a copy
	templateCopy := *template
	return &templateCopy, nil
}

// ListTemplates lists all templates
func (tm *TemplateManagerImpl) ListTemplates(ctx context.Context) ([]*Template, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	templates := make([]*Template, 0, len(tm.templates))
	for _, template := range tm.templates {
		templateCopy := *template
		templates = append(templates, &templateCopy)
	}

	return templates, nil
}

// RenderTemplate renders a template with the provided data
func (tm *TemplateManagerImpl) RenderTemplate(ctx context.Context, templateID string, data interface{}) (string, error) {
	tm.mu.RLock()
	compiled, exists := tm.compiled[templateID]
	tm.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("template %s not found", templateID)
	}

	var buffer bytes.Buffer
	if err := compiled.Execute(&buffer, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buffer.String(), nil
}

// validateTemplate validates a template
func (tm *TemplateManagerImpl) validateTemplate(template *Template) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}

	if template.Body == "" {
		return fmt.Errorf("template body is required")
	}

	// Extract variables from template
	variables := tm.extractVariables(template.Body)
	template.Variables = variables

	return nil
}

// compileTemplate compiles a template
func (tm *TemplateManagerImpl) compileTemplate(tmpl *Template) (*template.Template, error) {
	t := template.New(tmpl.ID)
	
	// Add custom functions
	t.Funcs(tm.getTemplateFunctions())

	compiled, err := t.Parse(tmpl.Body)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %w", err)
	}

	return compiled, nil
}

// extractVariables extracts variable names from template body
func (tm *TemplateManagerImpl) extractVariables(body string) []string {
	// Regular expression to match template variables
	re := regexp.MustCompile(`\{\{\s*\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\}\}`)
	matches := re.FindAllStringSubmatch(body, -1)

	variableSet := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			variableSet[match[1]] = true
		}
	}

	variables := make([]string, 0, len(variableSet))
	for variable := range variableSet {
		variables = append(variables, variable)
	}

	return variables
}

// getTemplateFunctions returns custom template functions
func (tm *TemplateManagerImpl) getTemplateFunctions() template.FuncMap {
	return template.FuncMap{
		"formatTime": func(t time.Time, layout string) string {
			if layout == "" {
				layout = time.RFC3339
			}
			return t.Format(layout)
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": strings.Title,
		"join": func(sep string, items []string) string {
			return strings.Join(items, sep)
		},
		"default": func(defaultValue interface{}, value interface{}) interface{} {
			if value == nil || (reflect.ValueOf(value).Kind() == reflect.String && value.(string) == "") {
				return defaultValue
			}
			return value
		},
		"contains": strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
		},
		"truncate": func(length int, s string) string {
			if len(s) <= length {
				return s
			}
			return s[:length] + "..."
		},
		"now": time.Now,
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"mul": func(a, b int) int {
			return a * b
		},
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
	}
}

// registerDefaultTemplates registers default notification templates
func (tm *TemplateManagerImpl) registerDefaultTemplates() {
	defaultTemplates := []*Template{
		{
			ID:   "secret_rotation_success",
			Name: "Secret Rotation Success",
			Type: NotificationTypeEmail,
			Subject: "Secret Rotation Completed Successfully",
			Body: `Secret rotation completed successfully.

Secret: {{.secret.name}}
Rotated At: {{formatTime .rotation.completed_at "2006-01-02 15:04:05"}}
New Version: {{.secret.version}}
Rotated By: {{default "System" .rotation.triggered_by}}

{{if .rotation.notes}}
Notes: {{.rotation.notes}}
{{end}}

This is an automated notification from the Vault Agent.`,
			Variables: []string{"secret.name", "secret.version", "rotation.completed_at", "rotation.triggered_by", "rotation.notes"},
		},
		{
			ID:   "secret_rotation_failed",
			Name: "Secret Rotation Failed",
			Type: NotificationTypeEmail,
			Subject: "Secret Rotation Failed",
			Body: `Secret rotation failed and requires attention.

Secret: {{.secret.name}}
Failed At: {{formatTime .rotation.failed_at "2006-01-02 15:04:05"}}
Error: {{.rotation.error}}
Attempt: {{.rotation.attempt}} of {{.rotation.max_attempts}}

{{if .rotation.next_retry}}
Next Retry: {{formatTime .rotation.next_retry "2006-01-02 15:04:05"}}
{{else}}
No more retries scheduled. Manual intervention required.
{{end}}

This is an automated notification from the Vault Agent.`,
			Variables: []string{"secret.name", "rotation.failed_at", "rotation.error", "rotation.attempt", "rotation.max_attempts", "rotation.next_retry"},
		},
		{
			ID:   "secret_expired",
			Name: "Secret Expired",
			Type: NotificationTypeEmail,
			Subject: "Secret Has Expired",
			Body: `A secret has expired and may need attention.

Secret: {{.secret.name}}
Expired At: {{formatTime .secret.expires_at "2006-01-02 15:04:05"}}
Last Accessed: {{if .secret.last_accessed}}{{formatTime .secret.last_accessed "2006-01-02 15:04:05"}}{{else}}Never{{end}}

{{if .secret.auto_rotation_enabled}}
Automatic rotation is enabled for this secret.
{{else}}
Please update this secret manually or enable automatic rotation.
{{end}}

This is an automated notification from the Vault Agent.`,
			Variables: []string{"secret.name", "secret.expires_at", "secret.last_accessed", "secret.auto_rotation_enabled"},
		},
		{
			ID:   "auth_failure",
			Name: "Authentication Failure",
			Type: NotificationTypeEmail,
			Subject: "Authentication Failure Detected",
			Body: `An authentication failure has been detected.

User: {{default "Unknown" .auth.user}}
IP Address: {{.auth.ip_address}}
User Agent: {{.auth.user_agent}}
Failed At: {{formatTime .auth.failed_at "2006-01-02 15:04:05"}}
Reason: {{.auth.failure_reason}}

{{if .auth.consecutive_failures}}
Consecutive Failures: {{.auth.consecutive_failures}}
{{end}}

Please investigate this authentication failure.

This is an automated notification from the Vault Agent.`,
			Variables: []string{"auth.user", "auth.ip_address", "auth.user_agent", "auth.failed_at", "auth.failure_reason", "auth.consecutive_failures"},
		},
		{
			ID:   "policy_violation",
			Name: "Policy Violation",
			Type: NotificationTypeEmail,
			Subject: "Policy Violation Detected",
			Body: `A policy violation has been detected.

User: {{.violation.user}}
Policy: {{.violation.policy_name}}
Resource: {{.violation.resource}}
Action: {{.violation.action}}
Violated At: {{formatTime .violation.timestamp "2006-01-02 15:04:05"}}
IP Address: {{.violation.ip_address}}

Violation Details:
{{.violation.details}}

This access has been denied and logged for review.

This is an automated notification from the Vault Agent.`,
			Variables: []string{"violation.user", "violation.policy_name", "violation.resource", "violation.action", "violation.timestamp", "violation.ip_address", "violation.details"},
		},
		{
			ID:   "system_health",
			Name: "System Health Alert",
			Type: NotificationTypeEmail,
			Subject: "System Health Alert - {{upper .health.status}}",
			Body: `System health alert detected.

Status: {{upper .health.status}}
Component: {{.health.component}}
Message: {{.health.message}}
Detected At: {{formatTime .health.timestamp "2006-01-02 15:04:05"}}

{{if .health.metrics}}
Metrics:
{{range $key, $value := .health.metrics}}
- {{$key}}: {{$value}}
{{end}}
{{end}}

{{if eq .health.status "critical"}}
Immediate attention required.
{{else if eq .health.status "warning"}}
Please investigate when possible.
{{end}}

This is an automated notification from the Vault Agent.`,
			Variables: []string{"health.status", "health.component", "health.message", "health.timestamp", "health.metrics"},
		},
	}

	for _, template := range defaultTemplates {
		template.CreatedAt = time.Now()
		template.UpdatedAt = time.Now()
		
		compiled, err := tm.compileTemplate(template)
		if err != nil {
			tm.logger.Errorf("Failed to compile default template %s: %v", template.ID, err)
			continue
		}

		tm.templates[template.ID] = template
		tm.compiled[template.ID] = compiled
	}

	tm.logger.Infof("Registered %d default templates", len(defaultTemplates))
}