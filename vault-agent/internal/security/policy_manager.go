package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SecurityPolicyManagerImpl implements security policy management
type SecurityPolicyManagerImpl struct {
	config *PolicyManagerConfig
}

type PolicyManagerConfig struct {
	TemplatesPath    string   `json:"templates_path"`
	PoliciesPath     string   `json:"policies_path"`
	EnabledCategories []string `json:"enabled_categories"`
	AutoApply        bool     `json:"auto_apply"`
	ValidationStrict bool     `json:"validation_strict"`
}

type PolicyTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Category    PolicyCategory         `json:"category"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Rules       []*PolicyRuleTemplate  `json:"rules"`
	Parameters  []*PolicyParameter     `json:"parameters"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type PolicyRuleTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Condition   string                 `json:"condition"`
	Action      string                 `json:"action"`
	Parameters  []string               `json:"parameters"`
	Required    bool                   `json:"required"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type PolicyParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Description  string      `json:"description"`
	DefaultValue interface{} `json:"default_value"`
	Required     bool        `json:"required"`
	Validation   string      `json:"validation"`
}

type PolicyValidation struct {
	ID          string                 `json:"id"`
	PolicyID    string                 `json:"policy_id"`
	Valid       bool                   `json:"valid"`
	Score       float64                `json:"score"`
	Errors      []*ValidationError     `json:"errors"`
	Warnings    []*ValidationWarning   `json:"warnings"`
	Suggestions []*PolicySuggestion    `json:"suggestions"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
}

type ValidationError struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Severity    SeverityLevel `json:"severity"`
	Message     string        `json:"message"`
	Location    string        `json:"location"`
	Suggestion  string        `json:"suggestion"`
}

type ValidationWarning struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Message    string `json:"message"`
	Location   string `json:"location"`
	Suggestion string `json:"suggestion"`
}

type PolicySuggestion struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Priority    SeverityLevel `json:"priority"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Action      string        `json:"action"`
}

type BestPracticeGuide struct {
	ID          string                    `json:"id"`
	Category    string                    `json:"category"`
	Title       string                    `json:"title"`
	Description string                    `json:"description"`
	Practices   []*BestPractice           `json:"practices"`
	References  []*Reference              `json:"references"`
	Compliance  []ComplianceStandard      `json:"compliance"`
	Metadata    map[string]interface{}    `json:"metadata"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

type BestPractice struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Priority    SeverityLevel `json:"priority"`
	Steps       []string      `json:"steps"`
	Examples    []string      `json:"examples"`
	Rationale   string        `json:"rationale"`
}

type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Type  string `json:"type"`
}

type PolicyRecommendation struct {
	ID          string                 `json:"id"`
	Category    PolicyCategory         `json:"category"`
	Priority    SeverityLevel          `json:"priority"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Rationale   string                 `json:"rationale"`
	Actions     []*RecommendedAction   `json:"actions"`
	Impact      string                 `json:"impact"`
	Effort      string                 `json:"effort"`
	Timeline    string                 `json:"timeline"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type RecommendedAction struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Config      string `json:"config,omitempty"`
}

// NewSecurityPolicyManager creates a new security policy manager
func NewSecurityPolicyManager(config *PolicyManagerConfig) *SecurityPolicyManagerImpl {
	if config == nil {
		config = &PolicyManagerConfig{
			TemplatesPath:     "./security/templates/",
			PoliciesPath:      "./security/policies/",
			EnabledCategories: []string{"access", "encryption", "audit", "network"},
			AutoApply:         false,
			ValidationStrict:  true,
		}
	}
	return &SecurityPolicyManagerImpl{config: config}
}

// CreatePolicyTemplate creates a new security policy template
func (p *SecurityPolicyManagerImpl) CreatePolicyTemplate(ctx context.Context, template *PolicyTemplate) error {
	// Validate template
	if err := p.validateTemplate(template); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Set metadata
	template.ID = uuid.New().String()
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	// Save template to file
	templatePath := filepath.Join(p.config.TemplatesPath, fmt.Sprintf("%s.json", template.ID))
	if err := p.saveTemplateToFile(template, templatePath); err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	return nil
}

// ApplySecurityPolicy applies a security policy
func (p *SecurityPolicyManagerImpl) ApplySecurityPolicy(ctx context.Context, policy *SecurityPolicy) error {
	// Validate policy before applying
	validation, err := p.ValidatePolicyCompliance(ctx, policy)
	if err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	if !validation.Valid && p.config.ValidationStrict {
		return fmt.Errorf("policy validation failed with %d errors", len(validation.Errors))
	}

	// Apply policy rules
	for _, rule := range policy.Rules {
		if err := p.applyPolicyRule(ctx, rule); err != nil {
			return fmt.Errorf("failed to apply rule %s: %w", rule.ID, err)
		}
	}

	// Save applied policy
	policyPath := filepath.Join(p.config.PoliciesPath, fmt.Sprintf("%s.json", policy.ID))
	if err := p.savePolicyToFile(policy, policyPath); err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}

	return nil
}

// ValidatePolicyCompliance validates policy compliance
func (p *SecurityPolicyManagerImpl) ValidatePolicyCompliance(ctx context.Context, policy *SecurityPolicy) (*PolicyValidation, error) {
	validation := &PolicyValidation{
		ID:          uuid.New().String(),
		PolicyID:    policy.ID,
		Valid:       true,
		Score:       100.0,
		Errors:      []*ValidationError{},
		Warnings:    []*ValidationWarning{},
		Suggestions: []*PolicySuggestion{},
		Metadata:    make(map[string]interface{}),
		Timestamp:   time.Now(),
	}

	// Validate policy structure
	if err := p.validatePolicyStructure(policy, validation); err != nil {
		return validation, err
	}

	// Validate policy rules
	if err := p.validatePolicyRules(policy, validation); err != nil {
		return validation, err
	}

	// Validate policy enforcement
	if err := p.validatePolicyEnforcement(policy, validation); err != nil {
		return validation, err
	}

	// Calculate final score
	validation.Score = p.calculateValidationScore(validation)
	validation.Valid = validation.Score >= 70.0 && len(validation.Errors) == 0

	return validation, nil
}

// GetBestPracticeGuides returns best practice guides for a category
func (p *SecurityPolicyManagerImpl) GetBestPracticeGuides(ctx context.Context, category string) ([]*BestPracticeGuide, error) {
	guides := []*BestPracticeGuide{}

	switch strings.ToLower(category) {
	case "encryption":
		guides = append(guides, p.getEncryptionBestPractices())
	case "access":
		guides = append(guides, p.getAccessControlBestPractices())
	case "audit":
		guides = append(guides, p.getAuditBestPractices())
	case "network":
		guides = append(guides, p.getNetworkSecurityBestPractices())
	case "compliance":
		guides = append(guides, p.getComplianceBestPractices())
	default:
		// Return all guides
		guides = append(guides, p.getEncryptionBestPractices())
		guides = append(guides, p.getAccessControlBestPractices())
		guides = append(guides, p.getAuditBestPractices())
		guides = append(guides, p.getNetworkSecurityBestPractices())
		guides = append(guides, p.getComplianceBestPractices())
	}

	return guides, nil
}

// GeneratePolicyRecommendations generates policy recommendations
func (p *SecurityPolicyManagerImpl) GeneratePolicyRecommendations(ctx context.Context) ([]*PolicyRecommendation, error) {
	recommendations := []*PolicyRecommendation{}

	// Generate encryption recommendations
	encryptionRecs := p.generateEncryptionRecommendations()
	recommendations = append(recommendations, encryptionRecs...)

	// Generate access control recommendations
	accessRecs := p.generateAccessControlRecommendations()
	recommendations = append(recommendations, accessRecs...)

	// Generate audit recommendations
	auditRecs := p.generateAuditRecommendations()
	recommendations = append(recommendations, auditRecs...)

	// Generate network security recommendations
	networkRecs := p.generateNetworkRecommendations()
	recommendations = append(recommendations, networkRecs...)

	return recommendations, nil
}

// Helper methods for template validation

func (p *SecurityPolicyManagerImpl) validateTemplate(template *PolicyTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}

	if template.Category == "" {
		return fmt.Errorf("template category is required")
	}

	if len(template.Rules) == 0 {
		return fmt.Errorf("template must have at least one rule")
	}

	for _, rule := range template.Rules {
		if err := p.validateRuleTemplate(rule); err != nil {
			return fmt.Errorf("invalid rule template %s: %w", rule.ID, err)
		}
	}

	return nil
}

func (p *SecurityPolicyManagerImpl) validateRuleTemplate(rule *PolicyRuleTemplate) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if rule.Condition == "" {
		return fmt.Errorf("rule condition is required")
	}

	if rule.Action == "" {
		return fmt.Errorf("rule action is required")
	}

	return nil
}

// Helper methods for policy validation

func (p *SecurityPolicyManagerImpl) validatePolicyStructure(policy *SecurityPolicy, validation *PolicyValidation) error {
	if policy.Name == "" {
		validation.Errors = append(validation.Errors, &ValidationError{
			ID:       uuid.New().String(),
			Type:     "structure",
			Severity: SeverityHigh,
			Message:  "Policy name is required",
			Location: "policy.name",
			Suggestion: "Provide a descriptive name for the policy",
		})
	}

	if len(policy.Rules) == 0 {
		validation.Errors = append(validation.Errors, &ValidationError{
			ID:       uuid.New().String(),
			Type:     "structure",
			Severity: SeverityHigh,
			Message:  "Policy must have at least one rule",
			Location: "policy.rules",
			Suggestion: "Add one or more policy rules",
		})
	}

	return nil
}

func (p *SecurityPolicyManagerImpl) validatePolicyRules(policy *SecurityPolicy, validation *PolicyValidation) error {
	for i, rule := range policy.Rules {
		if rule.Name == "" {
			validation.Errors = append(validation.Errors, &ValidationError{
				ID:       uuid.New().String(),
				Type:     "rule",
				Severity: SeverityMedium,
				Message:  "Rule name is required",
				Location: fmt.Sprintf("policy.rules[%d].name", i),
				Suggestion: "Provide a descriptive name for the rule",
			})
		}

		if rule.Condition == "" {
			validation.Errors = append(validation.Errors, &ValidationError{
				ID:       uuid.New().String(),
				Type:     "rule",
				Severity: SeverityHigh,
				Message:  "Rule condition is required",
				Location: fmt.Sprintf("policy.rules[%d].condition", i),
				Suggestion: "Define the condition that triggers this rule",
			})
		}

		if rule.Action == "" {
			validation.Errors = append(validation.Errors, &ValidationError{
				ID:       uuid.New().String(),
				Type:     "rule",
				Severity: SeverityHigh,
				Message:  "Rule action is required",
				Location: fmt.Sprintf("policy.rules[%d].action", i),
				Suggestion: "Define the action to take when the condition is met",
			})
		}
	}

	return nil
}

func (p *SecurityPolicyManagerImpl) validatePolicyEnforcement(policy *SecurityPolicy, validation *PolicyValidation) error {
	if policy.Enforcement == "" {
		validation.Warnings = append(validation.Warnings, &ValidationWarning{
			ID:       uuid.New().String(),
			Type:     "enforcement",
			Message:  "No enforcement level specified",
			Location: "policy.enforcement",
			Suggestion: "Specify enforcement level (advisory, warning, enforcing, blocking)",
		})
	}

	return nil
}

func (p *SecurityPolicyManagerImpl) calculateValidationScore(validation *PolicyValidation) float64 {
	score := 100.0

	// Deduct points for errors
	for _, err := range validation.Errors {
		switch err.Severity {
		case SeverityCritical:
			score -= 25.0
		case SeverityHigh:
			score -= 15.0
		case SeverityMedium:
			score -= 10.0
		case SeverityLow:
			score -= 5.0
		}
	}

	// Deduct points for warnings
	for range validation.Warnings {
		score -= 2.0
	}

	if score < 0 {
		score = 0
	}

	return score
}

// Helper methods for policy application

func (p *SecurityPolicyManagerImpl) applyPolicyRule(ctx context.Context, rule *PolicyRule) error {
	// In a real implementation, this would apply the rule to the system
	// For now, just validate the rule structure
	
	if rule.Condition == "" {
		return fmt.Errorf("rule condition is empty")
	}

	if rule.Action == "" {
		return fmt.Errorf("rule action is empty")
	}

	// Simulate rule application
	return nil
}

// Best practice guide generators

func (p *SecurityPolicyManagerImpl) getEncryptionBestPractices() *BestPracticeGuide {
	return &BestPracticeGuide{
		ID:          uuid.New().String(),
		Category:    "encryption",
		Title:       "Encryption Best Practices",
		Description: "Guidelines for implementing strong encryption in vault agent deployments",
		Practices: []*BestPractice{
			{
				ID:          uuid.New().String(),
				Title:       "Use Strong Encryption Algorithms",
				Description: "Implement AES-256-GCM for symmetric encryption and RSA-4096 or ECDSA P-384 for asymmetric encryption",
				Priority:    SeverityCritical,
				Steps: []string{
					"Configure AES-256-GCM for data encryption",
					"Use RSA-4096 or ECDSA P-384 for key exchange",
					"Implement proper key derivation functions (PBKDF2, scrypt, or Argon2)",
					"Enable perfect forward secrecy for communication",
				},
				Examples: []string{
					"encryption_algorithm: AES-256-GCM",
					"key_derivation: PBKDF2-SHA256",
					"key_size: 256",
				},
				Rationale: "Strong encryption algorithms protect against current and future cryptographic attacks",
			},
			{
				ID:          uuid.New().String(),
				Title:       "Implement Proper Key Management",
				Description: "Use secure key generation, storage, and rotation practices",
				Priority:    SeverityCritical,
				Steps: []string{
					"Generate keys using cryptographically secure random number generators",
					"Store keys in hardware security modules (HSMs) when possible",
					"Implement automatic key rotation policies",
					"Use key escrow for disaster recovery",
				},
				Examples: []string{
					"key_rotation_interval: 90d",
					"key_storage: hsm",
					"backup_keys: encrypted",
				},
				Rationale: "Proper key management is essential for maintaining encryption security over time",
			},
		},
		References: []*Reference{
			{Title: "NIST Cryptographic Standards", URL: "https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines", Type: "standard"},
			{Title: "OWASP Cryptographic Storage Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html", Type: "guide"},
		},
		Compliance: []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, CompliancePCIDSS},
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

func (p *SecurityPolicyManagerImpl) getAccessControlBestPractices() *BestPracticeGuide {
	return &BestPracticeGuide{
		ID:          uuid.New().String(),
		Category:    "access",
		Title:       "Access Control Best Practices",
		Description: "Guidelines for implementing robust access control mechanisms",
		Practices: []*BestPractice{
			{
				ID:          uuid.New().String(),
				Title:       "Implement Least Privilege Access",
				Description: "Grant users and services only the minimum permissions necessary to perform their functions",
				Priority:    SeverityHigh,
				Steps: []string{
					"Define role-based access control (RBAC) policies",
					"Implement attribute-based access control (ABAC) for fine-grained permissions",
					"Regular access reviews and permission audits",
					"Implement just-in-time (JIT) access for administrative functions",
				},
				Examples: []string{
					"role: secret-reader",
					"permissions: [read]",
					"resources: [secrets/app/*]",
				},
				Rationale: "Limiting access reduces the attack surface and potential for privilege escalation",
			},
			{
				ID:          uuid.New().String(),
				Title:       "Enable Multi-Factor Authentication",
				Description: "Require multiple authentication factors for accessing sensitive resources",
				Priority:    SeverityHigh,
				Steps: []string{
					"Implement TOTP-based MFA",
					"Support hardware security keys (FIDO2/WebAuthn)",
					"Enable adaptive authentication based on risk factors",
					"Provide backup authentication methods",
				},
				Examples: []string{
					"mfa_required: true",
					"mfa_methods: [totp, webauthn]",
					"adaptive_auth: enabled",
				},
				Rationale: "MFA significantly reduces the risk of unauthorized access even if credentials are compromised",
			},
		},
		References: []*Reference{
			{Title: "NIST Access Control Guidelines", URL: "https://csrc.nist.gov/publications/detail/sp/800-162/final", Type: "standard"},
			{Title: "OWASP Access Control Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html", Type: "guide"},
		},
		Compliance: []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, ComplianceHIPAA},
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

func (p *SecurityPolicyManagerImpl) getAuditBestPractices() *BestPracticeGuide {
	return &BestPracticeGuide{
		ID:          uuid.New().String(),
		Category:    "audit",
		Title:       "Audit and Logging Best Practices",
		Description: "Guidelines for comprehensive audit logging and monitoring",
		Practices: []*BestPractice{
			{
				ID:          uuid.New().String(),
				Title:       "Implement Comprehensive Audit Logging",
				Description: "Log all security-relevant events with sufficient detail for forensic analysis",
				Priority:    SeverityHigh,
				Steps: []string{
					"Log all authentication and authorization events",
					"Record all secret access and modification operations",
					"Include contextual information (user, IP, timestamp, etc.)",
					"Implement log integrity protection",
				},
				Examples: []string{
					"audit_events: [auth, access, modify, delete]",
					"log_format: json",
					"integrity_protection: enabled",
				},
				Rationale: "Comprehensive audit logs are essential for security monitoring and compliance",
			},
		},
		References: []*Reference{
			{Title: "NIST Audit and Accountability Guidelines", URL: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", Type: "standard"},
		},
		Compliance: []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, ComplianceHIPAA, CompliancePCIDSS},
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

func (p *SecurityPolicyManagerImpl) getNetworkSecurityBestPractices() *BestPracticeGuide {
	return &BestPracticeGuide{
		ID:          uuid.New().String(),
		Category:    "network",
		Title:       "Network Security Best Practices",
		Description: "Guidelines for securing network communications and infrastructure",
		Practices: []*BestPractice{
			{
				ID:          uuid.New().String(),
				Title:       "Implement Zero-Trust Network Architecture",
				Description: "Never trust, always verify network communications",
				Priority:    SeverityHigh,
				Steps: []string{
					"Implement mutual TLS (mTLS) for all communications",
					"Use network segmentation and micro-segmentation",
					"Deploy network monitoring and intrusion detection",
					"Implement certificate-based device authentication",
				},
				Examples: []string{
					"mtls_required: true",
					"network_segmentation: enabled",
					"certificate_auth: required",
				},
				Rationale: "Zero-trust architecture provides defense in depth against network-based attacks",
			},
		},
		References: []*Reference{
			{Title: "NIST Zero Trust Architecture", URL: "https://csrc.nist.gov/publications/detail/sp/800-207/final", Type: "standard"},
		},
		Compliance: []ComplianceStandard{ComplianceSOC2, ComplianceISO27001},
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

func (p *SecurityPolicyManagerImpl) getComplianceBestPractices() *BestPracticeGuide {
	return &BestPracticeGuide{
		ID:          uuid.New().String(),
		Category:    "compliance",
		Title:       "Compliance Best Practices",
		Description: "Guidelines for maintaining regulatory compliance",
		Practices: []*BestPractice{
			{
				ID:          uuid.New().String(),
				Title:       "Implement Continuous Compliance Monitoring",
				Description: "Continuously monitor and validate compliance with regulatory requirements",
				Priority:    SeverityHigh,
				Steps: []string{
					"Implement automated compliance scanning",
					"Generate regular compliance reports",
					"Maintain evidence collection and documentation",
					"Perform regular compliance assessments",
				},
				Examples: []string{
					"compliance_scanning: automated",
					"report_frequency: monthly",
					"evidence_retention: 7_years",
				},
				Rationale: "Continuous monitoring ensures ongoing compliance and reduces audit burden",
			},
		},
		References: []*Reference{
			{Title: "SOC 2 Compliance Guide", URL: "https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html", Type: "standard"},
		},
		Compliance: []ComplianceStandard{ComplianceSOC2, ComplianceISO27001, ComplianceHIPAA, CompliancePCIDSS},
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// Recommendation generators

func (p *SecurityPolicyManagerImpl) generateEncryptionRecommendations() []*PolicyRecommendation {
	return []*PolicyRecommendation{
		{
			ID:          uuid.New().String(),
			Category:    PolicyCategoryEncryption,
			Priority:    SeverityHigh,
			Title:       "Upgrade to AES-256-GCM Encryption",
			Description: "Replace any weaker encryption algorithms with AES-256-GCM",
			Rationale:   "AES-256-GCM provides authenticated encryption and is recommended by security standards",
			Actions: []*RecommendedAction{
				{
					ID:          uuid.New().String(),
					Type:        "config",
					Description: "Update encryption configuration",
					Config:      "encryption:\n  algorithm: AES-256-GCM\n  key_size: 256",
				},
			},
			Impact:   "High - Significantly improves data protection",
			Effort:   "Medium - Requires configuration changes and key rotation",
			Timeline: "30 days",
			Metadata: make(map[string]interface{}),
		},
	}
}

func (p *SecurityPolicyManagerImpl) generateAccessControlRecommendations() []*PolicyRecommendation {
	return []*PolicyRecommendation{
		{
			ID:          uuid.New().String(),
			Category:    PolicyCategoryAccess,
			Priority:    SeverityHigh,
			Title:       "Implement Multi-Factor Authentication",
			Description: "Enable MFA for all user accounts accessing the vault agent",
			Rationale:   "MFA significantly reduces the risk of unauthorized access",
			Actions: []*RecommendedAction{
				{
					ID:          uuid.New().String(),
					Type:        "config",
					Description: "Enable MFA in authentication configuration",
					Config:      "auth:\n  mfa_required: true\n  mfa_methods: [totp, webauthn]",
				},
			},
			Impact:   "High - Greatly improves authentication security",
			Effort:   "Medium - Requires user enrollment and configuration",
			Timeline: "60 days",
			Metadata: make(map[string]interface{}),
		},
	}
}

func (p *SecurityPolicyManagerImpl) generateAuditRecommendations() []*PolicyRecommendation {
	return []*PolicyRecommendation{
		{
			ID:          uuid.New().String(),
			Category:    PolicyCategoryAudit,
			Priority:    SeverityMedium,
			Title:       "Enable Comprehensive Audit Logging",
			Description: "Configure detailed audit logging for all security events",
			Rationale:   "Comprehensive audit logs are essential for security monitoring and compliance",
			Actions: []*RecommendedAction{
				{
					ID:          uuid.New().String(),
					Type:        "config",
					Description: "Configure audit logging",
					Config:      "audit:\n  enabled: true\n  events: [auth, access, modify, delete]\n  format: json",
				},
			},
			Impact:   "Medium - Improves security monitoring capabilities",
			Effort:   "Low - Configuration change only",
			Timeline: "14 days",
			Metadata: make(map[string]interface{}),
		},
	}
}

func (p *SecurityPolicyManagerImpl) generateNetworkRecommendations() []*PolicyRecommendation {
	return []*PolicyRecommendation{
		{
			ID:          uuid.New().String(),
			Category:    PolicyCategoryNetwork,
			Priority:    SeverityHigh,
			Title:       "Implement Zero-Trust Network Security",
			Description: "Configure zero-trust network policies and mTLS communication",
			Rationale:   "Zero-trust architecture provides defense in depth against network attacks",
			Actions: []*RecommendedAction{
				{
					ID:          uuid.New().String(),
					Type:        "config",
					Description: "Enable zero-trust networking",
					Config:      "network:\n  zero_trust: enabled\n  mtls_required: true\n  certificate_auth: required",
				},
			},
			Impact:   "High - Significantly improves network security",
			Effort:   "High - Requires certificate management and network reconfiguration",
			Timeline: "90 days",
			Metadata: make(map[string]interface{}),
		},
	}
}

// File operations

func (p *SecurityPolicyManagerImpl) saveTemplateToFile(template *PolicyTemplate, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal template to JSON
	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(path, data, 0644)
}

func (p *SecurityPolicyManagerImpl) savePolicyToFile(policy *SecurityPolicy, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal policy to JSON
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(path, data, 0644)
}