package vaultagent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMethod represents an authentication method interface
type AuthMethod interface {
	GetHeaders() (map[string]string, error)
	GetTLSConfig() (*tls.Config, error)
}

// APIKeyAuth implements API key authentication
type APIKeyAuth struct {
	APIKey string
}

// NewAPIKeyAuth creates a new API key authentication method
func NewAPIKeyAuth(apiKey string) *APIKeyAuth {
	return &APIKeyAuth{APIKey: apiKey}
}

func (a *APIKeyAuth) GetHeaders() (map[string]string, error) {
	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", a.APIKey),
		"Content-Type":  "application/json",
	}, nil
}

func (a *APIKeyAuth) GetTLSConfig() (*tls.Config, error) {
	return nil, nil
}

// JWTAuth implements JWT token authentication
type JWTAuth struct {
	Token string
}

// NewJWTAuth creates a new JWT authentication method
func NewJWTAuth(token string) *JWTAuth {
	return &JWTAuth{Token: token}
}

// NewJWTAuthFromCredentials creates JWT token from username/password credentials
func NewJWTAuthFromCredentials(username, password, secretKey string, options ...JWTOption) (*JWTAuth, error) {
	config := &JWTConfig{
		Algorithm: "HS256",
		ExpiresIn: 3600,
	}

	for _, option := range options {
		option(config)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(config.ExpiresIn) * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(config.Algorithm), claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return &JWTAuth{Token: tokenString}, nil
}

type JWTConfig struct {
	Algorithm string
	ExpiresIn int64
}

type JWTOption func(*JWTConfig)

func WithJWTAlgorithm(algorithm string) JWTOption {
	return func(c *JWTConfig) {
		c.Algorithm = algorithm
	}
}

func WithJWTExpiresIn(expiresIn int64) JWTOption {
	return func(c *JWTConfig) {
		c.ExpiresIn = expiresIn
	}
}

func (j *JWTAuth) GetHeaders() (map[string]string, error) {
	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", j.Token),
		"Content-Type":  "application/json",
	}, nil
}

func (j *JWTAuth) GetTLSConfig() (*tls.Config, error) {
	return nil, nil
}

// CertificateAuth implements client certificate authentication
type CertificateAuth struct {
	CertPath    string
	KeyPath     string
	KeyPassword string
	certificate tls.Certificate
}

// NewCertificateAuth creates a new certificate authentication method
func NewCertificateAuth(certPath, keyPath, keyPassword string) (*CertificateAuth, error) {
	auth := &CertificateAuth{
		CertPath:    certPath,
		KeyPath:     keyPath,
		KeyPassword: keyPassword,
	}

	if err := auth.loadCertificate(); err != nil {
		return nil, err
	}

	return auth, nil
}

func (c *CertificateAuth) loadCertificate() error {
	cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	c.certificate = cert
	return nil
}

func (c *CertificateAuth) GetHeaders() (map[string]string, error) {
	if len(c.certificate.Certificate) == 0 {
		return nil, fmt.Errorf("certificate not loaded")
	}

	// Parse the certificate to get fingerprint
	cert, err := x509.ParseCertificate(c.certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate SHA256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	return map[string]string{
		"X-Client-Cert-Fingerprint": hex.EncodeToString(fingerprint[:]),
		"Content-Type":              "application/json",
	}, nil
}

func (c *CertificateAuth) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{c.certificate},
	}, nil
}

// OAuthAuth implements OAuth 2.0 authentication
type OAuthAuth struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	Scope        string
	accessToken  string
	tokenExpiry  time.Time
}

// NewOAuthAuth creates a new OAuth authentication method
func NewOAuthAuth(clientID, clientSecret, tokenURL, scope string) *OAuthAuth {
	return &OAuthAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scope:        scope,
	}
}

func (o *OAuthAuth) getAccessToken() (string, error) {
	if o.accessToken != "" && time.Now().Before(o.tokenExpiry) {
		return o.accessToken, nil
	}

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", o.ClientID)
	data.Set("client_secret", o.ClientSecret)
	if o.Scope != "" {
		data.Set("scope", o.Scope)
	}

	// Make token request
	resp, err := http.PostForm(o.TokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to request OAuth token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("OAuth token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response (simplified - would use proper JSON parsing in production)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OAuth response: %w", err)
	}

	// This is a simplified implementation - in production, you'd use proper JSON parsing
	bodyStr := string(body)
	if strings.Contains(bodyStr, "access_token") {
		// Extract token (simplified parsing)
		parts := strings.Split(bodyStr, "\"access_token\":\"")
		if len(parts) > 1 {
			tokenPart := strings.Split(parts[1], "\"")[0]
			o.accessToken = tokenPart
			// Set expiry (default to 1 hour if not specified)
			o.tokenExpiry = time.Now().Add(55 * time.Minute) // 5 minutes buffer
			return o.accessToken, nil
		}
	}

	return "", fmt.Errorf("failed to parse OAuth token response")
}

func (o *OAuthAuth) GetHeaders() (map[string]string, error) {
	token, err := o.getAccessToken()
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
		"Content-Type":  "application/json",
	}, nil
}

func (o *OAuthAuth) GetTLSConfig() (*tls.Config, error) {
	return nil, nil
}

// BasicAuth implements HTTP Basic authentication
type BasicAuth struct {
	Username string
	Password string
}

// NewBasicAuth creates a new basic authentication method
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		Username: username,
		Password: password,
	}
}

func (b *BasicAuth) GetHeaders() (map[string]string, error) {
	credentials := fmt.Sprintf("%s:%s", b.Username, b.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	return map[string]string{
		"Authorization": fmt.Sprintf("Basic %s", encoded),
		"Content-Type":  "application/json",
	}, nil
}

func (b *BasicAuth) GetTLSConfig() (*tls.Config, error) {
	return nil, nil
}