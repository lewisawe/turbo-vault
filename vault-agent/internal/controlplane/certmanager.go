package controlplane

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CertManager handles automatic certificate management
type CertManager struct {
	certFile   string
	keyFile    string
	caFile     string
	agentID    string
	renewDays  int
}

// NewCertManager creates a new certificate manager
func NewCertManager(certFile, keyFile, caFile, agentID string) *CertManager {
	return &CertManager{
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		agentID:   agentID,
		renewDays: 30, // Renew 30 days before expiration
	}
}

// EnsureCertificates ensures valid certificates exist
func (cm *CertManager) EnsureCertificates() error {
	// Check if certificates exist and are valid
	if cm.certificatesExist() {
		if valid, err := cm.validateCertificates(); err != nil {
			return fmt.Errorf("failed to validate certificates: %w", err)
		} else if valid {
			return nil // Certificates are valid
		}
	}

	// Generate new certificates if needed
	return cm.generateCertificates()
}

// CheckRenewal checks if certificates need renewal
func (cm *CertManager) CheckRenewal() (bool, error) {
	if !cm.certificatesExist() {
		return true, nil
	}

	cert, err := cm.loadCertificate()
	if err != nil {
		return true, err
	}

	// Check if certificate expires within renewal period
	renewalTime := cert.NotAfter.AddDate(0, 0, -cm.renewDays)
	return time.Now().After(renewalTime), nil
}

// RenewCertificates renews the certificates
func (cm *CertManager) RenewCertificates() error {
	return cm.generateCertificates()
}

// certificatesExist checks if certificate files exist
func (cm *CertManager) certificatesExist() bool {
	_, certErr := os.Stat(cm.certFile)
	_, keyErr := os.Stat(cm.keyFile)
	return certErr == nil && keyErr == nil
}

// validateCertificates validates existing certificates
func (cm *CertManager) validateCertificates() (bool, error) {
	cert, err := cm.loadCertificate()
	if err != nil {
		return false, err
	}

	// Check expiration
	if time.Now().After(cert.NotAfter) {
		return false, nil
	}

	// Check if expires soon
	renewalTime := cert.NotAfter.AddDate(0, 0, -cm.renewDays)
	if time.Now().After(renewalTime) {
		return false, nil
	}

	return true, nil
}

// loadCertificate loads the certificate from file
func (cm *CertManager) loadCertificate() (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(cm.certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// generateCertificates generates new client certificates
func (cm *CertManager) generateCertificates() error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cm.agentID,
			Organization: []string{"KeyVault Agent"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Load CA certificate and key for signing
	caCert, caKey, err := cm.loadCA()
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate
	if err := cm.saveCertificate(certDER); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Save private key
	if err := cm.savePrivateKey(privateKey); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	return nil
}

// loadCA loads the CA certificate and key
func (cm *CertManager) loadCA() (*x509.Certificate, interface{}, error) {
	// For this implementation, we assume the CA cert is provided
	// In a real implementation, this would load from the control plane
	caCertPEM, err := os.ReadFile(cm.caFile)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// For simplicity, return the cert twice (in real implementation, load CA private key)
	return caCert, caCert, nil
}

// saveCertificate saves the certificate to file
func (cm *CertManager) saveCertificate(certDER []byte) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(cm.certFile), 0755); err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return os.WriteFile(cm.certFile, certPEM, 0644)
}

// savePrivateKey saves the private key to file
func (cm *CertManager) savePrivateKey(key *rsa.PrivateKey) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(cm.keyFile), 0755); err != nil {
		return err
	}

	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	return os.WriteFile(cm.keyFile, keyPEM, 0600)
}

// GetTLSConfig returns TLS configuration with current certificates
func (cm *CertManager) GetTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	caCert, err := os.ReadFile(cm.caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
