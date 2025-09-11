package crypto

import (
	"fmt"
)

// KeyManagerFactory creates key managers based on configuration
type KeyManagerFactory struct{}

// NewKeyManagerFactory creates a new key manager factory
func NewKeyManagerFactory() *KeyManagerFactory {
	return &KeyManagerFactory{}
}

// CreateKeyManager creates a key manager based on the provided configuration
func (f *KeyManagerFactory) CreateKeyManager(config *KeyManagerConfig) (KeyManager, error) {
	if config == nil {
		return nil, fmt.Errorf("key manager config cannot be nil")
	}

	switch config.Type {
	case KeyTypeFile:
		if config.FilePath == "" {
			return nil, fmt.Errorf("file path is required for file-based key manager")
		}
		return NewFileKeyManager(config.FilePath)

	case KeyTypeHSM:
		if config.HSMConfig == nil {
			return nil, fmt.Errorf("HSM config is required for HSM-based key manager")
		}
		return NewHSMKeyManager(config.HSMConfig)

	case KeyTypeCloud:
		if config.CloudConfig == nil {
			return nil, fmt.Errorf("cloud config is required for cloud-based key manager")
		}
		return NewCloudKMSKeyManager(config.CloudConfig)

	default:
		return nil, fmt.Errorf("unsupported key manager type: %s", config.Type)
	}
}

// CreateEncryptor creates an encryptor that works with the provided key manager
func (f *KeyManagerFactory) CreateEncryptor(keyManager KeyManager) (Encryptor, error) {
	if keyManager == nil {
		return nil, fmt.Errorf("key manager cannot be nil")
	}

	switch km := keyManager.(type) {
	case *FileKeyManager:
		return NewAESGCMEncryptor(km), nil
	case *HSMKeyManager:
		return NewHSMEncryptor(km), nil
	case *CloudKMSKeyManager:
		return NewCloudKMSEncryptor(km), nil
	default:
		return nil, fmt.Errorf("unsupported key manager type: %T", keyManager)
	}
}

// CryptoService provides a unified interface for key management and encryption
type CryptoService struct {
	keyManager KeyManager
	encryptor  Encryptor
	factory    *KeyManagerFactory
}

// NewCryptoService creates a new crypto service with the specified configuration
func NewCryptoService(config *KeyManagerConfig) (*CryptoService, error) {
	factory := NewKeyManagerFactory()

	keyManager, err := factory.CreateKeyManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %w", err)
	}

	encryptor, err := factory.CreateEncryptor(keyManager)
	if err != nil {
		keyManager.Close() // Clean up on error
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &CryptoService{
		keyManager: keyManager,
		encryptor:  encryptor,
		factory:    factory,
	}, nil
}

// KeyManager returns the underlying key manager
func (cs *CryptoService) KeyManager() KeyManager {
	return cs.keyManager
}

// Encryptor returns the underlying encryptor
func (cs *CryptoService) Encryptor() Encryptor {
	return cs.encryptor
}

// Close releases all resources held by the crypto service
func (cs *CryptoService) Close() error {
	if cs.keyManager != nil {
		return cs.keyManager.Close()
	}
	return nil
}

// DefaultKeyManagerConfig returns a default configuration for file-based key management
func DefaultKeyManagerConfig(keyPath string) *KeyManagerConfig {
	return &KeyManagerConfig{
		Type:     KeyTypeFile,
		FilePath: keyPath,
		RotationPolicy: &RotationPolicy{
			Enabled:       true,
			Interval:      24 * 30 * 3, // 90 days in hours
			MaxKeyAge:     24 * 30 * 6, // 180 days in hours
			RetainOldKeys: 5,
		},
	}
}

// HSMKeyManagerConfig returns a configuration for HSM-based key management
func HSMKeyManagerConfig(library string, slotID int, pin string) *KeyManagerConfig {
	return &KeyManagerConfig{
		Type: KeyTypeHSM,
		HSMConfig: &HSMConfig{
			Library: library,
			SlotID:  slotID,
			Pin:     pin,
			Attributes: map[string]string{
				"CKA_ENCRYPT": "true",
				"CKA_DECRYPT": "true",
				"CKA_WRAP":    "false",
				"CKA_UNWRAP":  "false",
			},
		},
		RotationPolicy: &RotationPolicy{
			Enabled:       true,
			Interval:      24 * 30 * 6, // 180 days in hours
			MaxKeyAge:     24 * 30 * 12, // 365 days in hours
			RetainOldKeys: 3,
		},
	}
}

// AWSKMSKeyManagerConfig returns a configuration for AWS KMS-based key management
func AWSKMSKeyManagerConfig(region string, credentials map[string]string) *KeyManagerConfig {
	return &KeyManagerConfig{
		Type: KeyTypeCloud,
		CloudConfig: &CloudKMSConfig{
			Provider: "aws",
			Region:   region,
			Credentials: credentials,
		},
		RotationPolicy: &RotationPolicy{
			Enabled:       true,
			Interval:      24 * 30 * 12, // 365 days in hours (AWS manages rotation)
			MaxKeyAge:     24 * 30 * 24, // 2 years in hours
			RetainOldKeys: 10,
		},
	}
}

// GCPKMSKeyManagerConfig returns a configuration for Google Cloud KMS-based key management
func GCPKMSKeyManagerConfig(projectID, keyRing, region string, credentials map[string]string) *KeyManagerConfig {
	return &KeyManagerConfig{
		Type: KeyTypeCloud,
		CloudConfig: &CloudKMSConfig{
			Provider:  "gcp",
			ProjectID: projectID,
			KeyRing:   keyRing,
			Region:    region,
			Credentials: credentials,
		},
		RotationPolicy: &RotationPolicy{
			Enabled:       true,
			Interval:      24 * 30 * 3, // 90 days in hours
			MaxKeyAge:     24 * 30 * 12, // 365 days in hours
			RetainOldKeys: 10,
		},
	}
}

// AzureKeyVaultConfig returns a configuration for Azure Key Vault-based key management
func AzureKeyVaultConfig(vaultURL string, credentials map[string]string) *KeyManagerConfig {
	return &KeyManagerConfig{
		Type: KeyTypeCloud,
		CloudConfig: &CloudKMSConfig{
			Provider: "azure",
			Region:   vaultURL, // Using region field for vault URL
			Credentials: credentials,
		},
		RotationPolicy: &RotationPolicy{
			Enabled:       true,
			Interval:      24 * 30 * 6, // 180 days in hours
			MaxKeyAge:     24 * 30 * 12, // 365 days in hours
			RetainOldKeys: 5,
		},
	}
}