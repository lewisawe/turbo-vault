package crypto

import (
	"context"
	"time"
)

// KeyManager defines the interface for key management operations
type KeyManager interface {
	// GenerateKey creates a new encryption key with the specified algorithm
	GenerateKey(ctx context.Context, keyID string, algorithm KeyAlgorithm) (*Key, error)
	
	// GetKey retrieves a key by its ID
	GetKey(ctx context.Context, keyID string) (*Key, error)
	
	// RotateKey creates a new version of an existing key
	RotateKey(ctx context.Context, keyID string) (*Key, error)
	
	// ListKeys returns all available keys
	ListKeys(ctx context.Context) ([]*KeyMetadata, error)
	
	// DeleteKey marks a key as deleted (but keeps it for decryption)
	DeleteKey(ctx context.Context, keyID string) error
	
	// Close releases any resources held by the key manager
	Close() error
}

// Encryptor defines the interface for encryption operations
type Encryptor interface {
	// Encrypt encrypts plaintext using the specified key
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptedData, error)
	
	// Decrypt decrypts ciphertext using the appropriate key
	Decrypt(ctx context.Context, encryptedData *EncryptedData) ([]byte, error)
	
	// EncryptString is a convenience method for string encryption
	EncryptString(ctx context.Context, keyID string, plaintext string) (*EncryptedData, error)
	
	// DecryptString is a convenience method for string decryption
	DecryptString(ctx context.Context, encryptedData *EncryptedData) (string, error)
}

// KeyAlgorithm represents supported encryption algorithms
type KeyAlgorithm string

const (
	AlgorithmAES256GCM KeyAlgorithm = "AES-256-GCM"
	AlgorithmChaCha20  KeyAlgorithm = "ChaCha20-Poly1305"
)

// KeyType represents the type of key storage backend
type KeyType string

const (
	KeyTypeFile  KeyType = "file"
	KeyTypeHSM   KeyType = "hsm"
	KeyTypeCloud KeyType = "cloud"
)

// Key represents an encryption key with metadata
type Key struct {
	ID        string       `json:"id"`
	Algorithm KeyAlgorithm `json:"algorithm"`
	Version   int          `json:"version"`
	KeyData   []byte       `json:"-"` // Never serialize key data
	CreatedAt time.Time    `json:"created_at"`
	Status    KeyStatus    `json:"status"`
}

// KeyMetadata contains key information without sensitive data
type KeyMetadata struct {
	ID        string       `json:"id"`
	Algorithm KeyAlgorithm `json:"algorithm"`
	Version   int          `json:"version"`
	CreatedAt time.Time    `json:"created_at"`
	Status    KeyStatus    `json:"status"`
}

// KeyStatus represents the lifecycle status of a key
type KeyStatus string

const (
	KeyStatusActive     KeyStatus = "active"
	KeyStatusRotating   KeyStatus = "rotating"
	KeyStatusDeprecated KeyStatus = "deprecated"
	KeyStatusDeleted    KeyStatus = "deleted"
)

// EncryptedData contains encrypted data with metadata
type EncryptedData struct {
	KeyID     string    `json:"key_id"`
	KeyVersion int      `json:"key_version"`
	Algorithm KeyAlgorithm `json:"algorithm"`
	Nonce     []byte    `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
	CreatedAt time.Time `json:"created_at"`
}

// KeyManagerConfig contains configuration for key managers
type KeyManagerConfig struct {
	Type     KeyType                `json:"type"`
	FilePath string                 `json:"file_path,omitempty"`
	HSMConfig *HSMConfig            `json:"hsm_config,omitempty"`
	CloudConfig *CloudKMSConfig     `json:"cloud_config,omitempty"`
	RotationPolicy *RotationPolicy  `json:"rotation_policy,omitempty"`
}

// HSMConfig contains HSM-specific configuration
type HSMConfig struct {
	Library    string            `json:"library"`
	SlotID     int               `json:"slot_id"`
	Pin        string            `json:"pin"`
	Attributes map[string]string `json:"attributes"`
}

// CloudKMSConfig contains cloud KMS configuration
type CloudKMSConfig struct {
	Provider   string            `json:"provider"` // aws, gcp, azure
	Region     string            `json:"region"`
	KeyRing    string            `json:"key_ring,omitempty"`
	ProjectID  string            `json:"project_id,omitempty"`
	Credentials map[string]string `json:"credentials"`
}

// RotationPolicy defines automatic key rotation settings
type RotationPolicy struct {
	Enabled      bool          `json:"enabled"`
	Interval     time.Duration `json:"interval"`
	MaxKeyAge    time.Duration `json:"max_key_age"`
	RetainOldKeys int          `json:"retain_old_keys"`
}