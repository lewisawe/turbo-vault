package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// HSMKeyManager implements KeyManager interface using Hardware Security Module
type HSMKeyManager struct {
	config *HSMConfig
	keys   map[string]*KeyMetadata
	mutex  sync.RWMutex
}

// NewHSMKeyManager creates a new HSM-based key manager
func NewHSMKeyManager(config *HSMConfig) (*HSMKeyManager, error) {
	if config == nil {
		return nil, fmt.Errorf("HSM config cannot be nil")
	}

	km := &HSMKeyManager{
		config: config,
		keys:   make(map[string]*KeyMetadata),
	}

	// Initialize HSM connection
	if err := km.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize HSM: %w", err)
	}

	return km, nil
}

// initialize sets up the HSM connection
func (km *HSMKeyManager) initialize() error {
	// In a real implementation, this would:
	// 1. Load the PKCS#11 library specified in config.Library
	// 2. Initialize the library
	// 3. Open a session with the specified slot
	// 4. Login with the PIN
	// 5. Discover existing keys
	
	// For now, we'll simulate HSM initialization
	// This is where you would integrate with actual HSM libraries like:
	// - github.com/miekg/pkcs11 for PKCS#11 HSMs
	// - AWS CloudHSM SDK
	// - Azure Dedicated HSM SDK
	// - etc.
	
	return nil
}

// GenerateKey creates a new encryption key in the HSM
func (km *HSMKeyManager) GenerateKey(ctx context.Context, keyID string, algorithm KeyAlgorithm) (*Key, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// Check if key already exists
	if _, exists := km.keys[keyID]; exists {
		return nil, fmt.Errorf("key %s already exists", keyID)
	}

	// Validate algorithm support
	if !km.isAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("algorithm %s not supported by HSM", algorithm)
	}

	// In a real HSM implementation, this would:
	// 1. Generate key material within the HSM
	// 2. Store the key with the specified ID
	// 3. Set appropriate key attributes (usage, extractability, etc.)
	
	// For simulation, create metadata
	metadata := &KeyMetadata{
		ID:        keyID,
		Algorithm: algorithm,
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Status:    KeyStatusActive,
	}

	km.keys[keyID] = metadata

	// Return key without actual key data (HSM keeps it secure)
	return &Key{
		ID:        keyID,
		Algorithm: algorithm,
		Version:   1,
		KeyData:   nil, // HSM keys don't expose raw key data
		CreatedAt: time.Now().UTC(),
		Status:    KeyStatusActive,
	}, nil
}

// GetKey retrieves key metadata (HSM keys don't expose raw data)
func (km *HSMKeyManager) GetKey(ctx context.Context, keyID string) (*Key, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	metadata, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key %s not found", keyID)
	}

	return &Key{
		ID:        metadata.ID,
		Algorithm: metadata.Algorithm,
		Version:   metadata.Version,
		KeyData:   nil, // HSM keys don't expose raw key data
		CreatedAt: metadata.CreatedAt,
		Status:    metadata.Status,
	}, nil
}

// RotateKey creates a new version of an existing key in the HSM
func (km *HSMKeyManager) RotateKey(ctx context.Context, keyID string) (*Key, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	existingKey, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key %s not found", keyID)
	}

	// Mark existing key as deprecated
	existingKey.Status = KeyStatusDeprecated

	// Create new key version in HSM
	newMetadata := &KeyMetadata{
		ID:        keyID,
		Algorithm: existingKey.Algorithm,
		Version:   existingKey.Version + 1,
		CreatedAt: time.Now().UTC(),
		Status:    KeyStatusActive,
	}

	km.keys[keyID] = newMetadata

	return &Key{
		ID:        keyID,
		Algorithm: existingKey.Algorithm,
		Version:   newMetadata.Version,
		KeyData:   nil, // HSM keys don't expose raw key data
		CreatedAt: newMetadata.CreatedAt,
		Status:    KeyStatusActive,
	}, nil
}

// ListKeys returns metadata for all keys in the HSM
func (km *HSMKeyManager) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	metadata := make([]*KeyMetadata, 0, len(km.keys))
	for _, key := range km.keys {
		metadata = append(metadata, &KeyMetadata{
			ID:        key.ID,
			Algorithm: key.Algorithm,
			Version:   key.Version,
			CreatedAt: key.CreatedAt,
			Status:    key.Status,
		})
	}

	return metadata, nil
}

// DeleteKey marks a key as deleted in the HSM
func (km *HSMKeyManager) DeleteKey(ctx context.Context, keyID string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	key, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key %s not found", keyID)
	}

	key.Status = KeyStatusDeleted

	// In a real HSM implementation, this would mark the key as deleted
	// but keep it available for decryption of existing data

	return nil
}

// Close releases HSM resources
func (km *HSMKeyManager) Close() error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// In a real HSM implementation, this would:
	// 1. Logout from the HSM session
	// 2. Close the session
	// 3. Finalize the PKCS#11 library

	km.keys = make(map[string]*KeyMetadata)
	return nil
}

// isAlgorithmSupported checks if the HSM supports the specified algorithm
func (km *HSMKeyManager) isAlgorithmSupported(algorithm KeyAlgorithm) bool {
	// In a real implementation, this would query HSM capabilities
	switch algorithm {
	case AlgorithmAES256GCM:
		return true
	case AlgorithmChaCha20:
		return false // Most HSMs don't support ChaCha20 yet
	default:
		return false
	}
}

// HSMEncryptor implements encryption operations using HSM
type HSMEncryptor struct {
	keyManager *HSMKeyManager
}

// NewHSMEncryptor creates a new HSM-based encryptor
func NewHSMEncryptor(keyManager *HSMKeyManager) *HSMEncryptor {
	return &HSMEncryptor{
		keyManager: keyManager,
	}
}

// Encrypt encrypts data using HSM-stored keys
func (e *HSMEncryptor) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptedData, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	// Get key metadata
	key, err := e.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", keyID, err)
	}

	if key.Status != KeyStatusActive {
		return nil, fmt.Errorf("key %s is not active (status: %s)", keyID, key.Status)
	}

	// In a real HSM implementation, this would:
	// 1. Use HSM's encrypt function with the specified key
	// 2. The HSM would generate nonce and perform encryption internally
	// 3. Return the encrypted data with metadata

	// For simulation, we'll return a placeholder
	return &EncryptedData{
		KeyID:      keyID,
		KeyVersion: key.Version,
		Algorithm:  key.Algorithm,
		Nonce:      make([]byte, 12), // Placeholder nonce
		Ciphertext: append([]byte("HSM_ENCRYPTED:"), plaintext...), // Placeholder
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// Decrypt decrypts data using HSM-stored keys
func (e *HSMEncryptor) Decrypt(ctx context.Context, encryptedData *EncryptedData) ([]byte, error) {
	if encryptedData == nil {
		return nil, fmt.Errorf("encrypted data cannot be nil")
	}

	// Get key metadata
	key, err := e.keyManager.GetKey(ctx, encryptedData.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", encryptedData.KeyID, err)
	}

	if key.Status == KeyStatusDeleted {
		return nil, fmt.Errorf("key %s has been deleted", encryptedData.KeyID)
	}

	// In a real HSM implementation, this would:
	// 1. Use HSM's decrypt function with the specified key
	// 2. The HSM would perform decryption internally
	// 3. Return the plaintext

	// For simulation, remove the placeholder prefix
	if len(encryptedData.Ciphertext) > 14 && string(encryptedData.Ciphertext[:14]) == "HSM_ENCRYPTED:" {
		return encryptedData.Ciphertext[14:], nil
	}

	return nil, fmt.Errorf("invalid HSM encrypted data format")
}

// EncryptString encrypts a string using HSM
func (e *HSMEncryptor) EncryptString(ctx context.Context, keyID string, plaintext string) (*EncryptedData, error) {
	return e.Encrypt(ctx, keyID, []byte(plaintext))
}

// DecryptString decrypts to a string using HSM
func (e *HSMEncryptor) DecryptString(ctx context.Context, encryptedData *EncryptedData) (string, error) {
	plaintext, err := e.Decrypt(ctx, encryptedData)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}