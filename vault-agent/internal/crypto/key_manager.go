package crypto

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileKeyManager implements KeyManager interface using file-based storage
type FileKeyManager struct {
	basePath string
	keys     map[string]*Key
	mutex    sync.RWMutex
}

// NewFileKeyManager creates a new file-based key manager
func NewFileKeyManager(basePath string) (*FileKeyManager, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	km := &FileKeyManager{
		basePath: basePath,
		keys:     make(map[string]*Key),
	}

	// Load existing keys
	if err := km.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing keys: %w", err)
	}

	return km, nil
}

// GenerateKey creates a new encryption key with the specified algorithm
func (km *FileKeyManager) GenerateKey(ctx context.Context, keyID string, algorithm KeyAlgorithm) (*Key, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// Check if key already exists
	if _, exists := km.keys[keyID]; exists {
		return nil, fmt.Errorf("key %s already exists", keyID)
	}

	var keySize int
	switch algorithm {
	case AlgorithmAES256GCM:
		keySize = 32 // 256 bits
	case AlgorithmChaCha20:
		keySize = 32 // 256 bits
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Generate cryptographically secure random key
	keyData := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return nil, fmt.Errorf("failed to generate key data: %w", err)
	}

	key := &Key{
		ID:        keyID,
		Algorithm: algorithm,
		Version:   1,
		KeyData:   keyData,
		CreatedAt: time.Now().UTC(),
		Status:    KeyStatusActive,
	}

	// Save key to file
	if err := km.saveKey(key); err != nil {
		// Zero out key data on error
		ZeroBytes(keyData)
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	// Store in memory
	km.keys[keyID] = key

	return key, nil
}

// GetKey retrieves a key by its ID
func (km *FileKeyManager) GetKey(ctx context.Context, keyID string) (*Key, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	key, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key %s not found", keyID)
	}

	// Return a copy to prevent modification
	keyCopy := *key
	keyCopy.KeyData = make([]byte, len(key.KeyData))
	copy(keyCopy.KeyData, key.KeyData)

	return &keyCopy, nil
}

// RotateKey creates a new version of an existing key
func (km *FileKeyManager) RotateKey(ctx context.Context, keyID string) (*Key, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	existingKey, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key %s not found", keyID)
	}

	// Mark existing key as deprecated
	existingKey.Status = KeyStatusDeprecated

	// Generate new key data
	var keySize int
	switch existingKey.Algorithm {
	case AlgorithmAES256GCM:
		keySize = 32
	case AlgorithmChaCha20:
		keySize = 32
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", existingKey.Algorithm)
	}

	keyData := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return nil, fmt.Errorf("failed to generate key data: %w", err)
	}

	newKey := &Key{
		ID:        keyID,
		Algorithm: existingKey.Algorithm,
		Version:   existingKey.Version + 1,
		KeyData:   keyData,
		CreatedAt: time.Now().UTC(),
		Status:    KeyStatusActive,
	}

	// Save both keys
	if err := km.saveKey(existingKey); err != nil {
		return nil, fmt.Errorf("failed to save deprecated key: %w", err)
	}

	if err := km.saveKey(newKey); err != nil {
		ZeroBytes(keyData)
		return nil, fmt.Errorf("failed to save new key: %w", err)
	}

	// Update in-memory storage
	km.keys[keyID] = newKey

	return newKey, nil
}

// ListKeys returns all available keys
func (km *FileKeyManager) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
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

// DeleteKey marks a key as deleted (but keeps it for decryption)
func (km *FileKeyManager) DeleteKey(ctx context.Context, keyID string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	key, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key %s not found", keyID)
	}

	key.Status = KeyStatusDeleted

	// Save updated key
	if err := km.saveKey(key); err != nil {
		return fmt.Errorf("failed to save deleted key: %w", err)
	}

	return nil
}

// Close releases any resources held by the key manager
func (km *FileKeyManager) Close() error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	// Zero out all key data in memory
	for _, key := range km.keys {
		ZeroBytes(key.KeyData)
	}

	km.keys = make(map[string]*Key)
	return nil
}

// saveKey saves a key to file
func (km *FileKeyManager) saveKey(key *Key) error {
	keyFile := filepath.Join(km.basePath, fmt.Sprintf("%s_v%d.key", key.ID, key.Version))

	// Create key file data (without sensitive key data)
	keyFileData := struct {
		ID        string       `json:"id"`
		Algorithm KeyAlgorithm `json:"algorithm"`
		Version   int          `json:"version"`
		CreatedAt time.Time    `json:"created_at"`
		Status    KeyStatus    `json:"status"`
		KeyData   []byte       `json:"key_data"`
	}{
		ID:        key.ID,
		Algorithm: key.Algorithm,
		Version:   key.Version,
		CreatedAt: key.CreatedAt,
		Status:    key.Status,
		KeyData:   key.KeyData,
	}

	data, err := json.Marshal(keyFileData)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(keyFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// loadKeys loads all keys from the file system
func (km *FileKeyManager) loadKeys() error {
	entries, err := os.ReadDir(km.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No keys directory yet
		}
		return fmt.Errorf("failed to read key directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".key" {
			continue
		}

		keyFile := filepath.Join(km.basePath, entry.Name())
		data, err := os.ReadFile(keyFile)
		if err != nil {
			continue // Skip corrupted files
		}

		var keyFileData struct {
			ID        string       `json:"id"`
			Algorithm KeyAlgorithm `json:"algorithm"`
			Version   int          `json:"version"`
			CreatedAt time.Time    `json:"created_at"`
			Status    KeyStatus    `json:"status"`
			KeyData   []byte       `json:"key_data"`
		}

		if err := json.Unmarshal(data, &keyFileData); err != nil {
			continue // Skip corrupted files
		}

		key := &Key{
			ID:        keyFileData.ID,
			Algorithm: keyFileData.Algorithm,
			Version:   keyFileData.Version,
			KeyData:   keyFileData.KeyData,
			CreatedAt: keyFileData.CreatedAt,
			Status:    keyFileData.Status,
		}

		// Only keep the latest version of each key in memory
		if existingKey, exists := km.keys[key.ID]; !exists || key.Version > existingKey.Version {
			km.keys[key.ID] = key
		}
	}

	return nil
}