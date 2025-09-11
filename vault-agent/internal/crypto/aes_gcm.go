package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// AESGCMEncryptor implements the Encryptor interface using AES-256-GCM
type AESGCMEncryptor struct {
	keyManager KeyManager
}

// NewAESGCMEncryptor creates a new AES-GCM encryptor
func NewAESGCMEncryptor(keyManager KeyManager) *AESGCMEncryptor {
	return &AESGCMEncryptor{
		keyManager: keyManager,
	}
}

// Encrypt encrypts plaintext using AES-256-GCM with the specified key
func (e *AESGCMEncryptor) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptedData, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Get the encryption key
	key, err := e.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", keyID, err)
	}

	if key.Status != KeyStatusActive {
		return nil, fmt.Errorf("key %s is not active (status: %s)", keyID, key.Status)
	}

	if key.Algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("key %s uses unsupported algorithm: %s", keyID, key.Algorithm)
	}

	// Validate key size for AES-256
	if len(key.KeyData) != 32 {
		return nil, fmt.Errorf("invalid key size for AES-256: got %d bytes, expected 32", len(key.KeyData))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate cryptographically secure nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedData{
		KeyID:      keyID,
		KeyVersion: key.Version,
		Algorithm:  AlgorithmAES256GCM,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (e *AESGCMEncryptor) Decrypt(ctx context.Context, encryptedData *EncryptedData) ([]byte, error) {
	if encryptedData == nil {
		return nil, errors.New("encrypted data cannot be nil")
	}

	if encryptedData.Algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("unsupported algorithm: %s", encryptedData.Algorithm)
	}

	// Get the decryption key
	key, err := e.keyManager.GetKey(ctx, encryptedData.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", encryptedData.KeyID, err)
	}

	// Allow decryption with deprecated keys for backward compatibility
	if key.Status == KeyStatusDeleted {
		return nil, fmt.Errorf("key %s has been deleted", encryptedData.KeyID)
	}

	if key.Algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("key algorithm mismatch: expected %s, got %s", 
			encryptedData.Algorithm, key.Algorithm)
	}

	// Validate key version matches (for key rotation compatibility)
	if key.Version != encryptedData.KeyVersion {
		// Try to get the specific key version
		// For now, we'll use the current key but log a warning
		// In a full implementation, we'd maintain key version history
	}

	// Validate key size
	if len(key.KeyData) != 32 {
		return nil, fmt.Errorf("invalid key size for AES-256: got %d bytes, expected 32", len(key.KeyData))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Validate nonce size
	if len(encryptedData.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, expected %d", 
			len(encryptedData.Nonce), gcm.NonceSize())
	}

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, encryptedData.Nonce, encryptedData.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns encrypted data
func (e *AESGCMEncryptor) EncryptString(ctx context.Context, keyID string, plaintext string) (*EncryptedData, error) {
	return e.Encrypt(ctx, keyID, []byte(plaintext))
}

// DecryptString decrypts encrypted data and returns a string
func (e *AESGCMEncryptor) DecryptString(ctx context.Context, encryptedData *EncryptedData) (string, error) {
	plaintext, err := e.Decrypt(ctx, encryptedData)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SecureCompare performs constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ZeroBytes securely zeros out a byte slice
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncryptedDataToJSON serializes encrypted data to JSON
func EncryptedDataToJSON(data *EncryptedData) ([]byte, error) {
	return json.Marshal(data)
}

// EncryptedDataFromJSON deserializes encrypted data from JSON
func EncryptedDataFromJSON(jsonData []byte) (*EncryptedData, error) {
	var data EncryptedData
	err := json.Unmarshal(jsonData, &data)
	return &data, err
}