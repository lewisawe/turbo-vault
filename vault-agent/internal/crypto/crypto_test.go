package crypto

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestFileKeyManager(t *testing.T) {
	// Create temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "vault_test_keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	km, err := NewFileKeyManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create file key manager: %v", err)
	}
	defer km.Close()

	ctx := context.Background()

	t.Run("GenerateKey", func(t *testing.T) {
		key, err := km.GenerateKey(ctx, "test-key-1", AlgorithmAES256GCM)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		if key.ID != "test-key-1" {
			t.Errorf("Expected key ID 'test-key-1', got '%s'", key.ID)
		}

		if key.Algorithm != AlgorithmAES256GCM {
			t.Errorf("Expected algorithm AES-256-GCM, got %s", key.Algorithm)
		}

		if len(key.KeyData) != 32 {
			t.Errorf("Expected key data length 32, got %d", len(key.KeyData))
		}

		if key.Status != KeyStatusActive {
			t.Errorf("Expected key status active, got %s", key.Status)
		}
	})

	t.Run("GetKey", func(t *testing.T) {
		key, err := km.GetKey(ctx, "test-key-1")
		if err != nil {
			t.Fatalf("Failed to get key: %v", err)
		}

		if key.ID != "test-key-1" {
			t.Errorf("Expected key ID 'test-key-1', got '%s'", key.ID)
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		keys, err := km.ListKeys(ctx)
		if err != nil {
			t.Fatalf("Failed to list keys: %v", err)
		}

		if len(keys) != 1 {
			t.Errorf("Expected 1 key, got %d", len(keys))
		}

		if keys[0].ID != "test-key-1" {
			t.Errorf("Expected key ID 'test-key-1', got '%s'", keys[0].ID)
		}
	})

	t.Run("RotateKey", func(t *testing.T) {
		newKey, err := km.RotateKey(ctx, "test-key-1")
		if err != nil {
			t.Fatalf("Failed to rotate key: %v", err)
		}

		if newKey.Version != 2 {
			t.Errorf("Expected key version 2, got %d", newKey.Version)
		}

		if newKey.Status != KeyStatusActive {
			t.Errorf("Expected key status active, got %s", newKey.Status)
		}
	})

	t.Run("DeleteKey", func(t *testing.T) {
		err := km.DeleteKey(ctx, "test-key-1")
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}

		key, err := km.GetKey(ctx, "test-key-1")
		if err != nil {
			t.Fatalf("Failed to get deleted key: %v", err)
		}

		if key.Status != KeyStatusDeleted {
			t.Errorf("Expected key status deleted, got %s", key.Status)
		}
	})

	t.Run("DuplicateKeyError", func(t *testing.T) {
		_, err := km.GenerateKey(ctx, "test-key-2", AlgorithmAES256GCM)
		if err != nil {
			t.Fatalf("Failed to generate first key: %v", err)
		}

		_, err = km.GenerateKey(ctx, "test-key-2", AlgorithmAES256GCM)
		if err == nil {
			t.Error("Expected error when generating duplicate key")
		}
	})

	t.Run("NonExistentKeyError", func(t *testing.T) {
		_, err := km.GetKey(ctx, "non-existent-key")
		if err == nil {
			t.Error("Expected error when getting non-existent key")
		}
	})
}

func TestAESGCMEncryptor(t *testing.T) {
	// Create temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "vault_test_keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	km, err := NewFileKeyManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create file key manager: %v", err)
	}
	defer km.Close()

	encryptor := NewAESGCMEncryptor(km)
	ctx := context.Background()

	// Generate a test key
	_, err = km.GenerateKey(ctx, "test-encrypt-key", AlgorithmAES256GCM)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	t.Run("EncryptDecrypt", func(t *testing.T) {
		plaintext := "This is a secret message"

		// Encrypt
		encryptedData, err := encryptor.EncryptString(ctx, "test-encrypt-key", plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if encryptedData.KeyID != "test-encrypt-key" {
			t.Errorf("Expected key ID 'test-encrypt-key', got '%s'", encryptedData.KeyID)
		}

		if encryptedData.Algorithm != AlgorithmAES256GCM {
			t.Errorf("Expected algorithm AES-256-GCM, got %s", encryptedData.Algorithm)
		}

		if len(encryptedData.Nonce) == 0 {
			t.Error("Expected non-empty nonce")
		}

		if len(encryptedData.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}

		// Decrypt
		decryptedText, err := encryptor.DecryptString(ctx, encryptedData)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if decryptedText != plaintext {
			t.Errorf("Expected decrypted text '%s', got '%s'", plaintext, decryptedText)
		}
	})

	t.Run("EncryptEmptyPlaintext", func(t *testing.T) {
		_, err := encryptor.EncryptString(ctx, "test-encrypt-key", "")
		if err == nil {
			t.Error("Expected error when encrypting empty plaintext")
		}
	})

	t.Run("DecryptWithNilData", func(t *testing.T) {
		_, err := encryptor.Decrypt(ctx, nil)
		if err == nil {
			t.Error("Expected error when decrypting nil data")
		}
	})

	t.Run("EncryptWithNonExistentKey", func(t *testing.T) {
		_, err := encryptor.EncryptString(ctx, "non-existent-key", "test")
		if err == nil {
			t.Error("Expected error when encrypting with non-existent key")
		}
	})

	t.Run("DecryptWithDeletedKey", func(t *testing.T) {
		// Generate and delete a key
		_, err := km.GenerateKey(ctx, "deleted-key", AlgorithmAES256GCM)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Encrypt with the key
		encryptedData, err := encryptor.EncryptString(ctx, "deleted-key", "test message")
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Delete the key
		err = km.DeleteKey(ctx, "deleted-key")
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}

		// Try to decrypt (should fail)
		_, err = encryptor.DecryptString(ctx, encryptedData)
		if err == nil {
			t.Error("Expected error when decrypting with deleted key")
		}
	})

	t.Run("MultipleEncryptionsProduceDifferentCiphertext", func(t *testing.T) {
		plaintext := "Same message"

		encrypted1, err := encryptor.EncryptString(ctx, "test-encrypt-key", plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt first time: %v", err)
		}

		encrypted2, err := encryptor.EncryptString(ctx, "test-encrypt-key", plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt second time: %v", err)
		}

		// Nonces should be different
		if string(encrypted1.Nonce) == string(encrypted2.Nonce) {
			t.Error("Expected different nonces for multiple encryptions")
		}

		// Ciphertexts should be different
		if string(encrypted1.Ciphertext) == string(encrypted2.Ciphertext) {
			t.Error("Expected different ciphertexts for multiple encryptions")
		}

		// But both should decrypt to the same plaintext
		decrypted1, err := encryptor.DecryptString(ctx, encrypted1)
		if err != nil {
			t.Fatalf("Failed to decrypt first: %v", err)
		}

		decrypted2, err := encryptor.DecryptString(ctx, encrypted2)
		if err != nil {
			t.Fatalf("Failed to decrypt second: %v", err)
		}

		if decrypted1 != plaintext || decrypted2 != plaintext {
			t.Error("Decrypted text doesn't match original plaintext")
		}
	})
}

func TestCryptoService(t *testing.T) {
	// Create temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "vault_test_keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultKeyManagerConfig(tempDir)
	service, err := NewCryptoService(config)
	if err != nil {
		t.Fatalf("Failed to create crypto service: %v", err)
	}
	defer service.Close()

	ctx := context.Background()

	t.Run("IntegratedEncryptDecrypt", func(t *testing.T) {
		// Generate a key
		key, err := service.KeyManager().GenerateKey(ctx, "service-test-key", AlgorithmAES256GCM)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Encrypt data
		plaintext := "Integrated test message"
		encryptedData, err := service.Encryptor().EncryptString(ctx, key.ID, plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decrypt data
		decryptedText, err := service.Encryptor().DecryptString(ctx, encryptedData)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if decryptedText != plaintext {
			t.Errorf("Expected '%s', got '%s'", plaintext, decryptedText)
		}
	})
}

func TestKeyManagerFactory(t *testing.T) {
	factory := NewKeyManagerFactory()

	t.Run("CreateFileKeyManager", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "vault_test_keys")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		config := &KeyManagerConfig{
			Type:     KeyTypeFile,
			FilePath: tempDir,
		}

		km, err := factory.CreateKeyManager(config)
		if err != nil {
			t.Fatalf("Failed to create file key manager: %v", err)
		}
		defer km.Close()

		if _, ok := km.(*FileKeyManager); !ok {
			t.Error("Expected FileKeyManager type")
		}
	})

	t.Run("CreateHSMKeyManager", func(t *testing.T) {
		config := &KeyManagerConfig{
			Type: KeyTypeHSM,
			HSMConfig: &HSMConfig{
				Library: "/usr/lib/libpkcs11.so",
				SlotID:  0,
				Pin:     "1234",
			},
		}

		km, err := factory.CreateKeyManager(config)
		if err != nil {
			t.Fatalf("Failed to create HSM key manager: %v", err)
		}
		defer km.Close()

		if _, ok := km.(*HSMKeyManager); !ok {
			t.Error("Expected HSMKeyManager type")
		}
	})

	t.Run("CreateCloudKMSKeyManager", func(t *testing.T) {
		config := &KeyManagerConfig{
			Type: KeyTypeCloud,
			CloudConfig: &CloudKMSConfig{
				Provider: "aws",
				Region:   "us-east-1",
				Credentials: map[string]string{
					"access_key_id":     "test",
					"secret_access_key": "test",
				},
			},
		}

		km, err := factory.CreateKeyManager(config)
		if err != nil {
			t.Fatalf("Failed to create cloud KMS key manager: %v", err)
		}
		defer km.Close()

		if _, ok := km.(*CloudKMSKeyManager); !ok {
			t.Error("Expected CloudKMSKeyManager type")
		}
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		_, err := factory.CreateKeyManager(nil)
		if err == nil {
			t.Error("Expected error with nil config")
		}

		config := &KeyManagerConfig{
			Type: "invalid",
		}

		_, err = factory.CreateKeyManager(config)
		if err == nil {
			t.Error("Expected error with invalid type")
		}
	})
}

func TestSecurityFunctions(t *testing.T) {
	t.Run("SecureCompare", func(t *testing.T) {
		a := []byte("hello")
		b := []byte("hello")
		c := []byte("world")

		if !SecureCompare(a, b) {
			t.Error("Expected true for identical byte slices")
		}

		if SecureCompare(a, c) {
			t.Error("Expected false for different byte slices")
		}

		if SecureCompare(a, []byte("hell")) {
			t.Error("Expected false for different length byte slices")
		}
	})

	t.Run("ZeroBytes", func(t *testing.T) {
		data := []byte("sensitive data")
		ZeroBytes(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("Expected byte at index %d to be zero, got %d", i, b)
			}
		}
	})
}

func TestEncryptedDataSerialization(t *testing.T) {
	originalData := &EncryptedData{
		KeyID:      "test-key",
		KeyVersion: 1,
		Algorithm:  AlgorithmAES256GCM,
		Nonce:      []byte("test-nonce"),
		Ciphertext: []byte("test-ciphertext"),
		CreatedAt:  time.Now().UTC().Truncate(time.Second), // Truncate for comparison
	}

	t.Run("JSONSerialization", func(t *testing.T) {
		// Serialize to JSON
		jsonData, err := EncryptedDataToJSON(originalData)
		if err != nil {
			t.Fatalf("Failed to serialize to JSON: %v", err)
		}

		// Deserialize from JSON
		deserializedData, err := EncryptedDataFromJSON(jsonData)
		if err != nil {
			t.Fatalf("Failed to deserialize from JSON: %v", err)
		}

		// Compare
		if deserializedData.KeyID != originalData.KeyID {
			t.Errorf("KeyID mismatch: expected %s, got %s", originalData.KeyID, deserializedData.KeyID)
		}

		if deserializedData.KeyVersion != originalData.KeyVersion {
			t.Errorf("KeyVersion mismatch: expected %d, got %d", originalData.KeyVersion, deserializedData.KeyVersion)
		}

		if deserializedData.Algorithm != originalData.Algorithm {
			t.Errorf("Algorithm mismatch: expected %s, got %s", originalData.Algorithm, deserializedData.Algorithm)
		}

		if string(deserializedData.Nonce) != string(originalData.Nonce) {
			t.Errorf("Nonce mismatch: expected %s, got %s", string(originalData.Nonce), string(deserializedData.Nonce))
		}

		if string(deserializedData.Ciphertext) != string(originalData.Ciphertext) {
			t.Errorf("Ciphertext mismatch: expected %s, got %s", string(originalData.Ciphertext), string(deserializedData.Ciphertext))
		}

		if !deserializedData.CreatedAt.Equal(originalData.CreatedAt) {
			t.Errorf("CreatedAt mismatch: expected %v, got %v", originalData.CreatedAt, deserializedData.CreatedAt)
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkAESGCMEncryption(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "vault_bench_keys")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	km, err := NewFileKeyManager(tempDir)
	if err != nil {
		b.Fatalf("Failed to create key manager: %v", err)
	}
	defer km.Close()

	encryptor := NewAESGCMEncryptor(km)
	ctx := context.Background()

	// Generate test key
	_, err = km.GenerateKey(ctx, "bench-key", AlgorithmAES256GCM)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := make([]byte, 1024) // 1KB of data
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encryptor.Encrypt(ctx, "bench-key", plaintext)
			if err != nil {
				b.Fatalf("Encryption failed: %v", err)
			}
		}
	})
}

func BenchmarkAESGCMDecryption(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "vault_bench_keys")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	km, err := NewFileKeyManager(tempDir)
	if err != nil {
		b.Fatalf("Failed to create key manager: %v", err)
	}
	defer km.Close()

	encryptor := NewAESGCMEncryptor(km)
	ctx := context.Background()

	// Generate test key
	_, err = km.GenerateKey(ctx, "bench-key", AlgorithmAES256GCM)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := make([]byte, 1024) // 1KB of data
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	// Pre-encrypt data for benchmarking
	encryptedData, err := encryptor.Encrypt(ctx, "bench-key", plaintext)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encryptor.Decrypt(ctx, encryptedData)
			if err != nil {
				b.Fatalf("Decryption failed: %v", err)
			}
		}
	})
}