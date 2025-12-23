package unit

import (
	"cryptocore/src/kdf"
	"cryptocore/tests"
	"fmt"
	"testing"
	"time"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)
	context := "encryption-key"
	length := 32

	// Первая выработка
	key1, err := kdf.DeriveKey(masterKey, context, length)
	th.AssertNoErrorf(err, "First DeriveKey failed")

	// Вторая выработка с теми же параметрами
	key2, err := kdf.DeriveKey(masterKey, context, length)
	th.AssertNoErrorf(err, "Second DeriveKey failed")

	// Должны быть идентичны
	if !th.CompareBytes(key1, key2) {
		t.Error("DeriveKey is not deterministic")
	}

	// Проверяем длину
	if len(key1) != length {
		t.Errorf("Wrong key length: expected %d, got %d", length, len(key1))
	}
}

func TestDeriveKey_DifferentContexts(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)
	length := 32

	contexts := []string{
		"encryption",
		"authentication",
		"key-wrapping",
		"iv-generation",
		"hmac-key",
	}

	keys := make(map[string][]byte)

	for _, context := range contexts {
		t.Run(context, func(t *testing.T) {
			derivedKey, err := kdf.DeriveKey(masterKey, context, length)
			th.AssertNoErrorf(err, "DeriveKey failed for context %s", context)

			// Проверяем длину
			if len(derivedKey) != length {
				t.Errorf("Wrong key length for context %s: expected %d, got %d",
					context, length, len(derivedKey))
			}

			// Проверяем уникальность для каждого контекста
			for existingContext, existingKey := range keys {
				if th.IsEqual(derivedKey, existingKey) { // Используем IsEqual
					t.Errorf("Keys for contexts '%s' and '%s' are identical, should be different",
						context, existingContext)
				}
			}

			keys[context] = derivedKey
		})
	}

	t.Logf("Generated %d unique keys for different contexts", len(keys))
}

func TestDeriveKey_VariousLengths(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)
	context := "test-context"

	lengths := []int{1, 16, 32, 48, 64, 100, 256}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("Length-%d", length), func(t *testing.T) {
			derivedKey, err := kdf.DeriveKey(masterKey, context, length)
			th.AssertNoErrorf(err, "DeriveKey failed for length %d", length)

			// Проверяем длину
			if len(derivedKey) != length {
				t.Errorf("Wrong key length: expected %d, got %d", length, len(derivedKey))
			}

			// Проверяем, что ключ не состоит полностью из нулей
			allZeros := true
			for _, b := range derivedKey {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("Derived key is all zeros")
			}
		})
	}
}

func TestDeriveKey_InvalidParameters(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name      string
		masterKey []byte
		context   string
		length    int
		expectErr bool
	}{
		{
			name:      "Empty master key",
			masterKey: []byte{},
			context:   "test",
			length:    32,
			expectErr: true,
		},
		{
			name:      "Zero length",
			masterKey: th.GenerateTestData(32),
			context:   "test",
			length:    0,
			expectErr: true,
		},
		{
			name:      "Negative length",
			masterKey: th.GenerateTestData(32),
			context:   "test",
			length:    -1,
			expectErr: true,
		},
		{
			name:      "Empty context",
			masterKey: th.GenerateTestData(32),
			context:   "",
			length:    32,
			expectErr: false, // Пустой контекст допустим
		},
		{
			name:      "Valid parameters",
			masterKey: th.GenerateTestData(32),
			context:   "encryption",
			length:    32,
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kdf.DeriveKey(tc.masterKey, tc.context, tc.length)

			if tc.expectErr {
				th.AssertErrorf(err, "Expected error for %s", tc.name)
			} else {
				th.AssertNoErrorf(err, "DeriveKey should succeed for %s", tc.name)
			}
		})
	}
}

func TestHKDFExtractExpand(t *testing.T) {
	th := tests.NewTestHelper(t)

	ikm := th.GenerateTestData(64) // Input Key Material
	salt := th.GenerateTestData(32)
	info := []byte("test-info")
	length := 32

	t.Run("HKDF Extract", func(t *testing.T) {
		prk, err := kdf.HKDFExtract("sha256", salt, ikm)
		th.AssertNoErrorf(err, "HKDFExtract failed")

		// PRK должен быть 32 байта для SHA-256
		if len(prk) != 32 {
			t.Errorf("PRK should be 32 bytes for SHA-256, got %d", len(prk))
		}

		// С разной солью должны быть разные PRK
		diffSalt := th.GenerateTestData(32)
		prk2, err := kdf.HKDFExtract("sha256", diffSalt, ikm)
		th.AssertNoErrorf(err, "HKDFExtract with different salt failed")

		if th.CompareBytes(prk, prk2) {
			t.Error("Different salts should produce different PRKs")
		}
	})

	t.Run("HKDF Expand", func(t *testing.T) {
		prk := th.GenerateTestData(32)

		okm, err := kdf.HKDFExpand(prk, info, length)
		th.AssertNoErrorf(err, "HKDFExpand failed")

		if len(okm) != length {
			t.Errorf("Output key material length wrong: expected %d, got %d",
				length, len(okm))
		}

		// Детерминированность
		okm2, err := kdf.HKDFExpand(prk, info, length)
		th.AssertNoErrorf(err, "Second HKDFExpand failed")

		if !th.CompareBytes(okm, okm2) {
			t.Error("HKDFExpand is not deterministic")
		}

		// С разным info должны быть разные OKM
		diffInfo := []byte("different-info")
		okm3, err := kdf.HKDFExpand(prk, diffInfo, length)
		th.AssertNoErrorf(err, "HKDFExpand with different info failed")

		if th.CompareBytes(okm, okm3) {
			t.Error("Different info should produce different OKM")
		}
	})

	t.Run("HKDF Full", func(t *testing.T) {
		okm, err := kdf.HKDFFull("sha256", ikm, salt, info, length)
		th.AssertNoErrorf(err, "HKDFFull failed")

		if len(okm) != length {
			t.Errorf("Output key material length wrong: expected %d, got %d",
				length, len(okm))
		}

		// Детерминированность
		okm2, err := kdf.HKDFFull("sha256", ikm, salt, info, length)
		th.AssertNoErrorf(err, "Second HKDFFull failed")

		if !th.CompareBytes(okm, okm2) {
			t.Error("HKDFFull is not deterministic")
		}
	})
}

func TestDeriveMultipleKeys(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)

	contexts := map[string]int{
		"encryption":     32,
		"authentication": 32,
		"key-wrapping":   48,
		"iv-generation":  16,
		"hmac-key":       64,
	}

	keys, err := kdf.DeriveMultipleKeys(masterKey, contexts)
	th.AssertNoErrorf(err, "DeriveMultipleKeys failed")

	// Проверяем количество ключей
	if len(keys) != len(contexts) {
		t.Errorf("Expected %d keys, got %d", len(contexts), len(keys))
	}

	// Проверяем каждый ключ
	for context, expectedLength := range contexts {
		key, exists := keys[context]
		if !exists {
			t.Errorf("Key for context '%s' not found", context)
			continue
		}

		if len(key) != expectedLength {
			t.Errorf("Key for context '%s' has wrong length: expected %d, got %d",
				context, expectedLength, len(key))
		}

		// Проверяем уникальность
		for otherContext, otherKey := range keys {
			if context != otherContext && th.CompareBytes(key, otherKey) {
				t.Errorf("Keys for contexts '%s' and '%s' are identical",
					context, otherContext)
			}
		}
	}
}

func TestDeriveAEADKeys(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)

	testCases := []struct {
		name     string
		keySize  int
		expectOk bool
	}{
		{"AES-128", 16, true},
		{"AES-192", 24, true},
		{"AES-256", 32, true},
		{"ETM-48", 48, true},
		{"Invalid-8", 8, false},
		{"Invalid-64", 64, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encKey, macKey, err := kdf.DeriveAEADKeys(masterKey, tc.keySize)

			if !tc.expectOk {
				th.AssertErrorf(err, "Expected error for key size %d", tc.keySize)
				return
			}

			th.AssertNoErrorf(err, "DeriveAEADKeys failed")

			if tc.keySize == 48 {
				// Для ETM: 16 байт encryption key + 32 байт MAC key
				if len(encKey) != 16 {
					t.Errorf("Encryption key should be 16 bytes for ETM, got %d", len(encKey))
				}
				if len(macKey) != 32 {
					t.Errorf("MAC key should be 32 bytes for ETM, got %d", len(macKey))
				}

				// Ключи должны быть разными
				if th.CompareBytes(encKey, macKey[:16]) {
					t.Error("Encryption and MAC keys should be different")
				}
			} else {
				// Для GCM: только encryption key
				if len(encKey) != tc.keySize {
					t.Errorf("Encryption key should be %d bytes, got %d",
						tc.keySize, len(encKey))
				}
				if macKey != nil {
					t.Error("MAC key should be nil for non-ETM key sizes")
				}
			}

			// Проверяем, что ключи не нулевые
			if len(encKey) > 0 {
				allZeros := true
				for _, b := range encKey {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("Encryption key is all zeros")
				}
			}
		})
	}
}

func TestDeriveWithInfo(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)
	context := "base-context"
	info := "additional-info"
	length := 32

	key1, err := kdf.DeriveWithInfo(masterKey, context, info, length)
	th.AssertNoErrorf(err, "DeriveWithInfo failed")

	// Детерминированность
	key2, err := kdf.DeriveWithInfo(masterKey, context, info, length)
	th.AssertNoErrorf(err, "Second DeriveWithInfo failed")

	if !th.CompareBytes(key1, key2) {
		t.Error("DeriveWithInfo is not deterministic")
	}

	// Разный info должен давать разные ключи
	diffInfo := "different-info"
	key3, err := kdf.DeriveWithInfo(masterKey, context, diffInfo, length)
	th.AssertNoErrorf(err, "DeriveWithInfo with different info failed")

	if th.CompareBytes(key1, key3) {
		t.Error("Different info should produce different keys")
	}

	// Разный контекст должен давать разные ключи
	diffContext := "different-context"
	key4, err := kdf.DeriveWithInfo(masterKey, diffContext, info, length)
	th.AssertNoErrorf(err, "DeriveWithInfo with different context failed")

	if th.CompareBytes(key1, key4) {
		t.Error("Different context should produce different keys")
	}
}

func TestVerifyKeyDerivation(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey := th.GenerateTestData(32)
	context := "verification-test"
	length := 32

	// Вырабатываем ключ
	derivedKey, err := kdf.DeriveKey(masterKey, context, length)
	th.AssertNoErrorf(err, "DeriveKey failed")

	// Проверяем правильный ключ
	valid, err := kdf.VerifyKeyDerivation(masterKey, context, derivedKey)
	th.AssertNoErrorf(err, "VerifyKeyDerivation failed")
	if !valid {
		t.Error("Key verification should succeed for correct key")
	}

	// Проверяем неправильный ключ
	wrongKey := th.GenerateTestData(length)
	valid, err = kdf.VerifyKeyDerivation(masterKey, context, wrongKey)
	th.AssertNoErrorf(err, "VerifyKeyDerivation with wrong key failed")
	if valid {
		t.Error("Key verification should fail for wrong key")
	}

	// Проверяем с другим мастер-ключом
	wrongMasterKey := th.GenerateTestData(32)
	valid, err = kdf.VerifyKeyDerivation(wrongMasterKey, context, derivedKey)
	th.AssertNoErrorf(err, "VerifyKeyDerivation with wrong master key failed")
	if valid {
		t.Error("Key verification should fail for wrong master key")
	}

	// Проверяем с другим контекстом
	diffContext := "different-context"
	valid, err = kdf.VerifyKeyDerivation(masterKey, diffContext, derivedKey)
	th.AssertNoErrorf(err, "VerifyKeyDerivation with different context failed")
	if valid {
		t.Error("Key verification should fail for different context")
	}
}

func TestKDF_Performance(t *testing.T) {
	th := tests.NewTestHelper(t)

	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	masterKey := th.GenerateTestData(32)
	context := "performance-test"
	length := 32

	// Тестируем производительность
	iterations := 1000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := kdf.DeriveKey(masterKey, context, length)
		th.AssertNoErrorf(err, "DeriveKey failed at iteration %d", i)
	}
	elapsed := time.Since(start)

	t.Logf("Derived %d keys in %v", iterations, elapsed)
	t.Logf("Average: %v per key", elapsed/time.Duration(iterations))
	t.Logf("Rate: %.0f keys/second", float64(iterations)/elapsed.Seconds())
}
