package unit

import (
	"cryptocore/src/aead"
	"cryptocore/tests"
	"fmt"
	"testing"
)

func TestGCM_EncryptDecrypt(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)
	nonce := th.GenerateTestData(12)
	aad := []byte("additional authenticated data")

	testCases := []struct {
		name      string
		plaintext []byte
		aad       []byte
		nonce     []byte
	}{
		{"Empty", []byte{}, []byte{}, nonce},
		{"Short", []byte("Hello"), []byte{}, nonce},
		{"With AAD", []byte("Hello World"), aad, nonce},
		{"Long text", th.GenerateTestData(1024), aad, nonce},
		{"Empty AAD", th.GenerateTestData(100), []byte{}, nonce},
		{"Empty nonce", th.GenerateTestData(50), aad, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gcm, err := aead.NewGCM(key)
			th.AssertNoError(err, "Failed to create GCM")

			if tc.nonce != nil {
				err = gcm.SetNonce(tc.nonce)
				th.AssertNoError(err, "SetNonce failed")
			}

			// Шифруем
			ciphertext, err := gcm.Encrypt(tc.plaintext, tc.aad)
			th.AssertNoError(err, "GCM encryption failed")

			// Проверяем минимальную длину (nonce(12) + tag(16) = 28)
			if len(ciphertext) < 28 {
				t.Errorf("Ciphertext too short: %d bytes", len(ciphertext))
			}

			// Дешифруем
			decrypted, err := gcm.Decrypt(ciphertext, tc.aad)
			th.AssertNoError(err, "GCM decryption failed")

			// Проверяем совпадение
			if !th.CompareBytes(tc.plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
			}
		})
	}
}

func TestGCM_NIST_TestVectors(t *testing.T) {
	th := tests.NewTestHelper(t)

	// NIST GCM test vectors (упрощенные)
	testCases := []struct {
		name string
		key  string
		iv   string
		pt   string
		aad  string
		ct   string
		tag  string
	}{
		{
			name: "NIST Test Vector 1",
			key:  "00000000000000000000000000000000",
			iv:   "000000000000000000000000",
			pt:   "",
			aad:  "",
			ct:   "",
			tag:  "58e2fccefa7e3061367f1d57a4e7455a",
		},
		{
			name: "NIST Test Vector 2",
			key:  "00000000000000000000000000000000",
			iv:   "000000000000000000000000",
			pt:   "00000000000000000000000000000000",
			aad:  "",
			ct:   "0388dace60b6a392f328c2b971b2fe78",
			tag:  "ab6e47d42cec13bdf53a67b21257bddf",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := th.HexDecode(tc.key)
			nonce := th.HexDecode(tc.iv)
			plaintext := th.HexDecode(tc.pt)
			aad := th.HexDecode(tc.aad)
			expectedCT := th.HexDecode(tc.ct)
			expectedTag := th.HexDecode(tc.tag)

			gcm, err := aead.NewGCM(key)
			th.AssertNoError(err, "Failed to create GCM")

			err = gcm.SetNonce(nonce)
			th.AssertNoError(err, "SetNonce failed")

			// Шифруем
			ciphertext, err := gcm.Encrypt(plaintext, aad)
			th.AssertNoError(err, "GCM encryption failed")

			// Извлекаем tag из ciphertext
			tagStart := len(ciphertext) - 16
			actualTag := ciphertext[tagStart:]
			actualCT := ciphertext[12:tagStart] // Пропускаем nonce(12)

			// Проверяем ciphertext
			if len(expectedCT) > 0 && !th.CompareBytes(expectedCT, actualCT) {
				t.Errorf("Ciphertext doesn't match NIST vector")
			}

			// Проверяем tag
			if !th.CompareBytes(expectedTag, actualTag) {
				t.Errorf("Tag doesn't match NIST vector")
			}
		})
	}
}

func TestGCM_AuthenticationFailure(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)
	plaintextData := []byte("Secret message")
	aad := []byte("AAD")

	gcm, err := aead.NewGCM(key)
	th.AssertNoError(err, "Failed to create GCM")

	// Шифруем
	ciphertext, err := gcm.Encrypt(plaintextData, aad)
	th.AssertNoError(err, "GCM encryption failed")

	// Меняем один байт в ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[20] ^= 0x01 // Меняем байт

	// Попытка дешифровать должен завершиться ошибкой
	_, err = gcm.Decrypt(tampered, aad)
	th.AssertError(err, "GCM should fail authentication with tampered ciphertext")

	// Меняем AAD
	_, err = gcm.Decrypt(ciphertext, []byte("Wrong AAD"))
	th.AssertError(err, "GCM should fail authentication with wrong AAD")

	// Меняем tag
	tamperedTag := make([]byte, len(ciphertext))
	copy(tamperedTag, ciphertext)
	tamperedTag[len(tamperedTag)-1] ^= 0x01 // Меняем последний байт tag

	_, err = gcm.Decrypt(tamperedTag, aad)
	th.AssertError(err, "GCM should fail authentication with tampered tag")
}

func TestGCM_KeySizes(t *testing.T) {
	th := tests.NewTestHelper(t)

	keySizes := []int{16, 24, 32} // AES-128, AES-192, AES-256
	plaintext := []byte("Test message")
	aad := []byte("AAD")

	for _, size := range keySizes {
		t.Run(fmt.Sprintf("KeySize-%d", size*8), func(t *testing.T) {
			key := th.GenerateTestData(size)

			gcm, err := aead.NewGCM(key)
			th.AssertNoError(err, "Failed to create GCM")

			ciphertext, err := gcm.Encrypt(plaintext, aad)
			th.AssertNoError(err, "GCM encryption failed")

			decrypted, err := gcm.Decrypt(ciphertext, aad)
			th.AssertNoError(err, "GCM decryption failed")

			if !th.CompareBytes(plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
			}
		})
	}
}

func TestGCM_SetNonce(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)

	// Тест 1: nonce 12 байт
	t.Run("12-byte nonce", func(t *testing.T) {
		gcm, err := aead.NewGCM(key)
		th.AssertNoErrorf(err, "Failed to create GCM")

		nonce := th.GenerateTestData(12)
		err = gcm.SetNonce(nonce)
		th.AssertNoErrorf(err, "SetNonce failed")

		retrievedNonce := gcm.GetNonce()
		if !th.CompareBytes(nonce, retrievedNonce) {
			t.Error("Retrieved nonce doesn't match set nonce")
		}
	})

	// Тест 2: неправильный размер nonce
	t.Run("Wrong nonce size", func(t *testing.T) {
		gcm, err := aead.NewGCM(key)
		th.AssertNoErrorf(err, "Failed to create GCM")

		wrongNonce := th.GenerateTestData(16)
		err = gcm.SetNonce(wrongNonce)
		th.AssertError(err, "SetNonce should fail with wrong size")
	})

	// Тест 3: multiple encryptions with same nonce (security issue)
	t.Run("Nonce reuse", func(t *testing.T) {
		nonce := th.GenerateTestData(12)

		// Первое шифрование
		gcm1, err := aead.NewGCM(key)
		th.AssertNoError(err, "Failed to create GCM")
		gcm1.SetNonce(nonce)
		ct1, err := gcm1.Encrypt([]byte("Message 1"), nil)
		th.AssertNoError(err, "First encryption failed")

		// Второе шифрование с тем же nonce
		gcm2, err := aead.NewGCM(key)
		th.AssertNoError(err, "Failed to create GCM")
		gcm2.SetNonce(nonce)
		ct2, err := gcm2.Encrypt([]byte("Message 2"), nil)
		th.AssertNoError(err, "Second encryption failed")

		// Ciphertext должны быть разными (разные сообщения)
		if th.IsEqual(ct1, ct2) { // Используем IsEqual вместо CompareBytes
			t.Error("Different messages with same nonce produced identical ciphertext")
		}
	})
}

func TestGCM_LargeMessages(t *testing.T) {
	th := tests.NewTestHelper(t)

	if testing.Short() {
		t.Skip("Skipping large message test in short mode")
	}

	key := th.GenerateTestData(16)
	sizes := []int{1024, 1024 * 1024, 10 * 1024 * 1024} // 1KB, 1MB, 10MB

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", size), func(t *testing.T) {
			plaintext := th.GenerateTestData(size)

			gcm, err := aead.NewGCM(key)
			th.AssertNoError(err, "Failed to create GCM")

			ciphertext, err := gcm.Encrypt(plaintext, nil)
			th.AssertNoErrorf(err, "GCM encryption failed for size %d", size)

			decrypted, err := gcm.Decrypt(ciphertext, nil)
			th.AssertNoErrorf(err, "GCM decryption failed for size %d", size)

			if !th.CompareBytes(plaintext, decrypted) {
				t.Errorf("Large message (%d bytes) decryption failed", size)
			}
		})
	}
}

func TestGCM_EmptyMessages(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)

	gcm, err := aead.NewGCM(key)
	th.AssertNoError(err, "Failed to create GCM")

	// Шифрование пустого сообщения
	ciphertext, err := gcm.Encrypt([]byte{}, nil)
	th.AssertNoError(err, "GCM encryption of empty message failed")

	// Должен быть только nonce + tag
	if len(ciphertext) != 12+16 { // nonce(12) + tag(16)
		t.Errorf("Empty message ciphertext should be 28 bytes, got %d", len(ciphertext))
	}

	// Дешифрование
	decrypted, err := gcm.Decrypt(ciphertext, nil)
	th.AssertNoError(err, "GCM decryption of empty message failed")

	if len(decrypted) != 0 {
		t.Errorf("Decrypted empty message should be 0 bytes, got %d", len(decrypted))
	}
}

func TestGCM_Interface(t *testing.T) {
	// Проверяем, что GCM реализует ожидаемое поведение
	key := []byte("0123456789ABCDEF")

	gcm, err := aead.NewGCM(key)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	// Тестируем методы
	plaintext := []byte("test")
	aad := []byte("aad")

	ciphertext, err := gcm.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := gcm.Decrypt(ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted text doesn't match original")
	}
}
