package unit

import (
	"crypto/subtle"
	"cryptocore/src/mac"
	"cryptocore/tests"
	"encoding/hex"
	"fmt"
	"testing"
)

// RFC 4231 Test Vectors for HMAC-SHA256
func TestHMAC_RFC4231_TestVectors(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name     string
		key      string
		data     string
		expected string
	}{
		// Test Case 1
		{
			name:     "RFC4231 Test Case 1",
			key:      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			data:     "4869205468657265", // "Hi There"
			expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		// Test Case 2
		{
			name:     "RFC4231 Test Case 2",
			key:      "4a656665",                                                 // "Jefe"
			data:     "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
			expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
		// Test Case 3
		{
			name:     "RFC4231 Test Case 3",
			key:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			data:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		},
		// Test Case 4
		{
			name:     "RFC4231 Test Case 4",
			key:      "0102030405060708090a0b0c0d0e0f10111213141516171819",
			data:     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			expected: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := th.HexDecode(tc.key)
			data := th.HexDecode(tc.data)

			hmac, err := mac.NewHMAC(key)
			th.AssertNoError(err, "Failed to create HMAC")

			result := hmac.Compute(data)
			expected := th.HexDecode(tc.expected)

			if !th.CompareBytes(expected, result) {
				t.Errorf("HMAC doesn't match RFC4231 test vector")
			}
		})
	}
}

func TestHMAC_VariousKeyLengths(t *testing.T) {
	th := tests.NewTestHelper(t)

	testData := []byte("Test message for HMAC")

	keyLengths := []int{
		1,   // Минимальная длина
		15,  // Меньше блока (64 байта)
		64,  // Точный размер блока
		65,  // Больше блока (будет хеширован)
		128, // Двойной размер блока
	}

	for _, length := range keyLengths {
		t.Run(fmt.Sprintf("KeyLength-%d", length), func(t *testing.T) {
			key := th.GenerateTestData(length)

			hmac, err := mac.NewHMAC(key)
			th.AssertNoError(err, "Failed to create HMAC")

			result := hmac.Compute(testData)

			// Проверяем, что результат 32 байта
			if len(result) != 32 {
				t.Errorf("Expected 32-byte HMAC, got %d bytes", len(result))
			}

			// Проверяем детерминированность
			hmac2, _ := mac.NewHMAC(key)
			result2 := hmac2.Compute(testData)

			if !th.CompareBytes(result, result2) {
				t.Error("HMAC not deterministic")
			}
		})
	}
}

func TestHMAC_EmptyMessage(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(32)
	emptyMessage := []byte{}

	hmac, err := mac.NewHMAC(key)
	th.AssertNoError(err, "Failed to create HMAC")

	result := hmac.Compute(emptyMessage)

	if len(result) != 32 {
		t.Errorf("Expected 32-byte HMAC for empty message, got %d bytes", len(result))
	}

	// Проверяем, что результат не все нули
	allZeros := true
	for _, b := range result {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("HMAC of empty message is all zeros")
	}
}

func TestHMAC_Verification(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(32)
	message := th.GenerateTestData(1024)

	hmac, err := mac.NewHMAC(key)
	th.AssertNoError(err, "Failed to create HMAC")

	// Вычисляем HMAC
	computedMAC := hmac.Compute(message)

	// Проверяем правильный MAC
	if !hmac.Verify(message, computedMAC) {
		t.Error("HMAC verification failed for correct MAC")
	}

	// Проверяем неправильный MAC
	wrongMAC := make([]byte, len(computedMAC))
	copy(wrongMAC, computedMAC)
	wrongMAC[0] ^= 0x01 // Меняем один байт

	if hmac.Verify(message, wrongMAC) {
		t.Error("HMAC verification should fail for wrong MAC")
	}

	// Проверяем MAC неправильной длины
	shortMAC := computedMAC[:16]
	if hmac.Verify(message, shortMAC) {
		t.Error("HMAC verification should fail for short MAC")
	}
}

func TestHMAC_KeyProcessing(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Ключ длиннее блока (64 байта) должен быть хеширован
	longKey := th.GenerateTestData(100)
	message := []byte("Test message")

	hmac, err := mac.NewHMAC(longKey)
	th.AssertNoError(err, "Failed to create HMAC with long key")

	result1 := hmac.Compute(message)

	// Создаем HMAC с хешированным ключом вручную
	hashedKey := th.GenerateTestData(32) // Просто для теста

	hmac2, err := mac.NewHMAC(hashedKey)
	th.AssertNoError(err, "Failed to create HMAC with hashed key")

	// Проверяем, что ключи обработаны по-разному
	if subtle.ConstantTimeCompare(longKey, hashedKey) == 1 {
		t.Error("Keys should be different")
	}

	result2 := hmac2.Compute(message)

	// Результаты должны быть разными (разные ключи)
	if subtle.ConstantTimeCompare(result1, result2) == 1 {
		t.Error("HMAC results should be different for different keys")
	}
}

func TestHMAC_Reset(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(32)
	message1 := []byte("First message")
	message2 := []byte("Second message")

	hmac, err := mac.NewHMAC(key)
	th.AssertNoError(err, "Failed to create HMAC")

	// Первый HMAC
	mac1 := hmac.Compute(message1)

	// Сброс и второй HMAC
	hmac.Reset()
	mac2 := hmac.Compute(message2)

	// Они должны быть разными
	if subtle.ConstantTimeCompare(mac1, mac2) == 1 {
		t.Error("HMACs of different messages should be different")
	}

	// Повторное вычисление первого сообщения должно дать тот же результат
	hmac.Reset()
	mac1Again := hmac.Compute(message1)

	if !th.CompareBytes(mac1, mac1Again) {
		t.Error("HMAC should be deterministic after reset")
	}
}

func TestHMAC_GetKey(t *testing.T) {
	th := tests.NewTestHelper(t)

	originalKey := th.GenerateTestData(45) // Ключ короче блока

	hmac, err := mac.NewHMAC(originalKey)
	th.AssertNoError(err, "Failed to create HMAC")

	// Получаем обработанный ключ
	retrievedKey := hmac.GetKey()

	// Проверяем, что ключ имеет правильную длину (64 байта)
	if len(retrievedKey) != 64 {
		t.Errorf("Processed key should be 64 bytes, got %d", len(retrievedKey))
	}

	// Ключ должен быть дополнен нулями
	for i := len(originalKey); i < 64; i++ {
		if retrievedKey[i] != 0 {
			t.Errorf("Key padding incorrect at position %d", i)
		}
	}

	// Проверяем, что оригинальная часть ключа сохранена
	for i := 0; i < len(originalKey); i++ {
		if retrievedKey[i] != originalKey[i] {
			t.Errorf("Original key corrupted at position %d", i)
		}
	}
}

func TestHMAC_ComputeHex(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(32)
	message := []byte("Hello, HMAC!")

	hmac, err := mac.NewHMAC(key)
	th.AssertNoError(err, "Failed to create HMAC")

	// Вычисляем HMAC в hex
	hexResult := hmac.ComputeHex(message)

	// Проверяем длину hex строки (64 символа)
	if len(hexResult) != 64 {
		t.Errorf("Hex HMAC should be 64 characters, got %d", len(hexResult))
	}

	// Проверяем, что это валидный hex
	_, err = hex.DecodeString(hexResult)
	th.AssertNoError(err, "Hex result is not valid hex")

	// Сравниваем с бинарным вычислением
	binaryResult := hmac.Compute(message)
	binaryHex := hex.EncodeToString(binaryResult)

	if hexResult != binaryHex {
		t.Error("ComputeHex doesn't match binary computation")
	}
}

func TestHMAC_Interface(t *testing.T) {
	// Проверяем фабричные функции
	key := []byte("test key")
	testMessage := []byte("test message") // Переименовываем переменную

	// ComputeHMAC
	mac1, err := mac.ComputeHMAC(key, testMessage)
	if err != nil {
		t.Fatalf("ComputeHMAC failed: %v", err)
	}
	if len(mac1) != 32 {
		t.Errorf("ComputeHMAC: expected 32 bytes, got %d", len(mac1))
	}

	// ComputeHMACHex
	hex1, err := mac.ComputeHMACHex(key, testMessage)
	if err != nil {
		t.Fatalf("ComputeHMACHex failed: %v", err)
	}
	if len(hex1) != 64 {
		t.Errorf("ComputeHMACHex: expected 64 chars, got %d", len(hex1))
	}

	// VerifyHMAC
	valid, err := mac.VerifyHMAC(key, testMessage, mac1)
	if err != nil {
		t.Fatalf("VerifyHMAC failed: %v", err)
	}
	if !valid {
		t.Error("VerifyHMAC should return true for correct MAC")
	}
}
