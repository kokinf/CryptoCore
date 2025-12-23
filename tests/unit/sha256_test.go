package unit

import (
	"cryptocore/src/hash"
	"cryptocore/tests"
	"testing"
)

func TestSHA256_EmptyString(t *testing.T) {
	th := tests.NewTestHelper(t)

	hasher := hash.NewSHA256()
	hasher.Update([]byte{})
	result := hasher.Finalize()

	// SHA-256 of empty string
	expected := th.HexDecode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	if !th.CompareBytes(expected, result) {
		t.Error("SHA-256 of empty string incorrect")
	}
}

func TestSHA256_ShortMessages(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{
			name:     "abc",
			input:    "abc",
			expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name:     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			input:    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			name:     "The quick brown fox jumps over the lazy dog",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
		{
			name:     "The quick brown fox jumps over the lazy cog",
			input:    "The quick brown fox jumps over the lazy cog",
			expected: "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher := hash.NewSHA256()
			hasher.Update([]byte(tc.input))
			result := hasher.Finalize()

			expected := th.HexDecode(tc.expected)
			if !th.CompareBytes(expected, result) {
				t.Errorf("SHA-256 of %q incorrect", tc.name)
			}
		})
	}
}

func TestSHA256_LongMessage(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Тест с сообщением из миллиона символов 'a'
	hasher := hash.NewSHA256()

	// Используем буфер для эффективности
	const chunkSize = 8192
	data := make([]byte, chunkSize)
	for i := range data {
		data[i] = 'a'
	}

	// Добавляем 1,000,000 символов 'a'
	total := 0
	for total < 1000000 {
		toWrite := chunkSize
		if 1000000-total < chunkSize {
			toWrite = 1000000 - total
		}
		hasher.Update(data[:toWrite])
		total += toWrite
	}

	result := hasher.Finalize()

	// SHA-256 of 1,000,000 'a' characters
	expected := th.HexDecode("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

	if !th.CompareBytes(expected, result) {
		t.Error("SHA-256 of 1,000,000 'a' characters incorrect")
	}
}

func TestSHA256_IncrementalUpdate(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Тестируем инкрементальное обновление
	message := "The quick brown fox jumps over the lazy dog"

	// Полный хеш за один раз
	hasher1 := hash.NewSHA256()
	hasher1.Update([]byte(message))
	fullHash := hasher1.Finalize()

	// Инкрементальный хеш
	hasher2 := hash.NewSHA256()

	// Добавляем по частям
	parts := []string{"The quick ", "brown fox ", "jumps over ", "the lazy dog"}
	for _, part := range parts {
		hasher2.Update([]byte(part))
	}

	incrementalHash := hasher2.Finalize()

	if !th.CompareBytes(fullHash, incrementalHash) {
		t.Error("Incremental hashing produces different result")
	}
}

func TestSHA256_Reset(t *testing.T) {
	th := tests.NewTestHelper(t)

	hasher := hash.NewSHA256()

	// Первое сообщение
	hasher.Update([]byte("first message"))
	hash1 := hasher.Finalize()

	// Сброс
	hasher.Reset()

	// Второе сообщение
	hasher.Update([]byte("second message"))
	hash2 := hasher.Finalize()

	// Хеши должны быть разными
	if th.IsEqual(hash1, hash2) {
		t.Error("Reset didn't work, hashes are the same")
	}

	// Проверяем, что после сброса хеш корректный
	hasher.Reset()
	hasher.Update([]byte("abc"))
	result := hasher.Finalize()
	expected := th.HexDecode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

	if !th.CompareBytes(expected, result) {
		t.Error("Hash after reset is incorrect")
	}
}

func TestSHA256_BlockSize(t *testing.T) {
	hasher := hash.NewSHA256()

	if hasher.BlockSize() != 64 {
		t.Errorf("Expected block size 64, got %d", hasher.BlockSize())
	}
}

func TestSHA256_Interface(t *testing.T) {
	// Проверяем, что реализуется интерфейс Hasher
	var _ hash.Hasher = hash.NewSHA256()
}
