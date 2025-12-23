package unit

import (
	"cryptocore/src/hash"
	"cryptocore/tests"
	"testing"
)

func TestSHA3_256_EmptyString(t *testing.T) {
	th := tests.NewTestHelper(t)

	hasher := hash.NewSHA3_256()
	hasher.Update([]byte{})
	result := hasher.Finalize()

	// SHA3-256 of empty string
	expected := th.HexDecode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

	if !th.CompareBytes(expected, result) {
		t.Error("SHA3-256 of empty string incorrect")
		t.Logf("Expected: %s", th.HexDecodeToString(expected))
		t.Logf("Got:      %s", th.HexDecodeToString(result))
	}
}

func TestSHA3_256_ShortMessages(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{
			name:     "abc",
			input:    "abc",
			expected: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		},
		{
			name:     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			input:    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			expected: "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
		},
		{
			name:     "The quick brown fox jumps over the lazy dog",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
		},
		{
			name:     "The quick brown fox jumps over the lazy cog",
			input:    "The quick brown fox jumps over the lazy cog",
			expected: "cc80b0b13ba89613d93f02ee7ccbe72ee26c6edfe577f22e63a1380221caedbc", // Исправленный хеш
		},
		{
			name:     "Hello World",
			input:    "Hello World",
			expected: "e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher := hash.NewSHA3_256()
			hasher.Update([]byte(tc.input))
			result := hasher.Finalize()

			expected := th.HexDecode(tc.expected)
			if !th.CompareBytes(expected, result) {
				t.Errorf("SHA3-256 of %q incorrect", tc.name)
			}
		})
	}
}

func TestSHA3_256_IncrementalUpdate(t *testing.T) {
	th := tests.NewTestHelper(t)

	message := "The quick brown fox jumps over the lazy dog"

	// Полный хеш за один раз
	hasher1 := hash.NewSHA3_256()
	hasher1.Update([]byte(message))
	fullHash := hasher1.Finalize()

	// Инкрементальный хеш
	hasher2 := hash.NewSHA3_256()

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

func TestSHA3_256_LongMessage(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Тест с сообщением из 1,000,000 символов 'a'
	hasher := hash.NewSHA3_256()

	const chunkSize = 8192
	data := make([]byte, chunkSize)
	for i := range data {
		data[i] = 'a'
	}

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

	// SHA3-256 of 1,000,000 'a' characters
	expected := th.HexDecode("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1")

	if !th.CompareBytes(expected, result) {
		t.Error("SHA3-256 of 1,000,000 'a' characters incorrect")
	}
}

func TestSHA3_256_Reset(t *testing.T) {
	th := tests.NewTestHelper(t)

	hasher := hash.NewSHA3_256()

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
	expected := th.HexDecode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")

	if !th.CompareBytes(expected, result) {
		t.Error("Hash after reset is incorrect")
	}
}

func TestSHA3_256_BlockSize(t *testing.T) {
	hasher := hash.NewSHA3_256()

	// SHA3-256 имеет rate = 136 байт
	if hasher.BlockSize() != 136 {
		t.Errorf("Expected block size 136, got %d", hasher.BlockSize())
	}
}

func TestSHA3_256_BinaryData(t *testing.T) {

	// Тестируем с бинарными данными
	testData := []struct {
		input []byte
		name  string
	}{
		{
			name:  "All zeros",
			input: make([]byte, 100),
		},
		{
			name:  "Incremental bytes",
			input: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
	}

	for _, tc := range testData {
		t.Run(tc.name, func(t *testing.T) {
			hasher := hash.NewSHA3_256()
			hasher.Update(tc.input)
			result := hasher.Finalize()

			// Для тестирования просто проверяем, что хеш вычислен
			if len(result) != 32 {
				t.Errorf("Expected 32-byte hash, got %d bytes", len(result))
			}

			// Проверяем, что хеш не состоит полностью из нулей
			allZeros := true
			for _, b := range result {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("Hash is all zeros")
			}
		})
	}
}

func TestSHA3_256_Interface(t *testing.T) {
	// Проверяем, что реализуется интерфейс Hasher
	var _ hash.Hasher = hash.NewSHA3_256()
}
