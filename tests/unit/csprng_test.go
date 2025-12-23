package unit

import (
	"crypto/aes"
	"cryptocore/src/csprng"
	"cryptocore/tests"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestGenerateRandomBytes_Basic(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name     string
		numBytes int
		expectOk bool
	}{
		{"1 byte", 1, true},
		{"16 bytes", 16, true},
		{"32 bytes", 32, true},
		{"256 bytes", 256, true},
		{"4096 bytes", 4096, true},
		{"Zero bytes", 0, false},
		{"Negative bytes", -1, false},
		{"Large amount", 1024 * 1024, true}, // 1 MB
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := csprng.GenerateRandomBytes(tc.numBytes)

			if !tc.expectOk {
				th.AssertErrorf(err, "Expected error for %s", tc.name)
				return
			}

			th.AssertNoErrorf(err, "GenerateRandomBytes failed for %s", tc.name)

			// Проверяем длину
			if len(data) != tc.numBytes {
				t.Errorf("Wrong length: expected %d, got %d", tc.numBytes, len(data))
			}

			// Для не-пустых данных проверяем, что они не все нули
			if tc.numBytes > 0 {
				allZeros := true
				for _, b := range data {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("Random data is all zeros")
				}
			}
		})
	}
}

func TestGenerateRandomBytes_Uniqueness(t *testing.T) {
	th := tests.NewTestHelper(t)

	numSamples := 100
	bytesPerSample := 16

	generated := make(map[string]bool)
	duplicates := 0

	for i := 0; i < numSamples; i++ {
		data, err := csprng.GenerateRandomBytes(bytesPerSample)
		th.AssertNoErrorf(err, "GenerateRandomBytes failed at iteration %d", i)

		hexData := hex.EncodeToString(data)

		if generated[hexData] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate found at iteration %d: %s...", i, hexData[:16])
			}
		}

		generated[hexData] = true
	}

	uniqueCount := len(generated)

	t.Logf("Generated %d unique random strings out of %d attempts", uniqueCount, numSamples)
	t.Logf("Duplicates: %d", duplicates)

	// Для CSPRNG вероятность коллизии должна быть очень низкой
	if duplicates > 0 {
		t.Errorf("Found %d duplicates in %d samples - CSPRNG might be flawed",
			duplicates, numSamples)
	}

	// Проверяем, что получили все уникальные значения
	if uniqueCount != numSamples {
		t.Errorf("Expected %d unique values, got %d", numSamples, uniqueCount)
	}
}

func TestGenerateRandomBytes_Statistical(t *testing.T) {
	th := tests.NewTestHelper(t)

	if testing.Short() {
		t.Skip("Skipping statistical test in short mode")
	}

	// Генерируем достаточно данных для статистического анализа
	totalBytes := 1024 * 1024 // 1 MB
	chunkSize := 4096

	var totalBits int
	var onesCount int

	for bytesGenerated := 0; bytesGenerated < totalBytes; bytesGenerated += chunkSize {
		data, err := csprng.GenerateRandomBytes(chunkSize)
		th.AssertNoErrorf(err, "GenerateRandomBytes failed")

		// Анализируем биты
		for _, b := range data {
			for bit := 0; bit < 8; bit++ {
				totalBits++
				if (b>>bit)&1 == 1 {
					onesCount++
				}
			}
		}
	}

	zerosCount := totalBits - onesCount
	onesRatio := float64(onesCount) / float64(totalBits)

	t.Logf("Statistical analysis of %d random bits:", totalBits)
	t.Logf("  Ones: %d (%.2f%%)", onesCount, onesRatio*100)
	t.Logf("  Zeros: %d (%.2f%%)", zerosCount, (1-onesRatio)*100)

	// Для хорошего CSPRNG соотношение должно быть близко к 50/50
	const tolerance = 0.01 // 1% допуск
	expectedRatio := 0.5

	if onesRatio < expectedRatio-tolerance || onesRatio > expectedRatio+tolerance {
		t.Errorf("Bit ratio %.4f is outside acceptable range [%.3f, %.3f]",
			onesRatio, expectedRatio-tolerance, expectedRatio+tolerance)
	}

	// Проверяем, что есть и нули и единицы
	if onesCount == 0 || zerosCount == 0 {
		t.Error("Random data should contain both 0s and 1s")
	}
}

func TestGenerateRandomBytes_Distribution(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Тестируем распределение байтов
	numSamples := 10000
	byteCounts := make([]int, 256)

	for i := 0; i < numSamples; i++ {
		data, err := csprng.GenerateRandomBytes(1)
		th.AssertNoErrorf(err, "GenerateRandomBytes failed")

		byteCounts[data[0]]++
	}

	// Рассчитываем хи-квадрат статистику
	expectedCount := float64(numSamples) / 256.0
	chiSquared := 0.0

	for _, count := range byteCounts {
		diff := float64(count) - expectedCount
		chiSquared += (diff * diff) / expectedCount
	}

	t.Logf("Byte distribution analysis of %d random bytes:", numSamples)
	t.Logf("  Expected per byte: %.1f", expectedCount)
	t.Logf("  Chi-squared statistic: %.2f", chiSquared)

	// Для равномерного распределения и 255 степеней свободы,
	// хи-квадрат должен быть в разумных пределах
	// (это упрощенная проверка, не формальный тест)
	const maxReasonableChi2 = 350 // Эмпирическое значение для 255 степеней свободы

	if chiSquared > float64(maxReasonableChi2) {
		t.Logf("Warning: Chi-squared value %.2f is high (max reasonable ~%d)",
			chiSquared, maxReasonableChi2)
		t.Log("This could indicate non-uniform distribution")
	}

	// Проверяем, что все байты встречаются
	missingBytes := 0
	for i, count := range byteCounts {
		if count == 0 {
			missingBytes++
			if missingBytes <= 10 {
				t.Logf("  Byte 0x%02x never occurred", i)
			}
		}
	}

	if missingBytes > 0 {
		t.Logf("  Total missing bytes: %d out of 256", missingBytes)
		// Некоторые байты могут не встретиться при малом количестве семплов
		if missingBytes > 50 {
			t.Error("Too many byte values never occurred")
		}
	}
}

func TestGenerateRandomBytes_ErrorHandling(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Тестируем обработку ошибок через интерфейс ошибок
	testCases := []struct {
		name      string
		numBytes  int
		expectErr bool
	}{
		{"Negative", -1, true},
		{"Zero", 0, true},
		{"Positive", 1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := csprng.GenerateRandomBytes(tc.numBytes)

			if tc.expectErr {
				th.AssertErrorf(err, "Expected error for %s", tc.name)
				// Проверяем тип ошибки
				if _, ok := err.(*csprng.CSPRNGError); !ok {
					t.Errorf("Expected CSPRNGError, got %T", err)
				}
			} else {
				th.AssertNoErrorf(err, "Should generate random bytes for %s", tc.name)
			}
		})
	}
}

func TestGenerateRandomBytes_Concurrent(t *testing.T) {

	// Тестируем конкурентную генерацию
	numGoroutines := 10
	iterationsPerGoroutine := 100
	bytesPerGeneration := 16

	errChan := make(chan error, numGoroutines)
	resultsChan := make(chan []byte, numGoroutines*iterationsPerGoroutine)

	// Запускаем горутины
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < iterationsPerGoroutine; j++ {
				data, err := csprng.GenerateRandomBytes(bytesPerGeneration)
				if err != nil {
					errChan <- fmt.Errorf("goroutine %d, iteration %d: %v", id, j, err)
					return
				}
				resultsChan <- data
			}
			errChan <- nil
		}(i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		if err != nil {
			t.Fatalf("Concurrent generation failed: %v", err)
		}
	}

	close(resultsChan)

	// Собираем и проверяем результаты
	results := make(map[string]bool)
	for data := range resultsChan {
		hexData := hex.EncodeToString(data)

		if results[hexData] {
			t.Error("Duplicate random data found in concurrent generation")
			break
		}

		results[hexData] = true
	}

	expectedTotal := numGoroutines * iterationsPerGoroutine
	if len(results) != expectedTotal {
		t.Errorf("Expected %d unique results, got %d", expectedTotal, len(results))
	}

	t.Logf("Successfully generated %d unique random values concurrently", len(results))
}

func TestGenerateRandomBytes_Integration(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Интеграционный тест: используем CSPRNG для генерации реальных ключей и IV

	t.Run("Generate AES key", func(t *testing.T) {
		key, err := csprng.GenerateRandomBytes(16) // AES-128
		th.AssertNoErrorf(err, "Failed to generate AES key")

		if len(key) != 16 {
			t.Errorf("AES key should be 16 bytes, got %d", len(key))
		}

		// Проверяем, что ключ не слабый (не все нули, не последовательный и т.д.)
		allSame := true
		firstByte := key[0]
		for _, b := range key {
			if b != firstByte {
				allSame = false
				break
			}
		}
		if allSame {
			t.Error("Generated key has all bytes identical")
		}

		// Проверяем, что можно создать AES шифр с этим ключом
		_, err = aes.NewCipher(key)
		th.AssertNoErrorf(err, "Generated key is not valid for AES")
	})

	t.Run("Generate IV for CBC", func(t *testing.T) {
		iv, err := csprng.GenerateRandomBytes(16)
		th.AssertNoErrorf(err, "Failed to generate IV")

		if len(iv) != 16 {
			t.Errorf("IV should be 16 bytes, got %d", len(iv))
		}

		// IV должен быть уникальным при повторной генерации
		iv2, _ := csprng.GenerateRandomBytes(16)
		if th.IsEqual(iv, iv2) {
			t.Error("Subsequent IV generation produced identical result")
		}
	})

	t.Run("Generate nonce for GCM", func(t *testing.T) {
		nonce, err := csprng.GenerateRandomBytes(12)
		th.AssertNoErrorf(err, "Failed to generate GCM nonce")

		if len(nonce) != 12 {
			t.Errorf("GCM nonce should be 12 bytes, got %d", len(nonce))
		}
	})

	t.Run("Generate salt for PBKDF2", func(t *testing.T) {
		salt, err := csprng.GenerateRandomBytes(16)
		th.AssertNoErrorf(err, "Failed to generate salt")

		if len(salt) != 16 {
			t.Errorf("Salt should be 16 bytes, got %d", len(salt))
		}

		// Соль должна быть уникальной
		salt2, _ := csprng.GenerateRandomBytes(16)
		if th.IsEqual(salt, salt2) {
			t.Error("Subsequent salt generation produced identical result")
		}
	})
}

func TestGenerateRandomBytes_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Тестируем производительность генерации
	testCases := []struct {
		name       string
		size       int
		iterations int
	}{
		{"Small (16B)", 16, 10000},
		{"Medium (1KB)", 1024, 1000},
		{"Large (64KB)", 64 * 1024, 100},
		{"Very Large (1MB)", 1024 * 1024, 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()

			totalBytes := 0
			for i := 0; i < tc.iterations; i++ {
				data, err := csprng.GenerateRandomBytes(tc.size)
				if err != nil {
					t.Fatalf("GenerateRandomBytes failed: %v", err)
				}
				totalBytes += len(data)
			}

			elapsed := time.Since(start)

			throughput := float64(totalBytes) / (1024 * 1024) / elapsed.Seconds()

			t.Logf("Generated %d bytes in %v", totalBytes, elapsed)
			t.Logf("Throughput: %.2f MB/s", throughput)
			t.Logf("Latency per call: %v", elapsed/time.Duration(tc.iterations))

			// Для CSPRNG производительность обычно ниже, чем для PRNG
			// Но она все равно должна быть приемлемой
			if throughput < 0.1 { // Меньше 100 KB/s - слишком медленно
				t.Errorf("Throughput too low: %.2f MB/s", throughput)
			}
		})
	}
}
