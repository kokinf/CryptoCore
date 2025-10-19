package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"time"
)

// generateRandomBytesDirect - реализация идентичная GenerateRandomBytes из src/csprng.go
func generateRandomBytesDirect(numBytes int) ([]byte, error) {
	if numBytes <= 0 {
		return nil, fmt.Errorf("количество байт должно быть положительным")
	}

	buffer := make([]byte, numBytes)

	_, err := io.ReadFull(rand.Reader, buffer)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации случайных байт: %v", err)
	}

	return buffer, nil
}

// Проверка уникальности сгенерированных ключей (1000 ключей)
func testKeyUniqueness() error {
	fmt.Println("ТЕСТ 1: Уникальность 1000 ключей")

	keySet := make(map[string]bool)
	numKeys := 1000

	fmt.Printf("Генерация %d ключей для проверки уникальности...\n", numKeys)

	startTime := time.Now()
	duplicates := 0

	for i := 0; i < numKeys; i++ {
		key, err := generateRandomBytesDirect(16)
		if err != nil {
			return fmt.Errorf("ошибка генерации ключа %d: %v", i, err)
		}

		keyHex := fmt.Sprintf("%x", key)

		if keySet[keyHex] {
			duplicates++
			if duplicates <= 3 {
				fmt.Printf("Обнаружен дубликат ключа [%d]: %s\n", i, keyHex)
			}
		}

		keySet[keyHex] = true

		if (i+1)%100 == 0 {
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("Успешно сгенерировано %d уникальных ключей из %d попыток\n", len(keySet), numKeys)
	fmt.Printf("Время выполнения: %v\n", duration)
	fmt.Printf("Дубликатов: %d\n", duplicates)

	if duplicates > 0 {
		return fmt.Errorf("обнаружено %d дубликатов ключей", duplicates)
	}

	return nil
}

// Проверка статистического распределения битов
func testBitDistribution() error {
	fmt.Println("\nТЕСТ 2: Статистическое распределение битов")

	totalBits := 0
	totalOnes := 0
	numSamples := 1000
	sampleSize := 16

	fmt.Printf("Анализ распределения битов для %d samples...\n", numSamples)

	for i := 0; i < numSamples; i++ {
		data, err := generateRandomBytesDirect(sampleSize)
		if err != nil {
			return fmt.Errorf("ошибка генерации данных: %v", err)
		}

		for _, b := range data {
			totalBits += 8
			for j := 0; j < 8; j++ {
				if b&(1<<j) != 0 {
					totalOnes++
				}
			}
		}
	}

	if totalBits == 0 {
		return fmt.Errorf("не удалось проанализировать ни одного бита")
	}

	onesPercentage := float64(totalOnes) / float64(totalBits) * 100
	deviation := math.Abs(onesPercentage - 50.0)

	fmt.Printf("Процент единичных битов: %.4f%%\n", onesPercentage)
	fmt.Printf("Отклонение от идеала: %.4f%%\n", deviation)
	fmt.Printf("Проанализировано битов: %d\n", totalBits)

	if deviation > 5.0 {
		return fmt.Errorf("слишком большое отклонение: %.4f%% (> 5%%)", deviation)
	}

	if onesPercentage < 45.0 || onesPercentage > 55.0 {
		return fmt.Errorf("подозрительное распределение битов: %.4f%%", onesPercentage)
	}

	fmt.Println("Распределение битов в норме")
	return nil
}

// Подготовка данных для тестирования NIST STS (10 МБ)
func testNISTDataPreparation() error {
	fmt.Println("\nТЕСТ 3: Подготовка данных для NIST STS")

	totalSize := int64(10_000_000) // 10 MB
	outputFile := "nist_test_data.bin"

	fmt.Printf("Генерация %d MB случайных данных для NIST STS...\n", totalSize/(1024*1024))

	os.Remove(outputFile)

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("ошибка создания файла: %v", err)
	}
	defer file.Close()

	bytesWritten := int64(0)
	chunkSize := 1024 * 1024
	startTime := time.Now()

	for bytesWritten < totalSize {
		currentChunk := chunkSize
		if bytesWritten+int64(currentChunk) > totalSize {
			currentChunk = int(totalSize - bytesWritten)
		}

		randomData, err := generateRandomBytesDirect(currentChunk)
		if err != nil {
			return fmt.Errorf("ошибка генерации данных: %v", err)
		}

		_, err = file.Write(randomData)
		if err != nil {
			return fmt.Errorf("ошибка записи в файл: %v", err)
		}

		bytesWritten += int64(currentChunk)

		if bytesWritten%(5*1024*1024) == 0 {
			fmt.Printf("Сгенерировано %d/%d MB...\n", bytesWritten/(1024*1024), totalSize/(1024*1024))
		}
	}

	duration := time.Since(startTime)

	fileInfo, err := os.Stat(outputFile)
	if err != nil {
		return fmt.Errorf("ошибка проверки файла: %v", err)
	}

	fmt.Printf("Успешно сгенерировано %d MB за %v\n", fileInfo.Size()/(1024*1024), duration)
	fmt.Printf("Файл: %s (%d байт)\n", outputFile, fileInfo.Size())

	if fileInfo.Size() != totalSize {
		return fmt.Errorf("некорректный размер файла: %d (ожидалось %d)", fileInfo.Size(), totalSize)
	}

	return nil
}

// Тестирует генерацию данных разных размеров
func testVariousSizes() error {
	fmt.Println("\nТЕСТ 4: Генерация данных разных размеров")

	sizes := []int{1, 16, 64, 256, 1024, 4096, 16384}

	for _, size := range sizes {
		data, err := generateRandomBytesDirect(size)
		if err != nil {
			return fmt.Errorf("ошибка генерации %d байт: %v", size, err)
		}

		if len(data) != size {
			return fmt.Errorf("некорректный размер данных: %d (ожидалось %d)", len(data), size)
		}

		allZeros := true
		for _, b := range data {
			if b != 0 {
				allZeros = false
				break
			}
		}

		if allZeros {
			return fmt.Errorf("данные размером %d байт состоят только из нулей", size)
		}

		fmt.Printf("Размер %5d байт: OK\n", size)
	}

	fmt.Println("Все размеры обработаны корректно")
	return nil
}

// Тестирует генерацию векторов инициализации (IV)
func testIVGeneration() error {
	fmt.Println("\n=== ТЕСТ 5: Генерация векторов инициализации (IV) ===")

	numIVs := 100
	ivSize := 16
	ivSet := make(map[string]bool)

	fmt.Printf("Генерация %d IV...\n", numIVs)

	for i := 0; i < numIVs; i++ {
		iv, err := generateRandomBytesDirect(ivSize)
		if err != nil {
			return fmt.Errorf("ошибка генерации IV %d: %v", i, err)
		}

		if len(iv) != ivSize {
			return fmt.Errorf("некорректный размер IV: %d (ожидалось %d)", len(iv), ivSize)
		}

		ivHex := fmt.Sprintf("%x", iv)

		if ivSet[ivHex] {
			return fmt.Errorf("обнаружен дубликат IV: %s", ivHex)
		}

		ivSet[ivHex] = true
	}

	fmt.Printf("Успешно сгенерировано %d уникальных IV\n", len(ivSet))

	allZeroIV, _ := generateRandomBytesDirect(ivSize)
	allZero := true
	for _, b := range allZeroIV {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		return fmt.Errorf("IV состоит только из нулей")
	}

	fmt.Println("IV генерация работает корректно")
	return nil
}

// Проверяет обработку граничных случаев
func testEdgeCases() error {
	fmt.Println("\nТЕСТ 6: Обработка граничных случаев")

	// Нулевой размер
	fmt.Println("Проверка нулевого размера...")
	_, err := generateRandomBytesDirect(0)
	if err == nil {
		return fmt.Errorf("ожидалась ошибка для нулевого размера")
	}
	fmt.Println("Нулевой размер: корректная ошибка")

	// Отрицательный размер
	fmt.Println("Проверка отрицательного размера...")
	_, err = generateRandomBytesDirect(-1)
	if err == nil {
		return fmt.Errorf("ожидалась ошибка для отрицательного размера")
	}
	fmt.Println("Отрицательный размер: корректная ошибка")

	fmt.Println("Проверка большого размера...")
	largeData, err := generateRandomBytesDirect(1024 * 1024)
	if err != nil {
		return fmt.Errorf("ошибка генерации большого объема: %v", err)
	}

	if len(largeData) != 1024*1024 {
		return fmt.Errorf("некорректный размер больших данных: %d", len(largeData))
	}
	fmt.Println("Большой размер: OK")

	// Размер 1 байт
	fmt.Println("Проверка минимального размера (1 байт)...")
	oneByte, err := generateRandomBytesDirect(1)
	if err != nil {
		return fmt.Errorf("ошибка генерации 1 байта: %v", err)
	}

	if len(oneByte) != 1 {
		return fmt.Errorf("некорректный размер для 1 байта: %d", len(oneByte))
	}
	fmt.Println("Минимальный размер: OK")

	fmt.Println("Все граничные случаи обработаны корректно")
	return nil
}

// Проверяет, что последовательные вызовы дают разные результаты
func testSequentialCalls() error {
	fmt.Println("\nТЕСТ 7: Последовательные вызовы")

	numCalls := 100
	dataSize := 32
	previousData := ""

	fmt.Printf("Проверка %d последовательных вызовов...\n", numCalls)

	for i := 0; i < numCalls; i++ {
		data, err := generateRandomBytesDirect(dataSize)
		if err != nil {
			return fmt.Errorf("ошибка вызова %d: %v", i, err)
		}

		currentData := fmt.Sprintf("%x", data)

		if currentData == previousData {
			return fmt.Errorf("повторяющиеся данные на вызове %d: %s", i, currentData)
		}

		previousData = currentData

		if (i+1)%20 == 0 {
			fmt.Printf("Выполнено %d/%d вызовов...\n", i+1, numCalls)
		}
	}

	fmt.Printf("Все %d последовательных вызовов дали разные результаты\n", numCalls)
	return nil
}

// Интеграционный тест - проверка через cryptocore
func testIntegrationWithCryptocore() error {
	fmt.Println("\nТЕСТ 8: Интеграционный тест с Cryptocore")

	if _, err := os.Stat("../cryptocore"); os.IsNotExist(err) {
		fmt.Println("Сборка cryptocore...")
		cmd := exec.Command("go", "build", "-o", "cryptocore", "./src")
		cmd.Dir = ".."
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ошибка сборки cryptocore: %v\n%s", err, output)
		}
	}

	testFile := "integration_test.txt"
	testContent := "Integration test data for CSPRNG testing 12345"
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		return err
	}
	defer os.Remove(testFile)

	// Шифрование с автогенерацией ключа
	fmt.Println("Тест шифрования с автогенерацией ключа...")
	encryptedFile := "integration_test.enc"

	cmd := exec.Command("../cryptocore", "--algorithm", "aes", "--mode", "cbc", "--encrypt",
		"--input", testFile, "--output", encryptedFile)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("ошибка шифрования: %v\n%s", err, output)
	}
	defer os.Remove(encryptedFile)

	outputStr := string(output)

	if !strings.Contains(outputStr, "Сгенерированный ключ: ") {
		return fmt.Errorf("ключ не был сгенерирован\nВывод: %s", outputStr)
	}

	keyHex := ""
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Сгенерированный ключ: ") {
			parts := strings.Split(line, "Сгенерированный ключ: ")
			if len(parts) > 1 {
				keyHex = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	if len(keyHex) != 32 {
		return fmt.Errorf("некорректный формат ключа: %s", keyHex)
	}

	fmt.Printf("Ключ сгенерирован: %s\n", keyHex)

	// Проверяем что зашифрованный файл создан
	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		return fmt.Errorf("зашифрованный файл не создан")
	}

	encData, err := os.ReadFile(encryptedFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения зашифрованного файла: %v", err)
	}

	if len(encData) <= 16 {
		return fmt.Errorf("зашифрованный файл слишком короткий: %d байт", len(encData))
	}

	fmt.Printf("Зашифрованный файл создан: %d байт\n", len(encData))

	// Дешифрование
	fmt.Println("Тест дешифрования...")
	decryptedFile := "integration_test_decrypted.txt"

	cmd = exec.Command("../cryptocore", "--algorithm", "aes", "--mode", "cbc", "--decrypt",
		"--key", keyHex, "--input", encryptedFile, "--output", decryptedFile)
	output, err = cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("ошибка дешифрования: %v\n%s", err, output)
	}
	defer os.Remove(decryptedFile)

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения дешифрованного файла: %v", err)
	}

	if string(decryptedContent) != testContent {
		return fmt.Errorf("дешифрованные данные не совпадают с оригиналом")
	}

	fmt.Println("Дешифрование успешно")
	fmt.Println("Интеграционный тест пройден")
	return nil
}

func main() {

	startTime := time.Now()

	tests := []struct {
		name string
		test func() error
	}{
		{"Уникальность ключей", testKeyUniqueness},
		{"Статистическое распределение битов", testBitDistribution},
		{"Подготовка данных NIST STS", testNISTDataPreparation},
		{"Генерация данных разных размеров", testVariousSizes},
		{"Генерация векторов инициализации", testIVGeneration},
		{"Обработка граничных случаев", testEdgeCases},
		{"Последовательные вызовы", testSequentialCalls},
		{"Интеграционный тест", testIntegrationWithCryptocore},
	}

	passed := 0
	failed := 0

	for _, tc := range tests {
		fmt.Printf("\n--- %s ---\n", tc.name)
		if err := tc.test(); err != nil {
			fmt.Printf("ТЕСТ FAILED: %v\n", err)
			failed++
		} else {
			fmt.Printf("ТЕСТ PASSED\n")
			passed++
		}
	}

	totalTime := time.Since(startTime)

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("ИТОГИ ТЕСТИРОВАНИЯ:\n")
	fmt.Printf("Пройдено: %d тестов\n", passed)
	fmt.Printf("Провалено: %d тестов\n", failed)
	fmt.Printf("Общее время: %v\n", totalTime)
	fmt.Printf("Успешность: %.1f%%\n", float64(passed)/float64(passed+failed)*100)

	if failed > 0 {
		fmt.Println("\nНЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
		os.Exit(1)
	}

}
