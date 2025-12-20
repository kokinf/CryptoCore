package main

import (
	"crypto/subtle"
	"cryptocore/src/aead"
	"cryptocore/src/csprng"
	"cryptocore/src/mac"
	"cryptocore/src/modes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FileIOError struct {
	Operation string
	Path      string
	Err       error
}

func (e *FileIOError) Error() string {
	return fmt.Sprintf("ошибка ввода-вывода при %s файла '%s': %v", e.Operation, e.Path, e.Err)
}

// ExecuteCryptoOperation выполняет операцию шифрования или дешифрования
func ExecuteCryptoOperation(config *Config) error {
	if config.Encrypt {
		return executeEncryption(config)
	} else {
		return executeDecryption(config)
	}
}

func ExecuteMACOperation(config *Config) error {
	if config.VerifyFile != "" {
		return executeHMACVerification(config)
	} else {
		return executeHMACGeneration(config)
	}
}

func generateRandomIV() ([]byte, error) {
	return csprng.GenerateRandomBytes(16)
}

func generateRandomNonce() ([]byte, error) {
	return csprng.GenerateRandomBytes(12)
}

func executeEncryption(config *Config) error {
	plaintext, err := ReadInputFile(config.InputFile)
	if err != nil {
		return err
	}

	if config.UseAEAD {
		if config.Mode == "gcm" {
			return executeGCMEncryption(config, plaintext)
		}
	}

	if config.UseETM {
		return executeETMEncryption(config, plaintext)
	}

	return executeRegularEncryption(config, plaintext)
}

func executeRegularEncryption(config *Config, plaintext []byte) error {
	if config.Key == nil {
		generatedKey, err := csprng.GenerateRandomBytes(16)
		if err != nil {
			return fmt.Errorf("ошибка генерации ключа: %v", err)
		}
		config.Key = generatedKey

		fmt.Printf("Сгенерированный ключ: %s\n", hex.EncodeToString(config.Key))
	}

	switch config.Mode {
	case "ecb":
		ciphertext, err := modes.ECBEncrypt(plaintext, config.Key)
		if err != nil {
			return fmt.Errorf("ошибка шифрования ECB: %v", err)
		}
		return WriteOutputFile(config.OutputFile, ciphertext)

	case "cbc":
		iv, err := generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для CBC: %v", err)
		}
		ciphertext, err := modes.CBCEncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования CBC: %v", err)
		}
		return writeEncryptionOutput(config, ciphertext, iv)

	case "cfb":
		iv, err := generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для CFB: %v", err)
		}
		ciphertext, err := modes.CFBEncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования CFB: %v", err)
		}
		return writeEncryptionOutput(config, ciphertext, iv)

	case "ofb":
		iv, err := generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для OFB: %v", err)
		}
		ciphertext, err := modes.OFBEncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования OFB: %v", err)
		}
		return writeEncryptionOutput(config, ciphertext, iv)

	case "ctr":
		iv, err := generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для CTR: %v", err)
		}
		ciphertext, err := modes.CTREncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования CTR: %v", err)
		}
		return writeEncryptionOutput(config, ciphertext, iv)

	default:
		return fmt.Errorf("неподдерживаемый режим: %s", config.Mode)
	}
}

func executeETMEncryption(config *Config, plaintext []byte) error {
	if len(config.Key) != 48 {
		return fmt.Errorf("для Encrypt-then-MAC требуется ключ 48 байт, получено %d байт", len(config.Key))
	}

	etm, err := aead.NewEncryptThenMac(config.Key, config.Mode)
	if err != nil {
		return fmt.Errorf("ошибка создания Encrypt-then-MAC: %v", err)
	}

	ciphertext, err := etm.Encrypt(plaintext, config.AAD)
	if err != nil {
		return fmt.Errorf("ошибка шифрования Encrypt-then-MAC: %v", err)
	}

	if err := WriteOutputFile(config.OutputFile, ciphertext); err != nil {
		CleanupFailedOutput(config.OutputFile)
		return err
	}

	fmt.Printf("Encrypt-then-MAC encryption completed with mode: %s\n", config.Mode)
	if len(config.AAD) > 0 {
		fmt.Printf("AAD used: %s\n", hex.EncodeToString(config.AAD))
	}
	return nil
}

func executeGCMEncryption(config *Config, plaintext []byte) error {
	if config.Key == nil {
		generatedKey, err := csprng.GenerateRandomBytes(16)
		if err != nil {
			return fmt.Errorf("ошибка генерации ключа: %v", err)
		}
		config.Key = generatedKey

		fmt.Printf("Сгенерированный ключ: %s\n", hex.EncodeToString(config.Key))
	}

	gcm, err := aead.NewGCM(config.Key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM: %v", err)
	}

	if config.IV != nil && len(config.IV) > 0 {
		if len(config.IV) != 12 {
			return fmt.Errorf("некорректная длина nonce: %d байт (должно быть 12 байт)", len(config.IV))
		}
		if err := gcm.SetNonce(config.IV); err != nil {
			return fmt.Errorf("ошибка установки nonce: %v", err)
		}
		fmt.Printf("Используется указанный nonce: %s\n", hex.EncodeToString(config.IV))
	}

	ciphertextWithNonceAndTag, err := gcm.Encrypt(plaintext, config.AAD)
	if err != nil {
		return fmt.Errorf("ошибка шифрования GCM: %v", err)
	}

	if len(ciphertextWithNonceAndTag) >= 12 {
		nonce := ciphertextWithNonceAndTag[:12]
		fmt.Printf("GCM encryption completed with nonce: %s\n", hex.EncodeToString(nonce))
	}

	if len(config.AAD) > 0 {
		fmt.Printf("AAD used: %s\n", hex.EncodeToString(config.AAD))
	}

	if err := WriteOutputFile(config.OutputFile, ciphertextWithNonceAndTag); err != nil {
		CleanupFailedOutput(config.OutputFile)
		return err
	}

	return nil
}

func executeDecryption(config *Config) error {
	if config.UseAEAD && config.Mode == "gcm" {
		return executeGCMDecryption(config)
	}

	if config.UseETM {
		return executeETMDecryption(config)
	}

	return executeRegularDecryption(config)
}

func executeRegularDecryption(config *Config) error {
	var ciphertext []byte
	var iv []byte

	if config.Mode == "ecb" {
		data, err := ReadInputFile(config.InputFile)
		if err != nil {
			return err
		}
		ciphertext = data
		iv = nil
	} else {
		// CBC, CFB, OFB, CTR
		if config.IV != nil {
			data, err := ReadInputFile(config.InputFile)
			if err != nil {
				return err
			}
			ciphertext = data
			iv = config.IV
		} else {
			var err error
			ciphertext, iv, err = ReadEncryptedFileWithIV(config.InputFile)
			if err != nil {
				return err
			}
		}
	}

	// Дешифрование в зависимости от режима
	switch config.Mode {
	case "ecb":
		plaintext, err := modes.ECBDecrypt(ciphertext, config.Key)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования ECB: %v", err)
		}
		return WriteOutputFile(config.OutputFile, plaintext)

	case "cbc":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err := modes.CBCDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования CBC: %v", err)
		}
		return WriteOutputFile(config.OutputFile, plaintext)

	case "cfb":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err := modes.CFBDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования CFB: %v", err)
		}
		return WriteOutputFile(config.OutputFile, plaintext)

	case "ofb":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err := modes.OFBDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования OFB: %v", err)
		}
		return WriteOutputFile(config.OutputFile, plaintext)

	case "ctr":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err := modes.CTRDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования CTR: %v", err)
		}
		return WriteOutputFile(config.OutputFile, plaintext)

	default:
		return fmt.Errorf("неподдерживаемый режим: %s", config.Mode)
	}
}

func executeETMDecryption(config *Config) error {
	if len(config.Key) != 48 {
		return fmt.Errorf("для Encrypt-then-MAC требуется ключ 48 байт, получено %d байт", len(config.Key))
	}

	data, err := ReadInputFile(config.InputFile)
	if err != nil {
		return err
	}

	if len(data) < 33 {
		return &FileIOError{
			Operation: "чтение",
			Path:      config.InputFile,
			Err:       fmt.Errorf("файл слишком короткий для Encrypt-then-MAC (требуется минимум 33 байта, получено %d)", len(data)),
		}
	}

	etm, err := aead.NewEncryptThenMac(config.Key, config.Mode)
	if err != nil {
		return fmt.Errorf("ошибка создания Encrypt-then-MAC: %v", err)
	}

	plaintext, err := etm.Decrypt(data, config.AAD)
	if err != nil {
		CleanupFailedOutput(config.OutputFile)
		return fmt.Errorf("ошибка аутентификации Encrypt-then-MAC: %v", err)
	}

	if err := WriteOutputFile(config.OutputFile, plaintext); err != nil {
		CleanupFailedOutput(config.OutputFile)
		return err
	}

	return nil
}

func executeGCMDecryption(config *Config) error {
	data, err := ReadInputFile(config.InputFile)
	if err != nil {
		return err
	}

	// nonce(12) + tag(16)
	if len(data) < 28 {
		return &FileIOError{
			Operation: "чтение",
			Path:      config.InputFile,
			Err:       fmt.Errorf("файл слишком короткий для GCM (требуется минимум 28 байт, получено %d)", len(data)),
		}
	}

	gcm, err := aead.NewGCM(config.Key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM: %v", err)
	}

	// Если указан nonce через --iv, нужно использовать его
	if config.IV != nil && len(config.IV) > 0 {
		if len(config.IV) != 12 {
			return fmt.Errorf("некорректная длина nonce: %d байт (должно быть 12 байт)", len(config.IV))
		}

		if len(data) < 16 {
			return fmt.Errorf("данные слишком короткие: %d байт (требуется минимум 16 для tag)", len(data))
		}

		gcmData := make([]byte, len(config.IV)+len(data))
		copy(gcmData[:12], config.IV)
		copy(gcmData[12:], data)
		data = gcmData

		fmt.Printf("Используется указанный nonce для дешифрования\n")
	}

	plaintext, err := gcm.Decrypt(data, config.AAD)
	if err != nil {
		CleanupFailedOutput(config.OutputFile)
		return fmt.Errorf("ошибка аутентификации GCM: %v", err)
	}

	if err := WriteOutputFile(config.OutputFile, plaintext); err != nil {
		CleanupFailedOutput(config.OutputFile)
		return err
	}

	return nil
}

func writeEncryptionOutput(config *Config, ciphertext []byte, iv []byte) error {
	if config.Mode == "ecb" {
		return WriteOutputFile(config.OutputFile, ciphertext)
	} else {
		finalOutput := make([]byte, len(iv)+len(ciphertext))
		copy(finalOutput[:16], iv)
		copy(finalOutput[16:], ciphertext)
		return WriteOutputFile(config.OutputFile, finalOutput)
	}
}

func executeHMACGeneration(config *Config) error {
	hmac, err := mac.NewHMAC(config.Key)
	if err != nil {
		return fmt.Errorf("ошибка создания HMAC: %v", err)
	}

	hmacValue, err := hmac.ComputeFromFile(config.InputFile)
	if err != nil {
		return fmt.Errorf("ошибка вычисления HMAC: %v", err)
	}

	// HMAC_VALUE INPUT_FILE_PATH
	hmacHex := hex.EncodeToString(hmacValue)
	output := hmacHex + "  " + config.InputFile

	if config.OutputFile != "" {
		if err := WriteHashToFile(hmacValue, config.InputFile, config.OutputFile); err != nil {
			return fmt.Errorf("ошибка записи HMAC в файл: %v", err)
		}
		fmt.Printf("HMAC written to: %s\n", config.OutputFile)
	} else {
		fmt.Println(output)
	}

	return nil
}

func executeHMACVerification(config *Config) error {
	hmac, err := mac.NewHMAC(config.Key)
	if err != nil {
		return fmt.Errorf("ошибка создания HMAC: %v", err)
	}

	hmacValue, err := hmac.ComputeFromFile(config.InputFile)
	if err != nil {
		return fmt.Errorf("ошибка вычисления HMAC: %v", err)
	}

	expectedHMAC, err := readExpectedHMAC(config.VerifyFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения ожидаемого HMAC: %v", err)
	}

	if subtle.ConstantTimeCompare(hmacValue, expectedHMAC) == 1 {
		fmt.Printf("[OK] HMAC verification successful\n")
		return nil
	} else {
		return fmt.Errorf("HMAC verification failed")
	}
}

func readExpectedHMAC(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, &FileIOError{
			Operation: "чтение",
			Path:      filename,
			Err:       err,
		}
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return nil, errors.New("файл HMAC пуст")
	}

	firstLine := strings.TrimSpace(lines[0])
	if firstLine == "" {
		return nil, errors.New("первая строка файла HMAC пуста")
	}

	parts := strings.Fields(firstLine)
	if len(parts) == 0 {
		return nil, errors.New("не удалось распарсить файл HMAC")
	}

	hmacHex := parts[0]

	if _, err := hex.DecodeString(hmacHex); err != nil {
		return nil, fmt.Errorf("некорректный формат HMAC в файле: %v", err)
	}

	if len(hmacHex) != 64 {
		return nil, fmt.Errorf("некорректная длина HMAC: %d символов (ожидалось 64 для SHA-256)", len(hmacHex))
	}

	return hex.DecodeString(hmacHex)
}
func ReadEncryptedFileWithIV(filePath string) ([]byte, []byte, error) {
	data, err := ReadInputFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	if len(data) < 16 {
		return nil, nil, &FileIOError{
			Operation: "чтение",
			Path:      filePath,
			Err:       fmt.Errorf("файл слишком короткий для извлечения IV (требуется минимум 16 байт, получено %d байт)", len(data)),
		}
	}

	iv := data[:16]
	ciphertext := data[16:]

	return ciphertext, iv, nil
}

func ReadEncryptedFileWithNonce(filePath string) ([]byte, []byte, []byte, error) {
	data, err := ReadInputFile(filePath)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(data) < 28 {
		return nil, nil, nil, &FileIOError{
			Operation: "чтение",
			Path:      filePath,
			Err:       fmt.Errorf("файл слишком короткий для GCM (требуется минимум 28 байт, получено %d байт)", len(data)),
		}
	}

	nonce := data[:12]
	tag := data[len(data)-16:]
	ciphertext := data[12 : len(data)-16]

	return ciphertext, nonce, tag, nil
}

func ReadInputFile(inputPath string) ([]byte, error) {
	fileInfo, err := os.Stat(inputPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &FileIOError{
				Operation: "проверка существования",
				Path:      inputPath,
				Err:       fmt.Errorf("файл не существует"),
			}
		}
		return nil, &FileIOError{
			Operation: "доступ",
			Path:      inputPath,
			Err:       err,
		}
	}

	if fileInfo.IsDir() {
		return nil, &FileIOError{
			Operation: "чтение",
			Path:      inputPath,
			Err:       fmt.Errorf("это директория, а не файл"),
		}
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, &FileIOError{
			Operation: "чтение содержимого",
			Path:      inputPath,
			Err:       err,
		}
	}

	return data, nil
}

// WriteOutputFile записывает данные в выходной файл с обработкой ошибок
func WriteOutputFile(outputPath string, data []byte) error {
	outputDir := filepath.Dir(outputPath)
	if outputDir != "." && outputDir != "" {
		dirInfo, err := os.Stat(outputDir)
		if err != nil {
			if os.IsNotExist(err) {
				if err := os.MkdirAll(outputDir, 0755); err != nil {
					return &FileIOError{
						Operation: "создание директории",
						Path:      outputDir,
						Err:       err,
					}
				}
			} else {
				return &FileIOError{
					Operation: "доступ к директории",
					Path:      outputDir,
					Err:       err,
				}
			}
		} else if !dirInfo.IsDir() {
			return &FileIOError{
				Operation: "запись",
				Path:      outputPath,
				Err:       fmt.Errorf("путь содержит файл вместо директории: %s", outputDir),
			}
		}
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return &FileIOError{
			Operation: "запись содержимого",
			Path:      outputPath,
			Err:       err,
		}
	}

	return nil
}

func WriteHashToFile(hashValue []byte, inputFile string, outputFile string) error {
	outputDir := filepath.Dir(outputFile)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return &FileIOError{
				Operation: "создание директории",
				Path:      outputDir,
				Err:       err,
			}
		}
	}

	hashOutput := hex.EncodeToString(hashValue) + "  " + inputFile + "\n"

	if err := os.WriteFile(outputFile, []byte(hashOutput), 0644); err != nil {
		return &FileIOError{
			Operation: "запись",
			Path:      outputFile,
			Err:       err,
		}
	}

	return nil
}

// CleanupFailedOutput удаляет выходной файл при ошибке аутентификации
func CleanupFailedOutput(outputPath string) {
	if outputPath != "" {
		if _, err := os.Stat(outputPath); err == nil {
			os.Remove(outputPath)
			fmt.Fprintf(os.Stderr, "Удален выходной файл из-за ошибки аутентификации: %s\n", outputPath)
		}
	}
}
