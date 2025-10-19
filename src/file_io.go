package main

import (
	"cryptocore/src/modes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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

func generateRandomIV() ([]byte, error) {
	return GenerateRandomBytes(16)
}

func executeEncryption(config *Config) error {
	if config.Key == nil {
		generatedKey, err := GenerateRandomBytes(16)
		if err != nil {
			return fmt.Errorf("ошибка генерации ключа: %v", err)
		}
		config.Key = generatedKey

		fmt.Printf("Сгенерированный ключ: %s\n", hex.EncodeToString(config.Key))
	}

	plaintext, err := ReadInputFile(config.InputFile)
	if err != nil {
		return err
	}

	var ciphertext []byte
	var iv []byte

	// Шифрование
	switch config.Mode {
	case "ecb":
		ciphertext, err = modes.ECBEncrypt(plaintext, config.Key)
		if err != nil {
			return fmt.Errorf("ошибка шифрования ECB: %v", err)
		}

	case "cbc":
		iv, err = generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для CBC: %v", err)
		}
		ciphertext, err = modes.CBCEncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования CBC: %v", err)
		}

	case "cfb":
		iv, err = generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для CFB: %v", err)
		}
		ciphertext, err = modes.CFBEncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования CFB: %v", err)
		}

	case "ofb":
		iv, err = generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для OFB: %v", err)
		}
		ciphertext, err = modes.OFBEncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования OFB: %v", err)
		}

	case "ctr":
		iv, err = generateRandomIV()
		if err != nil {
			return fmt.Errorf("ошибка генерации IV для CTR: %v", err)
		}
		ciphertext, err = modes.CTREncryptWithIV(plaintext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка шифрования CTR: %v", err)
		}

	default:
		return fmt.Errorf("неподдерживаемый режим: %s", config.Mode)
	}

	if err := writeEncryptionOutput(config, ciphertext, iv); err != nil {
		return err
	}

	return nil
}

func executeDecryption(config *Config) error {
	var ciphertext []byte
	var iv []byte
	var err error

	if config.Mode == "ecb" {
		ciphertext, err = ReadInputFile(config.InputFile)
		if err != nil {
			return err
		}
		iv = nil
	} else {
		if config.IV != nil {
			ciphertext, err = ReadInputFile(config.InputFile)
			if err != nil {
				return err
			}
			iv = config.IV
		} else {
			ciphertext, iv, err = ReadEncryptedFileWithIV(config.InputFile)
			if err != nil {
				return err
			}
		}
	}

	var plaintext []byte

	// Дешифрования
	switch config.Mode {
	case "ecb":
		plaintext, err = modes.ECBDecrypt(ciphertext, config.Key)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования ECB: %v", err)
		}

	case "cbc":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err = modes.CBCDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования CBC: %v", err)
		}

	case "cfb":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err = modes.CFBDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования CFB: %v", err)
		}

	case "ofb":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err = modes.OFBDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования OFB: %v", err)
		}

	case "ctr":
		if len(iv) != 16 {
			return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
		}
		plaintext, err = modes.CTRDecrypt(ciphertext, config.Key, iv)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования CTR: %v", err)
		}

	default:
		return fmt.Errorf("неподдерживаемый режим: %s", config.Mode)
	}

	if err := WriteOutputFile(config.OutputFile, plaintext); err != nil {
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
				return &FileIOError{
					Operation: "запись",
					Path:      outputPath,
					Err:       fmt.Errorf("директория не существует: %s", outputDir),
				}
			}
			return &FileIOError{
				Operation: "доступ к директории",
				Path:      outputDir,
				Err:       err,
			}
		}

		if !dirInfo.IsDir() {
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
