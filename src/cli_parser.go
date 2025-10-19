package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Algorithm  string
	Mode       string
	Encrypt    bool
	Decrypt    bool
	Key        []byte
	KeyStr     string
	InputFile  string
	OutputFile string
	IV         []byte
	IVStr      string
}

func ParseCLI(args []string) (*Config, error) {
	var config Config

	flagSet := flag.NewFlagSet("cryptocore", flag.ContinueOnError)

	flagSet.StringVar(&config.Algorithm, "algorithm", "", "Алгоритм шифрования (aes)")
	flagSet.StringVar(&config.Mode, "mode", "", "Режим работы (ecb, cbc, cfb, ofb, ctr)")
	flagSet.BoolVar(&config.Encrypt, "encrypt", false, "Выполнить шифрование")
	flagSet.BoolVar(&config.Decrypt, "decrypt", false, "Выполнить дешифрование")
	flagSet.StringVar(&config.KeyStr, "key", "", "Ключ шифрования в hex-формате (опционально для шифрования)")
	flagSet.StringVar(&config.InputFile, "input", "", "Путь к входному файлу")
	flagSet.StringVar(&config.OutputFile, "output", "", "Путь к выходному файлу")
	flagSet.StringVar(&config.IVStr, "iv", "", "Вектор инициализации в hex-формате (только для дешифрования)")

	if err := flagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("ошибка парсинга аргументов: %v", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	if config.OutputFile == "" {
		config.OutputFile = deriveOutputFilename(config.InputFile, config.Encrypt, config.Mode)
	}

	if err := validateIVLogic(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func validateConfig(config *Config) error {
	if config.Algorithm == "" {
		return errors.New("аргумент --algorithm обязателен")
	}
	if config.Algorithm != "aes" {
		return fmt.Errorf("неподдерживаемый алгоритм: %s (поддерживается только 'aes')", config.Algorithm)
	}

	if config.Mode == "" {
		return errors.New("аргумент --mode обязателен")
	}

	supportedModes := map[string]bool{
		"ecb": true,
		"cbc": true,
		"cfb": true,
		"ofb": true,
		"ctr": true,
	}
	if !supportedModes[config.Mode] {
		return fmt.Errorf("неподдерживаемый режим: %s (поддерживаются: ecb, cbc, cfb, ofb, ctr)", config.Mode)
	}

	if config.Encrypt && config.Decrypt {
		return errors.New("нельзя указывать одновременно --encrypt и --decrypt")
	}
	if !config.Encrypt && !config.Decrypt {
		return errors.New("необходимо указать либо --encrypt, либо --decrypt")
	}

	if config.KeyStr == "" {
		if config.Decrypt {
			return errors.New("аргумент --key обязателен для дешифрования")
		}
		fmt.Fprintf(os.Stderr, "Ключ не указан, будет сгенерирован автоматически\n")
	} else {
		key, err := hex.DecodeString(config.KeyStr)
		if err != nil {
			return fmt.Errorf("некорректный формат ключа: %v (должен быть hex-строка)", err)
		}
		if len(key) != 16 {
			return fmt.Errorf("некорректная длина ключа: %d байт (должно быть 16 байт для AES-128)", len(key))
		}
		config.Key = key

		if isWeakKey(key) {
			fmt.Fprintf(os.Stderr, "Предупреждение: обнаружен потенциально слабый ключ\n")
		}
	}

	if config.InputFile == "" {
		return errors.New("аргумент --input обязателен")
	}
	if _, err := os.Stat(config.InputFile); os.IsNotExist(err) {
		return fmt.Errorf("входной файл не существует: %s", config.InputFile)
	}

	return nil
}

func isWeakKey(key []byte) bool {
	if len(key) == 0 {
		return false
	}

	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}

	sequentialUp := true
	for i := 1; i < len(key); i++ {
		if key[i] != key[i-1]+1 {
			sequentialUp = false
			break
		}
	}
	if sequentialUp {
		return true
	}

	sequentialDown := true
	for i := 1; i < len(key); i++ {
		if key[i] != key[i-1]-1 {
			sequentialDown = false
			break
		}
	}
	if sequentialDown {
		return true
	}

	allSame := true
	first := key[0]
	for _, b := range key {
		if b != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	if hasRepeatingPattern(key) {
		return true
	}

	return false
}

func hasRepeatingPattern(key []byte) bool {
	if len(key) < 4 {
		return false
	}

	for patternLen := 2; patternLen <= len(key)/2; patternLen *= 2 {
		if len(key)%patternLen != 0 {
			continue
		}

		isRepeating := true
		pattern := key[:patternLen]
		for i := patternLen; i < len(key); i += patternLen {
			for j := 0; j < patternLen; j++ {
				if key[i+j] != pattern[j] {
					isRepeating = false
					break
				}
			}
			if !isRepeating {
				break
			}
		}
		if isRepeating {
			return true
		}
	}

	return false
}

func validateIVLogic(config *Config) error {
	if config.Encrypt {
		if config.IVStr != "" {
			fmt.Fprintf(os.Stderr, "Предупреждение: --iv игнорируется при шифровании (IV генерируется автоматически)\n")
		}
	} else if config.Decrypt {
		if config.Mode == "ecb" {
			if config.IVStr != "" {
				fmt.Fprintf(os.Stderr, "Предупреждение: --iv игнорируется для режима ECB\n")
			}
		} else {
			if config.IVStr == "" {
				fmt.Fprintf(os.Stderr, "IV не указан, будет прочитан из начала файла %s\n", config.InputFile)
			} else {
				iv, err := hex.DecodeString(config.IVStr)
				if err != nil {
					return fmt.Errorf("некорректный формат IV: %v (должен быть hex-строка)", err)
				}

				if len(iv) != 16 {
					return fmt.Errorf("некорректная длина IV: %d байт (должно быть 16 байт)", len(iv))
				}

				config.IV = iv
				fmt.Fprintf(os.Stderr, "Используется указанный IV\n")
			}
		}
	}

	return nil
}

// deriveOutputFilename автоматическая генерация выходного файла, если он не указан
func deriveOutputFilename(inputFile string, encrypt bool, mode string) string {
	base := filepath.Base(inputFile)
	ext := filepath.Ext(inputFile)
	name := strings.TrimSuffix(base, ext)

	if encrypt {
		if mode != "ecb" {
			return fmt.Sprintf("%s_%s.enc", name, mode)
		}
		return name + ".enc"
	} else {
		if strings.HasSuffix(base, ".enc") {
			base = strings.TrimSuffix(base, ".enc")
			ext = filepath.Ext(base)
			name = strings.TrimSuffix(base, ext)

			if strings.HasSuffix(name, "_ecb") || strings.HasSuffix(name, "_cbc") || strings.HasSuffix(name, "_cfb") || strings.HasSuffix(name, "_ofb") ||
				strings.HasSuffix(name, "_ctr") {
				name = strings.TrimSuffix(name, "_"+mode)
			}

			return name + ".dec" + ext
		} else {
			return name + ".dec" + ext
		}
	}
}
