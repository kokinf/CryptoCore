package main

import (
	"cryptocore/src/hash"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Algorithm     string
	Mode          string
	Encrypt       bool
	Decrypt       bool
	Key           []byte
	KeyStr        string
	InputFile     string
	OutputFile    string
	IV            []byte
	IVStr         string
	Command       string // encrypt, decrypt, или dgst
	HashAlgorithm hash.HashAlgorithm
	UseHMAC       bool
	VerifyFile    string
	AAD           []byte
	AADStr        string
	UseAEAD       bool
	UseETM        bool
}

func ParseCLI(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, errors.New("не указаны аргументы. Используйте --help для справки")
	}

	var command string
	var remainingArgs []string

	if args[0] == "dgst" {
		command = "dgst"
		remainingArgs = args[1:]
	} else if strings.HasPrefix(args[0], "-") {
		command = "encrypt"
		remainingArgs = args
	} else {
		return nil, fmt.Errorf("неизвестная подкоманда: %s. Поддерживаются: dgst", args[0])
	}

	if command == "dgst" {
		return parseDgstCommand(remainingArgs)
	} else {
		return parseCryptoCommand(remainingArgs)
	}
}

func parseDgstCommand(args []string) (*Config, error) {
	var config Config
	config.Command = "dgst"

	flagSet := flag.NewFlagSet("cryptocore dgst", flag.ContinueOnError)

	var algorithmStr string
	flagSet.StringVar(&algorithmStr, "algorithm", "", "Алгоритм хеширования (sha256, sha3-256)")
	flagSet.StringVar(&config.InputFile, "input", "", "Путь к входному файлу")
	flagSet.StringVar(&config.OutputFile, "output", "", "Путь к выходному файлу (опционально)")
	flagSet.BoolVar(&config.UseHMAC, "hmac", false, "Использовать HMAC (требует --key)")
	flagSet.StringVar(&config.KeyStr, "key", "", "Ключ для HMAC в hex-формате")
	flagSet.StringVar(&config.VerifyFile, "verify", "", "Файл с ожидаемым HMAC для проверки")

	if err := flagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("ошибка парсинга аргументов: %v", err)
	}

	if err := validateDgstConfig(&config, algorithmStr); err != nil {
		return nil, err
	}

	return &config, nil
}

func parseCryptoCommand(args []string) (*Config, error) {
	var config Config
	config.Command = "encrypt"

	flagSet := flag.NewFlagSet("cryptocore", flag.ContinueOnError)
	flagSet.SetOutput(os.Stderr)

	flagSet.StringVar(&config.Algorithm, "algorithm", "", "Алгоритм шифрования (aes)")
	flagSet.StringVar(&config.Mode, "mode", "", "Режим работы (ecb, cbc, cfb, ofb, ctr, gcm)")
	flagSet.BoolVar(&config.Encrypt, "encrypt", false, "Выполнить шифрование")
	flagSet.BoolVar(&config.Decrypt, "decrypt", false, "Выполнить дешифрование")
	flagSet.StringVar(&config.KeyStr, "key", "", "Ключ шифрования в hex-формате (опционально для шифрования)")
	flagSet.StringVar(&config.InputFile, "input", "", "Путь к входному файлу")
	flagSet.StringVar(&config.OutputFile, "output", "", "Путь к выходному файлу")
	flagSet.StringVar(&config.IVStr, "iv", "", "Вектор инициализации в hex-формате (для дешифрования)")
	flagSet.StringVar(&config.AADStr, "aad", "", "Дополнительные аутентифицированные данные в hex-формате (для AEAD режимов)")

	if err := flagSet.Parse(args); err != nil {
		if strings.Contains(err.Error(), "flag needs an argument") && strings.Contains(err.Error(), "-aad") {
			return parseCryptoCommandManual(args)
		}
		return nil, fmt.Errorf("ошибка парсинга аргументов: %v", err)
	}

	config.UseAEAD = isAEADMode(config.Mode)

	if config.KeyStr != "" {
		key, err := hex.DecodeString(config.KeyStr)
		if err == nil {
			if len(key) == 48 && config.Mode != "gcm" {
				config.UseETM = true
			}
		}
	}

	if err := validateCryptoConfig(&config); err != nil {
		return nil, err
	}

	if config.OutputFile == "" {
		config.OutputFile = deriveOutputFilename(config.InputFile, config.Encrypt, config.Mode)
	}

	if err := validateIVLogic(&config); err != nil {
		return nil, err
	}

	if err := validateAAD(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func parseCryptoCommandManual(args []string) (*Config, error) {
	var config Config
	config.Command = "encrypt"

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--algorithm":
			if i+1 < len(args) {
				config.Algorithm = args[i+1]
				i++
			}
		case "--mode":
			if i+1 < len(args) {
				config.Mode = args[i+1]
				i++
			}
		case "--encrypt":
			config.Encrypt = true
		case "--decrypt":
			config.Decrypt = true
		case "--key":
			if i+1 < len(args) {
				config.KeyStr = args[i+1]
				i++
			}
		case "--input":
			if i+1 < len(args) {
				config.InputFile = args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(args) {
				config.OutputFile = args[i+1]
				i++
			}
		case "--iv":
			if i+1 < len(args) {
				config.IVStr = args[i+1]
				i++
			}
		case "--aad":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				config.AADStr = args[i+1]
				i++
			} else {
				config.AADStr = ""
			}
		}
	}

	config.UseAEAD = isAEADMode(config.Mode)

	if config.KeyStr != "" {
		key, err := hex.DecodeString(config.KeyStr)
		if err == nil {
			if len(key) == 48 && config.Mode != "gcm" {
				config.UseETM = true
				fmt.Fprintf(os.Stderr, "Используется Encrypt-then-MAC режим\n")
			}
		}
	}

	if err := validateCryptoConfig(&config); err != nil {
		return nil, err
	}

	if config.OutputFile == "" {
		config.OutputFile = deriveOutputFilename(config.InputFile, config.Encrypt, config.Mode)
	}

	if err := validateIVLogic(&config); err != nil {
		return nil, err
	}

	if err := validateAAD(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func isAEADMode(mode string) bool {
	aeadModes := map[string]bool{
		"gcm": true,
	}
	return aeadModes[mode]
}

func validateDgstConfig(config *Config, algorithmStr string) error {
	if algorithmStr == "" {
		return errors.New("аргумент --algorithm обязателен для подкоманды dgst")
	}

	switch algorithmStr {
	case "sha256":
		config.HashAlgorithm = hash.SHA256
	case "sha3-256":
		config.HashAlgorithm = hash.SHA3_256
	default:
		return fmt.Errorf("неподдерживаемый алгоритм хеширования: %s (поддерживаются: sha256, sha3-256)", algorithmStr)
	}

	if config.InputFile == "" {
		return errors.New("аргумент --input обязателен")
	}
	if _, err := os.Stat(config.InputFile); os.IsNotExist(err) {
		return fmt.Errorf("входной файл не существует: %s", config.InputFile)
	}

	if config.UseHMAC {
		if config.KeyStr == "" {
			return errors.New("аргумент --key обязателен при использовании --hmac")
		}

		key, err := hex.DecodeString(config.KeyStr)
		if err != nil {
			return fmt.Errorf("некорректный формат ключа: %v (должен быть hex-строка)", err)
		}
		config.Key = key

		if algorithmStr != "sha256" {
			return errors.New("HMAC поддерживается только с алгоритмом sha256")
		}
	}

	if config.VerifyFile != "" && !config.UseHMAC {
		return errors.New("--verify может использоваться только с --hmac")
	}

	return nil
}

func validateCryptoConfig(config *Config) error {
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
		"gcm": true,
	}
	if !supportedModes[config.Mode] {
		return fmt.Errorf("неподдерживаемый режим: %s (поддерживаются: ecb, cbc, cfb, ofb, ctr, gcm)", config.Mode)
	}

	if config.Encrypt && config.Decrypt {
		return errors.New("нельзя указывать одновременно --encrypt и --decrypt")
	}
	if !config.Encrypt && !config.Decrypt {
		if config.KeyStr != "" {
			return errors.New("необходимо указать либо --encrypt, либо --decrypt")
		}
		config.Encrypt = true
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

		if config.Mode == "gcm" {
			if len(key) != 16 && len(key) != 24 && len(key) != 32 {
				return fmt.Errorf("некорректная длина ключа для GCM: %d байт (должно быть 16, 24 или 32 байта)", len(key))
			}
		} else {
			if len(key) != 16 && len(key) != 48 {
				return fmt.Errorf("некорректная длина ключа: %d байт (должно быть 16 байт для AES-128 или 48 байт для Encrypt-then-MAC)", len(key))
			}

			if len(key) == 48 {
				config.UseETM = true
			}
		}

		config.Key = key

		if isWeakKey(key) {
			fmt.Fprintf(os.Stderr, "Предупреждение: обнаружен потенциально слабый ключ\n")
		}
	}

	if config.InputFile == "" {
		return errors.New("аргумент --input обязателен")
	}

	if config.Encrypt && config.Key == nil {
	} else if _, err := os.Stat(config.InputFile); os.IsNotExist(err) {
		return fmt.Errorf("входной файл не существует: %s", config.InputFile)
	}

	return nil
}

func validateIVLogic(config *Config) error {
	if config.Encrypt {
		if config.Mode == "gcm" {
			if config.IVStr != "" {
				iv, err := hex.DecodeString(config.IVStr)
				if err != nil {
					return fmt.Errorf("некорректный формат IV/nonce: %v (должен быть hex-строка)", err)
				}

				if len(iv) != 12 {
					return fmt.Errorf("некорректная длина nonce для GCM: %d байт (должно быть 12 байт)", len(iv))
				}

				config.IV = iv
				fmt.Fprintf(os.Stderr, "Используется указанный nonce: %s\n", config.IVStr)
			} else {
				fmt.Fprintf(os.Stderr, "Nonce не указан, будет сгенерирован случайный 12-байтный nonce\n")
			}
		} else if config.IVStr != "" {
			fmt.Fprintf(os.Stderr, "Предупреждение: --iv игнорируется при шифровании (IV генерируется автоматически)\n")
		}
	} else if config.Decrypt {
		if config.Mode == "ecb" {
			if config.IVStr != "" {
				fmt.Fprintf(os.Stderr, "Предупреждение: --iv игнорируется для режима ECB\n")
			}
		} else if config.Mode == "gcm" {
			if config.IVStr != "" {
				iv, err := hex.DecodeString(config.IVStr)
				if err != nil {
					return fmt.Errorf("некорректный формат IV/nonce: %v (должен быть hex-строка)", err)
				}

				if len(iv) != 12 {
					return fmt.Errorf("некорректная длина nonce для GCM: %d байт (должно быть 12 байт)", len(iv))
				}

				config.IV = iv
				fmt.Fprintf(os.Stderr, "Используется указанный nonce\n")
			} else {
				fmt.Fprintf(os.Stderr, "Nonce не указан, будет прочитан из начала файла %s\n", config.InputFile)
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

func validateAAD(config *Config) error {
	if config.AADStr != "" {
		if config.AADStr == `""` || config.AADStr == "''" || config.AADStr == "00" {
			config.AAD = []byte{}
		} else {
			aad, err := hex.DecodeString(config.AADStr)
			if err != nil {
				return fmt.Errorf("некорректный формат AAD: %v (должен быть hex-строка)", err)
			}
			config.AAD = aad
		}

		if !config.UseAEAD && !config.UseETM {
			fmt.Fprintf(os.Stderr, "Предупреждение: AAD игнорируется для не-AEAD режима %s\n", config.Mode)
		}
	} else if config.UseAEAD || config.UseETM {
		config.AAD = []byte{}
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

// deriveOutputFilename автоматическая генерация выходного файла, если он не указан
func deriveOutputFilename(inputFile string, encrypt bool, mode string) string {
	base := filepath.Base(inputFile)
	ext := filepath.Ext(inputFile)
	name := strings.TrimSuffix(base, ext)

	if encrypt {
		switch mode {
		case "gcm":
			return fmt.Sprintf("%s_%s.aead", name, mode)
		default:
			if mode != "ecb" {
				return fmt.Sprintf("%s_%s.enc", name, mode)
			}
			return name + ".enc"
		}
	} else {
		if strings.HasSuffix(base, ".enc") || strings.HasSuffix(base, ".aead") || strings.HasSuffix(base, ".etm") {
			base = strings.TrimSuffix(base, ".enc")
			base = strings.TrimSuffix(base, ".aead")
			base = strings.TrimSuffix(base, ".etm")
			ext = filepath.Ext(base)
			name = strings.TrimSuffix(base, ext)

			modeSuffixes := []string{"_ecb", "_cbc", "_cfb", "_ofb", "_ctr", "_gcm"}
			for _, suffix := range modeSuffixes {
				if strings.HasSuffix(name, suffix) {
					name = strings.TrimSuffix(name, suffix)
					break
				}
			}

			return name + ".dec" + ext
		} else {
			return name + ".dec" + ext
		}
	}
}
