package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
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
}

func ParseCLI(args []string) (*Config, error) {
	var config Config

	flagSet := flag.NewFlagSet("cryptocore", flag.ContinueOnError)
	flagSet.StringVar(&config.Algorithm, "algorithm", "", "Cipher algorithm (aes)")
	flagSet.StringVar(&config.Mode, "mode", "", "Mode of operation (ecb)")
	flagSet.BoolVar(&config.Encrypt, "encrypt", false, "Perform encryption")
	flagSet.BoolVar(&config.Decrypt, "decrypt", false, "Perform decryption")
	flagSet.StringVar(&config.KeyStr, "key", "", "Encryption key as hexadecimal string")
	flagSet.StringVar(&config.InputFile, "input", "", "Input file path")
	flagSet.StringVar(&config.OutputFile, "output", "", "Output file path")

	if err := flagSet.Parse(args); err != nil {
		return nil, err
	}

	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	if config.OutputFile == "" {
		config.OutputFile = deriveOutputFilename(config.InputFile, config.Encrypt)
	}

	return &config, nil
}

func validateConfig(config *Config) error {
	if config.Algorithm == "" {
		return errors.New("--algorithm argument is required")
	}
	if config.Algorithm != "aes" {
		return fmt.Errorf("unsupported algorithm: %s (only 'aes' is supported)", config.Algorithm)
	}

	if config.Mode == "" {
		return errors.New("--mode argument is required")
	}
	if config.Mode != "ecb" {
		return fmt.Errorf("unsupported mode: %s (only 'ecb' is supported)", config.Mode)
	}

	if config.Encrypt && config.Decrypt {
		return errors.New("cannot specify both --encrypt and --decrypt")
	}
	if !config.Encrypt && !config.Decrypt {
		return errors.New("must specify either --encrypt or --decrypt")
	}

	if config.KeyStr == "" {
		return errors.New("--key argument is required")
	}
	key, err := hex.DecodeString(config.KeyStr)
	if err != nil {
		return fmt.Errorf("invalid key format: %v (must be hexadecimal string)", err)
	}
	if len(key) != 16 {
		return fmt.Errorf("invalid key length: %d bytes (must be 16 bytes for AES-128)", len(key))
	}
	config.Key = key

	if config.InputFile == "" {
		return errors.New("--input argument is required")
	}

	return nil
}

func deriveOutputFilename(inputFile string, encrypt bool) string {
	base := filepath.Base(inputFile)
	ext := filepath.Ext(inputFile)
	name := strings.TrimSuffix(base, ext)

	if encrypt {
		return name + ext + ".enc"
	} else {
		if strings.HasSuffix(base, ".enc") {
			base = strings.TrimSuffix(base, ".enc")
			ext = filepath.Ext(base)
			name = strings.TrimSuffix(base, ext)
		}
		return name + ".dec" + ext
	}
}
