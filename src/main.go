package main

import (
	"cryptocore/src/hash"
	"fmt"
	"os"
)

func main() {
	config, err := ParseCLI(os.Args[1:])
	if err != nil {
		printErrorAndExit(err)
	}

	switch config.Command {
	case "dgst":
		if err := ExecuteHashOperation(config); err != nil {
			printErrorAndExit(err)
		}
	default: // encrypt или decrypt
		if err := ExecuteCryptoOperation(config); err != nil {
			printErrorAndExit(err)
		}

		fmt.Printf("Operation completed successfully: %s -> %s\n",
			config.InputFile, config.OutputFile)
	}
}

func ExecuteHashOperation(config *Config) error {
	if config.UseHMAC {
		return ExecuteMACOperation(config)
	} else {
		result, err := hash.ComputeHash(config.HashAlgorithm, config.InputFile)
		if err != nil {
			return fmt.Errorf("ошибка вычисления хеша: %v", err)
		}

		hashOutput := result.String()

		if config.OutputFile != "" {
			if err := WriteHashToFile(result.Hash, config.InputFile, config.OutputFile); err != nil {
				return fmt.Errorf("ошибка записи хеша в файл: %v", err)
			}
			fmt.Printf("Hash written to: %s\n", config.OutputFile)
		} else {
			fmt.Println(hashOutput)
		}

		return nil
	}
}

func printErrorAndExit(err error) {
	exitCode := 1

	switch err.(type) {
	case *FileIOError:
		exitCode = 2
	case *hash.UnsupportedAlgorithmError:
		exitCode = 3
	case *hash.FileIOError:
		exitCode = 4
	}

	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(exitCode)
}
