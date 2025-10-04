package main

import (
	"fmt"
	"os"
)

func main() {
	config, err := ParseCLI(os.Args[1:])
	if err != nil {
		printErrorAndExit(err)
	}

	if err := ExecuteCryptoOperation(config); err != nil {
		printErrorAndExit(err)
	}

	fmt.Printf("Operation completed successfully: %s -> %s\n",
		config.InputFile, config.OutputFile)
}

func printErrorAndExit(err error) {
	exitCode := 1

	switch err.(type) {
	case *FileIOError:
		exitCode = 2
	}

	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(exitCode)
}
