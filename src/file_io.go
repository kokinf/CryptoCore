package main

import (
	ecb "cryptocore/src/modes"
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
	return fmt.Sprintf("file I/O error during %s on '%s': %v", e.Operation, e.Path, e.Err)
}

func ExecuteCryptoOperation(config *Config) error {
	inputData, err := ReadInputFile(config.InputFile)
	if err != nil {
		return err
	}

	var outputData []byte

	if config.Encrypt {
		outputData, err = ecb.ECBEncrypt(inputData, config.Key)
		if err != nil {
			return fmt.Errorf("encryption failed: %v", err)
		}
	} else {
		outputData, err = ecb.ECBDecrypt(inputData, config.Key)
		if err != nil {
			return fmt.Errorf("decryption failed: %v", err)
		}
	}

	if err := WriteOutputFile(config.OutputFile, outputData); err != nil {
		return err
	}

	return nil
}

func ReadInputFile(inputPath string) ([]byte, error) {
	fileInfo, err := os.Stat(inputPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &FileIOError{
				Operation: "check existence",
				Path:      inputPath,
				Err:       fmt.Errorf("file does not exist"),
			}
		}
		return nil, &FileIOError{
			Operation: "access",
			Path:      inputPath,
			Err:       err,
		}
	}

	if fileInfo.IsDir() {
		return nil, &FileIOError{
			Operation: "read",
			Path:      inputPath,
			Err:       fmt.Errorf("is a directory, not a file"),
		}
	}

	file, err := os.Open(inputPath)
	if err != nil {
		return nil, &FileIOError{
			Operation: "open for reading",
			Path:      inputPath,
			Err:       err,
		}
	}
	defer file.Close()

	if fileInfo.Mode().Perm()&0400 == 0 {
		return nil, &FileIOError{
			Operation: "read",
			Path:      inputPath,
			Err:       fmt.Errorf("insufficient read permissions"),
		}
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, &FileIOError{
			Operation: "read content",
			Path:      inputPath,
			Err:       err,
		}
	}

	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: Input file '%s' is empty\n", inputPath)
	}

	return data, nil
}

func WriteOutputFile(outputPath string, data []byte) error {
	outputDir := filepath.Dir(outputPath)
	if outputDir != "." && outputDir != "" {
		dirInfo, err := os.Stat(outputDir)
		if err != nil {
			if os.IsNotExist(err) {
				return &FileIOError{
					Operation: "write",
					Path:      outputPath,
					Err:       fmt.Errorf("output directory does not exist: %s", outputDir),
				}
			}
			return &FileIOError{
				Operation: "access output directory",
				Path:      outputDir,
				Err:       err,
			}
		}

		if !dirInfo.IsDir() {
			return &FileIOError{
				Operation: "write",
				Path:      outputPath,
				Err:       fmt.Errorf("output path contains a file where directory should be: %s", outputDir),
			}
		}

		tempFile, err := os.CreateTemp(outputDir, ".cryptocore_write_test_")
		if err != nil {
			return &FileIOError{
				Operation: "write",
				Path:      outputPath,
				Err:       fmt.Errorf("output directory is not writable: %s", outputDir),
			}
		}
		tempFile.Close()
		os.Remove(tempFile.Name())
	}

	if _, err := os.Stat(outputPath); err == nil {
		file, err := os.OpenFile(outputPath, os.O_WRONLY, 0644)
		if err != nil {
			return &FileIOError{
				Operation: "write",
				Path:      outputPath,
				Err:       fmt.Errorf("output file exists but is not writable"),
			}
		}
		file.Close()

		fmt.Fprintf(os.Stderr, "Warning: Output file '%s' already exists and will be overwritten\n", outputPath)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return &FileIOError{
			Operation: "write content",
			Path:      outputPath,
			Err:       err,
		}
	}

	if err := verifyFileWrite(outputPath, data); err != nil {
		os.Remove(outputPath)
		return &FileIOError{
			Operation: "verify write",
			Path:      outputPath,
			Err:       fmt.Errorf("file write verification failed: %v", err),
		}
	}

	return nil
}

func verifyFileWrite(filePath string, originalData []byte) error {
	writtenData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if len(writtenData) != len(originalData) {
		return fmt.Errorf("size mismatch: wrote %d bytes but file contains %d bytes",
			len(originalData), len(writtenData))
	}

	for i := range originalData {
		if writtenData[i] != originalData[i] {
			return fmt.Errorf("data corruption detected at byte %d", i)
		}
	}

	return nil
}

func SafeFileOperation(operation func() error, operationName, filePath string) error {
	if err := operation(); err != nil {
		return &FileIOError{
			Operation: operationName,
			Path:      filePath,
			Err:       err,
		}
	}
	return nil
}
