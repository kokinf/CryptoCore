package hash

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type HashAlgorithm string

const (
	SHA256   HashAlgorithm = "sha256"
	SHA3_256 HashAlgorithm = "sha3-256"
)

type Hasher interface {
	Update(data []byte)
	Finalize() []byte
	Reset()
	BlockSize() int
}

type HashResult struct {
	Algorithm HashAlgorithm
	Hash      []byte
	InputFile string
}

func (r *HashResult) String() string {
	return hex.EncodeToString(r.Hash) + "  " + r.InputFile
}

func ComputeHash(algorithm HashAlgorithm, inputFile string) (*HashResult, error) {
	hasher, err := NewHasher(algorithm)
	if err != nil {
		return nil, err
	}
	defer hasher.Reset()

	file, err := os.Open(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &FileIOError{
				Operation: "открытие",
				Path:      inputFile,
				Err:       fmt.Errorf("файл не существует"),
			}
		}
		return nil, &FileIOError{
			Operation: "открытие",
			Path:      inputFile,
			Err:       err,
		}
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, &FileIOError{
			Operation: "получение информации",
			Path:      inputFile,
			Err:       err,
		}
	}

	if fileInfo.IsDir() {
		return nil, &FileIOError{
			Operation: "чтение",
			Path:      inputFile,
			Err:       fmt.Errorf("это директория, а не файл"),
		}
	}

	buffer := make([]byte, 8192)
	totalRead := 0

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			hasher.Update(buffer[:n])
			totalRead += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &FileIOError{
				Operation: "чтение",
				Path:      inputFile,
				Err:       err,
			}
		}
	}

	if totalRead == 0 {
		hasher.Update([]byte{})
	}

	return &HashResult{
		Algorithm: algorithm,
		Hash:      hasher.Finalize(),
		InputFile: inputFile,
	}, nil
}

func ComputeHashFromReader(algorithm HashAlgorithm, reader io.Reader) ([]byte, error) {
	hasher, err := NewHasher(algorithm)
	if err != nil {
		return nil, err
	}
	defer hasher.Reset()

	buffer := make([]byte, 8192)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			hasher.Update(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return hasher.Finalize(), nil
}

func NewHasher(algorithm HashAlgorithm) (Hasher, error) {
	switch algorithm {
	case SHA256:
		return NewSHA256(), nil
	case SHA3_256:
		return NewSHA3_256(), nil
	default:
		return nil, &UnsupportedAlgorithmError{Algorithm: string(algorithm)}
	}
}

type UnsupportedAlgorithmError struct {
	Algorithm string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return "неподдерживаемый алгоритм хеширования: " + e.Algorithm
}

type FileIOError struct {
	Operation string
	Path      string
	Err       error
}

func (e *FileIOError) Error() string {
	return fmt.Sprintf("ошибка ввода-вывода при %s файла '%s': %v", e.Operation, e.Path, e.Err)
}
