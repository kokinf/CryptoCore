package tests

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelper предоставляет вспомогательные методы для тестов
type TestHelper struct {
	t *testing.T
}

func NewTestHelper(t *testing.T) *TestHelper {
	return &TestHelper{t: t}
}

// CompareBytes сравнивает два байтовых массива с безопасным сравнением по времени
func (th *TestHelper) CompareBytes(expected, actual []byte) bool {
	th.t.Helper()

	if len(expected) != len(actual) {
		th.t.Logf("Length mismatch: expected %d, got %d", len(expected), len(actual))
		return false
	}

	if subtle.ConstantTimeCompare(expected, actual) != 1 {
		return false
	}

	return true
}

// HexDecode декодирует hex строку, паникует при ошибке
func (th *TestHelper) HexDecode(s string) []byte {
	th.t.Helper()

	data, err := hex.DecodeString(s)
	if err != nil {
		th.t.Fatalf("Failed to decode hex string %q: %v", s, err)
	}
	return data
}

// HexDecodeToString декодирует hex и возвращает строку для вывода
func (th *TestHelper) HexDecodeToString(data []byte) string {
	return hex.EncodeToString(data)
}

// ReadTestFile читает тестовый файл
func (th *TestHelper) ReadTestFile(filename string) []byte {
	th.t.Helper()

	data, err := os.ReadFile(filename)
	if err != nil {
		th.t.Fatalf("Failed to read test file %s: %v", filename, err)
	}
	return data
}

// WriteTestFile записывает тестовый файл
func (th *TestHelper) WriteTestFile(filename string, data []byte) {
	th.t.Helper()

	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			th.t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		th.t.Fatalf("Failed to write test file %s: %v", filename, err)
	}
}

// CreateTempFile создает временный файл
func (th *TestHelper) CreateTempFile(data []byte) string {
	th.t.Helper()

	tmpfile, err := os.CreateTemp("", "cryptocore_test_*.tmp")
	if err != nil {
		th.t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()

	if _, err := tmpfile.Write(data); err != nil {
		th.t.Fatalf("Failed to write to temp file: %v", err)
	}

	return tmpfile.Name()
}

// CleanupTempFile удаляет временный файл
func (th *TestHelper) CleanupTempFile(filename string) {
	if filename != "" {
		os.Remove(filename)
	}
}

// RunCryptocore запускает cryptocore с заданными аргументами
func (th *TestHelper) RunCryptocore(args ...string) (string, error) {
	th.t.Helper()

	// Ищем бинарник cryptocore
	binaryPath := th.findCryptocoreBinary()
	if binaryPath == "" {
		th.t.Skip("cryptocore binary not found, skipping CLI test")
		return "", nil
	}

	// Запускаем команду
	cmd := exec.Command(binaryPath, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (th *TestHelper) findCryptocoreBinary() string {
	// Пробуем стандартные пути
	possiblePaths := []string{
		"../cryptocore",
		"../cryptocore.exe",
		"./cryptocore",
		"./cryptocore.exe",
		"cryptocore",
		"cryptocore.exe",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			absPath, _ := filepath.Abs(path)
			return absPath
		}
	}

	return ""
}

// GenerateTestData генерирует тестовые данные указанного размера
func (th *TestHelper) GenerateTestData(size int) []byte {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		th.t.Fatalf("Failed to generate random test data: %v", err)
	}
	return data
}

// TestVector структура для хранения тестовых векторов
type TestVector struct {
	Name     string
	Input    []byte
	Key      []byte
	IV       []byte
	AAD      []byte
	Expected []byte
	Comment  string
}

// ParseHexVector парсит hex строки в тестовый вектор
func (th *TestHelper) ParseHexVector(name, inputHex, keyHex, ivHex, aadHex, expectedHex, comment string) *TestVector {
	vector := &TestVector{
		Name:    name,
		Comment: comment,
	}

	if inputHex != "" {
		vector.Input = th.HexDecode(inputHex)
	}
	if keyHex != "" {
		vector.Key = th.HexDecode(keyHex)
	}
	if ivHex != "" {
		vector.IV = th.HexDecode(ivHex)
	}
	if aadHex != "" {
		vector.AAD = th.HexDecode(aadHex)
	}
	if expectedHex != "" {
		vector.Expected = th.HexDecode(expectedHex)
	}

	return vector
}

// TestAESEncryption тестирует AES шифрование с помощью стандартной библиотеки
func (th *TestHelper) TestAESEncryption(mode string, plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte

	switch strings.ToLower(mode) {
	case "ecb":
		if len(plaintext)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("plaintext length must be multiple of block size")
		}
		ciphertext = make([]byte, len(plaintext))
		for i := 0; i < len(plaintext); i += aes.BlockSize {
			block.Encrypt(ciphertext[i:], plaintext[i:i+aes.BlockSize])
		}

	case "cbc":
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
		}
		mode := cipher.NewCBCEncrypter(block, iv)
		ciphertext = make([]byte, len(plaintext))
		mode.CryptBlocks(ciphertext, plaintext)

	case "cfb":
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
		}
		stream := cipher.NewCFBEncrypter(block, iv)
		ciphertext = make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)

	case "ofb":
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
		}
		stream := cipher.NewOFB(block, iv)
		ciphertext = make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)

	case "ctr":
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
		}
		stream := cipher.NewCTR(block, iv)
		ciphertext = make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)

	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}

	return ciphertext, nil
}

// IsEqual сравнивает два байтовых массива
func (th *TestHelper) IsEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

// AssertNoError проверяет, что ошибки нет
func (th *TestHelper) AssertNoError(err error, message string) {
	th.t.Helper()
	if err != nil {
		th.t.Fatalf("%s: %v", message, err)
	}
}

// AssertError проверяет, что ошибка есть
func (th *TestHelper) AssertError(err error, message string) {
	th.t.Helper()
	if err == nil {
		th.t.Fatalf("%s: expected error but got none", message)
	}
}

// AssertNoErrorf проверяет, что ошибки нет (с форматированием)
func (th *TestHelper) AssertNoErrorf(err error, format string, args ...interface{}) {
	th.t.Helper()
	if err != nil {
		th.t.Fatalf(format+": %v", append(args, err)...)
	}
}

// AssertErrorf проверяет, что ошибка есть (с форматированием)
func (th *TestHelper) AssertErrorf(err error, format string, args ...interface{}) {
	th.t.Helper()
	if err == nil {
		th.t.Fatalf(format, args...)
	}
}

// BenchmarkHelper для бенчмарков
type BenchmarkHelper struct {
	t *testing.T
}

func NewBenchmarkHelper(t *testing.T) *BenchmarkHelper {
	return &BenchmarkHelper{t: t}
}

func (bh *BenchmarkHelper) Measure(name string, f func()) {
	bh.t.Helper()
	bh.t.Run(name, func(t *testing.T) {
		start := time.Now()
		f()
		elapsed := time.Since(start)
		t.Logf("%s took %v", name, elapsed)
	})
}

// MemoryCleanup проверяет очистку чувствительных данных
func (th *TestHelper) MemoryCleanup(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// LargeFileTest тестирует обработку больших файлов
func (th *TestHelper) LargeFileTest(size int64, testFunc func(filename string)) {
	th.t.Helper()

	// Создаем большой файл
	tmpfile, err := os.CreateTemp("", "cryptocore_large_*.tmp")
	if err != nil {
		th.t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	// Заполняем файл данными
	const chunkSize = 8192
	written := int64(0)
	data := make([]byte, chunkSize)

	for i := range data {
		data[i] = byte(i % 256)
	}

	for written < size {
		toWrite := chunkSize
		if size-written < int64(chunkSize) {
			toWrite = int(size - written)
		}
		n, err := tmpfile.Write(data[:toWrite])
		if err != nil {
			th.t.Fatalf("Failed to write to temp file: %v", err)
		}
		written += int64(n)
	}

	// Запускаем тест
	testFunc(tmpfile.Name())
}
