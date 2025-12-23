# CryptoCore API Documentation

## Версия 7.0.0

### Совместимость
- **Go 1.25+**: Требуется для компиляции
- **Кроссплатформенный**: Windows, Linux, macOS
- **Совместимость с OpenSSL**: Режимы ECB, CBC, CFB, OFB, CTR, PBKDF2-HMAC-SHA256
- **Кодировка**: UTF-8 для всех строковых параметров

### Структура пакета
```go
import "cryptocore/src"
```

## Содержание
1. [Модуль: main](#модуль-main)
2. [Модуль: file_io](#модуль-file_io)
3. [Модуль: cli_parser](#модуль-cli_parser)
4. [Модуль: modes](#модуль-modes)
5. [Модуль: hash](#модуль-hash)
6. [Модуль: mac](#модуль-mac)
7. [Модуль: aead](#модуль-aead)
8. [Модуль: kdf](#модуль-kdf)
9. [Модуль: csprng](#модуль-csprng)

---

## Модуль: main

### `main()`
Точка входа приложения. Обрабатывает командную строку и выполняет соответствующие операции.

**Параметры:**
- `os.Args []string`: Аргументы командной строки

**Возвращает:**
- Ничего. Завершает программу с кодом:
  - `0`: Успех
  - `1`: Ошибка CLI/валидации
  - `2`: Ошибка ввода-вывода
  - `3`: Ошибка неподдерживаемого алгоритма
  - `4`: Ошибка файловой операции

**Вызывает:**
```bash
// Шифрование
cryptocore --algorithm aes --mode gcm --encrypt --input file.txt --output file.enc

// Хеширование
cryptocore dgst --algorithm sha256 --input file.txt

// Выработка ключа
cryptocore derive --password "secret" --iterations 100000 --length 32
```

---

## Модуль: file_io

### Структура `FileIOError`
```go
type FileIOError struct {
    Operation string // Тип операции: "чтение", "запись", "создание директории"
    Path      string // Путь к файлу
    Err       error  // Исходная ошибка
}
```
Ошибка ввода-вывода для файловых операций.

### `ReadInputFile(inputPath string) ([]byte, error)`
Читает содержимое файла полностью в память.

**Параметры:**
- `inputPath string`: Путь к файлу для чтения

**Возвращает:**
- `[]byte`: Содержимое файла
- `error`: `FileIOError` или `nil` при успехе

**Ошибки:**
- `FileIOError`: Файл не существует, это директория, нет прав на чтение
- `context.DeadlineExceeded`: Таймаут операции чтения

**Пример:**
```go
data, err := ReadInputFile("secret.txt")
if err != nil {
    fmt.Printf("Ошибка: %v\n", err)
}
```

### `WriteOutputFile(outputPath string, data []byte) error`
Записывает данные в файл, создавая директории при необходимости.

**Параметры:**
- `outputPath string`: Путь для записи
- `data []byte`: Данные для записи

**Возвращает:**
- `error`: `FileIOError` или `nil` при успехе

**Права доступа:**
- Созданные файлы: `0644` (rw-r--r--)
- Созданные директории: `0755` (rwxr-xr-x)

**Пример:**
```go
err := WriteOutputFile("output/encrypted.bin", ciphertext)
if err != nil {
    fmt.Printf("Ошибка записи: %v\n", err)
}
```

### `ReadEncryptedFileWithIV(filePath string) ([]byte, []byte, error)`
Читает файл, содержащий IV (16 байт) и шифротекст.

**Параметры:**
- `filePath string`: Путь к зашифрованному файлу

**Возвращает:**
- `[]byte`: Шифротекст (без IV)
- `[]byte`: IV (16 байт)
- `error`: `FileIOError` при ошибке

**Формат файла:**
```
[16 байт IV][шифротекст]
```

**Минимальный размер:** 16 байт

**Пример:**
```go
ciphertext, iv, err := ReadEncryptedFileWithIV("encrypted.bin")
if err != nil {
    fmt.Printf("Ошибка: %v\n", err)
}
```

### `ReadEncryptedFileWithNonce(filePath string) ([]byte, []byte, []byte, error)`
Читает файл в формате GCM (nonce, шифротекст, тег).

**Параметры:**
- `filePath string`: Путь к файлу GCM

**Возвращает:**
- `[]byte`: Шифротекст
- `[]byte`: Nonce (12 байт)
- `[]byte`: Тег аутентификации (16 байт)
- `error`: `FileIOError` при ошибке

**Формат файла:**
```
[12 байт nonce][шифротекст][16 байт тег]
```

**Минимальный размер:** 28 байт

**Пример:**
```go
ciphertext, nonce, tag, err := ReadEncryptedFileWithNonce("encrypted.gcm")
if err != nil {
    fmt.Printf("Ошибка: %v\n", err)
}
```

### `CleanupFailedOutput(outputPath string)`
Удаляет файл при ошибке аутентификации. Предотвращает утечку частично дешифрованных данных.

**Параметры:**
- `outputPath string`: Путь к файлу для удаления

**Пример:**
```go
defer CleanupFailedOutput("output.txt")
// ... операции, которые могут завершиться ошибкой аутентификации
```

---

## Модуль: cli_parser

### Структура `Config`
```go
type Config struct {
    Algorithm     string          // "aes"
    Mode          string          // "ecb", "cbc", "cfb", "ofb", "ctr", "gcm"
    Encrypt       bool            // Режим шифрования
    Decrypt       bool            // Режим дешифрования
    Key           []byte          // Бинарный ключ
    KeyStr        string          // Ключ в hex формате
    InputFile     string          // Входной файл
    OutputFile    string          // Выходной файл
    IV            []byte          // Вектор инициализации
    IVStr         string          // IV в hex формате
    Command       string          // "encrypt", "decrypt", "dgst", "derive"
    HashAlgorithm hash.HashAlgorithm // "sha256", "sha3-256"
    UseHMAC       bool            // Использовать HMAC
    VerifyFile    string          // Файл для проверки HMAC
    AAD           []byte          // Additional Authenticated Data
    AADStr        string          // AAD в hex формате
    UseAEAD       bool            // Использовать AEAD режим
    UseETM        bool            // Использовать Encrypt-then-MAC
    Password      string          // Пароль для KDF
    SaltStr       string          // Соль в hex формате
    Salt          []byte          // Бинарная соль
    Iterations    int             // Итерации PBKDF2
    KeyLength     int             // Длина ключа
    KDFAlgorithm  string          // "pbkdf2"
}
```

### `ParseCLI(args []string) (*Config, error)`
Парсит аргументы командной строки и валидирует конфигурацию.

**Параметры:**
- `args []string`: Аргументы командной строки

**Возвращает:**
- `*Config`: Конфигурация операции
- `error`: Ошибка парсинга или валидации

**Примеры использования:**
```bash
# Шифрование
cryptocore --algorithm aes --mode cbc --encrypt --key 0011...0e0f --input in.txt --output out.bin

# Хеширование
cryptocore dgst --algorithm sha256 --input file.txt

# HMAC
cryptocore dgst --algorithm sha256 --hmac --key 0011...eeff --input file.txt

# Выработка ключа
cryptocore derive --password "secret" --iterations 100000 --length 32
```

**Ошибки валидации:**
- `не указаны аргументы`: Пустая командная строка
- `неподдерживаемый режим`: Режим не из списка {ecb, cbc, cfb, ofb, ctr, gcm}
- `некорректный формат ключа`: Ключ не в hex формате
- `нельзя указывать одновременно --encrypt и --decrypt`: Конфликт флагов

### `isWeakKey(key []byte) bool`
Проверяет ключ на слабость (все нули, последовательные значения и т.д.).

**Параметры:**
- `key []byte`: Ключ для проверки

**Возвращает:**
- `bool`: `true` если ключ слабый

**Проверяемые паттерны:**
- Все байты равны 0
- Последовательные значения (0x01, 0x02, 0x03...)
- Одинаковые байты (0xAA, 0xAA, 0xAA...)
- Повторяющиеся паттерны

**Пример:**
```go
key := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
if isWeakKey(key) {
    fmt.Println("Предупреждение: слабый ключ обнаружен")
}
```

### `deriveOutputFilename(inputFile string, encrypt bool, mode string) string`
Генерирует имя выходного файла, если не указано явно.

**Параметры:**
- `inputFile string`: Исходный файл
- `encrypt bool`: Режим шифрования (true) или дешифрования (false)
- `mode string`: Режим шифрования

**Возвращает:**
- `string`: Сгенерированное имя файла

**Примеры:**
```bash
# Шифрование secret.txt в режиме CBC → secret_cbc.enc
# Дешифрование secret_cbc.enc → secret.dec.txt
# Шифрование data.pdf в режиме GCM → data_gcm.aead
```

---

## Модуль: modes

### `CreateCipherBlock(key []byte) (cipher.Block, error)`
Создает объект AES блочного шифра.

**Параметры:**
- `key []byte`: Ключ шифрования (16, 24 или 32 байта)

**Возвращает:**
- `cipher.Block`: Объект блочного шифра
- `error`: `crypto/aes.KeySizeError` при некорректной длине ключа

**Пример:**
```go
block, err := CreateCipherBlock(key)
if err != nil {
    return fmt.Errorf("ошибка создания блочного шифра: %v", err)
}
```

### `PKCS7Pad(data []byte, blockSize int) []byte`
Добавляет padding PKCS#7 к данным.

**Параметры:**
- `data []byte`: Исходные данные
- `blockSize int`: Размер блока (16 для AES)

**Возвращает:**
- `[]byte`: Данные с padding

**Алгоритм:**
- Вычисляет количество байт для добавления: `padding = blockSize - (len(data) % blockSize)`
- Добавляет байты со значением `padding`

**Пример:**
```go
// Данные: "hello" (5 байт)
// Результат: "hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
padded := PKCS7Pad([]byte("hello"), 16)
```

### `PKCS7Unpad(data []byte) ([]byte, error)`
Удаляет padding PKCS#7 из данных.

**Параметры:**
- `data []byte`: Данные с padding

**Возвращает:**
- `[]byte`: Данные без padding
- `error`: При некорректном padding

**Ошибки:**
- `пустые данные`: Длина данных равна 0
- `некорректный padding`: Последний байт указывает на несуществующий padding
- `некорректный padding`: Не все байты padding равны значению padding

**Пример:**
```go
data := []byte("hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
unpadded, err := PKCS7Unpad(data)
if err != nil {
    return fmt.Errorf("ошибка удаления padding: %v", err)
}
// unpadded = "hello"
```

### `ECBEncrypt(plaintext, key []byte) ([]byte, error)`
Шифрует данные в режиме ECB.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `key []byte`: Ключ шифрования (16 байт)

**Возвращает:**
- `[]byte`: Шифротекст
- `error`: При ошибке шифрования

**Особенности:**
- Использует padding PKCS#7
- Каждый блок шифруется независимо
- **Не рекомендуется** для структурированных данных

**Пример:**
```go
ciphertext, err := ECBEncrypt([]byte("secret data"), key)
if err != nil {
    return fmt.Errorf("ошибка шифрования ECB: %v", err)
}
```

### `ECBDecrypt(ciphertext, key []byte) ([]byte, error)`
Дешифрует данные в режиме ECB.

**Параметры:**
- `ciphertext []byte`: Шифротекст
- `key []byte`: Ключ шифрования (16 байт)

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке дешифрования

**Требования:**
- Длина шифротекста должна быть кратна 16 байтам

**Пример:**
```go
plaintext, err := ECBDecrypt(ciphertext, key)
if err != nil {
    return fmt.Errorf("ошибка дешифрования ECB: %v", err)
}
```

### `CBCEncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме CBC.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Шифротекст
- `error`: При ошибке шифрования

**Особенности:**
- Использует padding PKCS#7
- Цепочка блоков: каждый блок XORится с предыдущим шифротекстом
- **Рекомендуется** для большинства файлов

**Пример:**
```go
iv, _ := csprng.GenerateRandomBytes(16)
ciphertext, err := CBCEncryptWithIV(plaintext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка шифрования CBC: %v", err)
}
```

### `CBCDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме CBC.

**Параметры:**
- `ciphertext []byte`: Шифротекст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке дешифрования

**Требования:**
- Длина шифротекста должна быть кратна 16 байтам
- IV должен быть ровно 16 байт

**Пример:**
```go
plaintext, err := CBCDecrypt(ciphertext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка дешифрования CBC: %v", err)
}
```

### `CFBEncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме CFB.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Шифротекст
- `error`: При ошибке шифрования

**Особенности:**
- **Не использует padding** (потоковый режим)
- Размер сегмента: 128 бит (полный блок)
- Самосинхронизирующийся

**Пример:**
```go
ciphertext, err := CFBEncryptWithIV(plaintext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка шифрования CFB: %v", err)
}
```

### `CFBDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме CFB.

**Параметры:**
- `ciphertext []byte`: Шифротекст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке дешифрования

**Требования:**
- IV должен быть ровно 16 байт

**Пример:**
```go
plaintext, err := CFBDecrypt(ciphertext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка дешифрования CFB: %v", err)
}
```

### `OFBEncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме OFB.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Шифротекст
- `error`: При ошибке шифрования

**Особенности:**
- **Не использует padding** (потоковый режим)
- Генерирует keystream независимо от данных
- Полезен для чувствительных к задержкам данных

**Пример:**
```go
ciphertext, err := OFBEncryptWithIV(plaintext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка шифрования OFB: %v", err)
}
```

### `OFBDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме OFB.

**Параметры:**
- `ciphertext []byte`: Шифротекст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке дешифрования

**Требования:**
- IV должен быть ровно 16 байт

**Пример:**
```go
plaintext, err := OFBDecrypt(ciphertext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка дешифрования OFB: %v", err)
}
```

### `CTREncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме CTR.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Шифротекст
- `error`: При ошибке шифрования

**Особенности:**
- **Не использует padding** (потоковый режим)
- Использует счетчик для генерации keystream
- Поддерживает параллельную обработку

**Пример:**
```go
ciphertext, err := CTREncryptWithIV(plaintext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка шифрования CTR: %v", err)
}
```

### `CTRDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме CTR.

**Параметры:**
- `ciphertext []byte`: Шифротекст
- `key []byte`: Ключ шифрования (16 байт)
- `iv []byte`: Вектор инициализации (16 байт)

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке дешифрования

**Требования:**
- IV должен быть ровно 16 байт

**Пример:**
```go
plaintext, err := CTRDecrypt(ciphertext, key, iv)
if err != nil {
    return fmt.Errorf("ошибка дешифрования CTR: %v", err)
}
```

### Внутренние структуры

#### `cbcEncrypter`
Реализация шифрования CBC.

**Методы:**
- `CryptBlocks(dst, src []byte)`: Шифрует блоки данных

**Требования:**
- Длина `src` должна быть кратна 16 байтам
- `dst` должен быть не меньше `src`

#### `cbcDecrypter`
Реализация дешифрования CBC.

**Методы:**
- `CryptBlocks(dst, src []byte)`: Дешифрует блоки данных

#### `ctr`
Реализация режима CTR.

**Методы:**
- `XORKeyStream(dst, src []byte)`: Применяет keystream к данным
- `incrementCounter()`: Увеличивает счетчик

#### `ofb`
Реализация режима OFB.

**Методы:**
- `XORKeyStream(dst, src []byte)`: Применяет keystream к данным

---

## Модуль: hash

### Типы

#### `HashAlgorithm`
```go
type HashAlgorithm string
```
Тип для идентификации алгоритмов хеширования.

**Возможные значения:**
- `SHA256`: "sha256"
- `SHA3_256`: "sha3-256"

#### `HashResult`
```go
type HashResult struct {
    Algorithm HashAlgorithm // Использованный алгоритм
    Hash      []byte        // Вычисленный хеш
    InputFile string        // Исходный файл
}
```
Результат вычисления хеша.

### Интерфейс `Hasher`
```go
type Hasher interface {
    Update(data []byte)          // Добавляет данные к хешу
    Finalize() []byte            // Возвращает финальный хеш
    Reset()                      // Сбрасывает состояние
    BlockSize() int              // Возвращает размер блока
}
```
Интерфейс для всех реализаций хеш-функций.

### `NewHasher(algorithm HashAlgorithm) (Hasher, error)`
Создает новый объект хеш-функции.

**Параметры:**
- `algorithm HashAlgorithm`: Алгоритм хеширования

**Возвращает:**
- `Hasher`: Объект хеш-функции
- `error`: `UnsupportedAlgorithmError` при неподдерживаемом алгоритме

**Пример:**
```go
hasher, err := NewHasher(hash.SHA256)
if err != nil {
    return fmt.Errorf("ошибка создания хешера: %v", err)
}
defer hasher.Reset()
```

### `ComputeHash(algorithm HashAlgorithm, inputFile string) (*HashResult, error)`
Вычисляет хеш файла.

**Параметры:**
- `algorithm HashAlgorithm`: Алгоритм хеширования
- `inputFile string`: Путь к файлу

**Возвращает:**
- `*HashResult`: Результат хеширования
- `error`: `FileIOError` при ошибке чтения файла

**Особенности:**
- Обрабатывает файлы по чанкам (8192 байта)
- Поддерживает пустые файлы
- Совместима с `sha256sum` форматом

**Пример:**
```go
result, err := ComputeHash(hash.SHA256, "document.pdf")
if err != nil {
    return fmt.Errorf("ошибка вычисления хеша: %v", err)
}
fmt.Println(result.String()) // Хеш и имя файла
```

### `ComputeHashFromReader(algorithm HashAlgorithm, reader io.Reader) ([]byte, error)`
Вычисляет хеш из потока данных.

**Параметры:**
- `algorithm HashAlgorithm`: Алгоритм хеширования
- `reader io.Reader`: Поток данных

**Возвращает:**
- `[]byte`: Вычисленный хеш
- `error`: При ошибке чтения

**Пример:**
```go
file, _ := os.Open("data.bin")
defer file.Close()

hash, err := ComputeHashFromReader(hash.SHA256, file)
if err != nil {
    return fmt.Errorf("ошибка: %v", err)
}
```

### `String() string` (метод `HashResult`)
Возвращает строковое представление хеша в формате `sha256sum`.

**Формат:**
```
HEX_HASH  FILENAME
```

**Пример:**
```
5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5 document.pdf
```

### `SHA256Impl`
Реализация SHA-256 с нуля.

#### `NewSHA256() *SHA256Impl`
Создает новый объект SHA-256.

**Инициализация:**
- Начальные значения хеша: дробные части квадратных корней первых 8 простых чисел
- Константы раундов: дробные части кубических корней первых 64 простых чисел

**Пример:**
```go
sha := hash.NewSHA256()
defer sha.Reset()
```

#### `Update(data []byte)`
Добавляет данные к хешу.

**Параметры:**
- `data []byte`: Данные для хеширования

**Особенности:**
- Обрабатывает данные блоками по 64 байта
- Поддерживает невыровненные данные

#### `Finalize() []byte`
Завершает вычисление хеша.

**Возвращает:**
- `[]byte`: 32-байтный хеш SHA-256

**Алгоритм:**
1. Добавляет padding: бит '1', нули, длина сообщения (64 бита)
2. Обрабатывает финальный блок
3. Возвращает конкатенацию 8 регистров состояния

#### `BlockSize() int`
Возвращает размер блока.

**Возвращает:**
- `int`: 64 (байта)

### `SHA3_256Impl`
Реализация SHA3-256 с нуля.

#### `NewSHA3_256() *SHA3_256Impl`
Создает новый объект SHA3-256.

**Инициализация:**
- Состояние: 25 × 64-битных слов (1600 бит)
- Rate: 136 байт (1088 бит)
- Output size: 32 байта (256 бит)

#### `Update(data []byte)`
Добавляет данные к губке.

**Параметры:**
- `data []byte`: Данные для поглощения

**Особенности:**
- Использует губку Keccak
- Rate: 136 байт

#### `Finalize() []byte`
Завершает вычисление хеша.

**Возвращает:**
- `[]byte`: 32-байтный хеш SHA3-256

**Алгоритм:**
1. Добавляет padding: `0x06`, нули, `0x80`
2. Применяет преобразование Keccak-f
3. Выжимает 32 байта из губки

#### `BlockSize() int`
Возвращает размер блока.

**Возвращает:**
- `int`: 136 (байт)

#### `keccakF()`
Применяет преобразование Keccak-f к состоянию.

**Раунды:** 24
**Операции:** θ (theta), ρ (rho), π (pi), χ (chi), ι (iota)

### Ошибки

#### `UnsupportedAlgorithmError`
```go
type UnsupportedAlgorithmError struct {
    Algorithm string
}
```
Ошибка неподдерживаемого алгоритма хеширования.

**Пример:**
```go
_, err := NewHasher("md5")
// err.Error() = "неподдерживаемый алгоритм хеширования: md5"
```

---

## Модуль: mac

### `HMAC`
```go
type HMAC struct {
    hashFunc   hash.Hasher // Внутренний хешер
    blockSize  int         // Размер блока (64 для SHA-256)
    outputSize int         // Размер вывода (32 для SHA-256)
    key        []byte      // Обработанный ключ
}
```
Реализация HMAC-SHA-256 согласно RFC 2104.

### `NewHMAC(key []byte) (*HMAC, error)`
Создает новый объект HMAC.

**Параметры:**
- `key []byte`: Ключ HMAC (любой длины)

**Возвращает:**
- `*HMAC`: Объект HMAC
- `error`: При нулевой длине ключа

**Обработка ключа:**
- Если ключ длиннее `blockSize` (64 байта): хешируется
- Если ключ короче `blockSize`: дополняется нулями

**Пример:**
```go
hmac, err := NewHMAC([]byte{0x01, 0x02, 0x03})
if err != nil {
    return fmt.Errorf("ошибка создания HMAC: %v", err)
}
```

### `Compute(message []byte) []byte`
Вычисляет HMAC для сообщения.

**Параметры:**
- `message []byte`: Сообщение

**Возвращает:**
- `[]byte`: 32-байтный HMAC-SHA-256

**Алгоритм:** RFC 2104
```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```
где:
- `H`: SHA-256
- `opad`: `0x5c` повторенный
- `ipad`: `0x36` повторенный

**Пример:**
```go
mac := hmac.Compute([]byte("Hello, World!"))
fmt.Printf("HMAC: %x\n", mac)
```

### `ComputeFromReader(reader io.Reader) ([]byte, error)`
Вычисляет HMAC для потока данных.

**Параметры:**
- `reader io.Reader`: Поток данных

**Возвращает:**
- `[]byte`: HMAC
- `error`: При ошибке чтения

**Особенности:**
- Обрабатывает данные чанками (8192 байта)
- Подходит для больших файлов

**Пример:**
```go
file, _ := os.Open("large_file.bin")
defer file.Close()

mac, err := hmac.ComputeFromReader(file)
if err != nil {
    return fmt.Errorf("ошибка: %v", err)
}
```

### `ComputeFromFile(filename string) ([]byte, error)`
Вычисляет HMAC для файла.

**Параметры:**
- `filename string`: Путь к файлу

**Возвращает:**
- `[]byte`: HMAC
- `error`: `FileIOError` при ошибке файла

**Пример:**
```go
mac, err := hmac.ComputeFromFile("document.pdf")
if err != nil {
    return fmt.Errorf("ошибка вычисления HMAC: %v", err)
}
```

### `Verify(message []byte, expectedMAC []byte) bool`
Проверяет HMAC сообщения.

**Параметры:**
- `message []byte`: Сообщение
- `expectedMAC []byte`: Ожидаемый HMAC

**Возвращает:**
- `bool`: `true` если HMAC совпадает

**Особенности:**
- Использует constant-time сравнение
- Защищено от timing-атак

**Пример:**
```go
isValid := hmac.Verify(message, expectedMAC)
if !isValid {
    return errors.New("HMAC verification failed")
}
```

### `VerifyFromFile(filename string, expectedMAC []byte) (bool, error)`
Проверяет HMAC файла.

**Параметры:**
- `filename string`: Путь к файлу
- `expectedMAC []byte`: Ожидаемый HMAC

**Возвращает:**
- `bool`: `true` если HMAC совпадает
- `error`: При ошибке чтения файла

**Пример:**
```go
valid, err := hmac.VerifyFromFile("data.bin", expectedMAC)
if err != nil {
    return fmt.Errorf("ошибка проверки: %v", err)
}
if !valid {
    return errors.New("файл изменен")
}
```

### `ComputeHex(message []byte) string`
Вычисляет HMAC и возвращает в hex формате.

**Параметры:**
- `message []byte`: Сообщение

**Возвращает:**
- `string`: HMAC в hex формате

**Пример:**
```go
hexMAC := hmac.ComputeHex([]byte("test"))
fmt.Println(hexMAC) // 32 hex символа
```

### `ComputeHexFromFile(filename string) (string, error)`
Вычисляет HMAC файла и возвращает в hex формате.

**Параметры:**
- `filename string`: Путь к файлу

**Возвращает:**
- `string`: HMAC в hex формате
- `error`: При ошибке файла

**Пример:**
```go
hexMAC, err := hmac.ComputeHexFromFile("file.txt")
if err != nil {
    return fmt.Errorf("ошибка: %v", err)
}
fmt.Printf("HMAC: %s\n", hexMAC)
```

### `GetKey() []byte`
Возвращает копию обработанного ключа.

**Возвращает:**
- `[]byte`: Копия ключа

**Безопасность:** Возвращает копию для предотвращения модификации

### `GetBlockSize() int`
Возвращает размер блока.

**Возвращает:**
- `int`: 64 (байта)

### `GetOutputSize() int`
Возвращает размер вывода.

**Возвращает:**
- `int`: 32 (байта)

### Вспомогательные функции

#### `ComputeHMAC(key, message []byte) ([]byte, error)`
Упрощенный вызов HMAC.

**Параметры:**
- `key []byte`: Ключ
- `message []byte`: Сообщение

**Возвращает:**
- `[]byte`: HMAC
- `error`: При ошибке создания HMAC

**Пример:**
```go
mac, err := ComputeHMAC(key, message)
if err != nil {
    return fmt.Errorf("ошибка: %v", err)
}
```

#### `ComputeHMACHex(key, message []byte) (string, error)`
Вычисляет HMAC и возвращает в hex формате.

**Параметры:**
- `key []byte`: Ключ
- `message []byte`: Сообщение

**Возвращает:**
- `string`: HMAC в hex формате
- `error`: При ошибке

#### `VerifyHMAC(key, message, expectedMAC []byte) (bool, error)`
Проверяет HMAC.

**Параметры:**
- `key []byte`: Ключ
- `message []byte`: Сообщение
- `expectedMAC []byte`: Ожидаемый HMAC

**Возвращает:**
- `bool`: `true` если HMAC совпадает
- `error`: При ошибке создания HMAC

---

## Модуль: aead

### `GCM`
```go
type GCM struct {
    block    cipher.Block  // AES блочный шифр
    hashKey  [16]byte      // Ключ для GHASH
    mulTable [16][256][16]byte // Предвычисленная таблица умножения
    nonce    []byte        // Nonce (12 байт)
}
```
Реализация GCM (Galois/Counter Mode) согласно NIST SP 800-38D.

### `NewGCM(key []byte) (*GCM, error)`
Создает новый объект GCM.

**Параметры:**
- `key []byte`: Ключ шифрования (16, 24 или 32 байта)

**Возвращает:**
- `*GCM`: Объект GCM
- `error`: При некорректной длине ключа

**Инициализация:**
1. Создает AES шифр
2. Вычисляет hashKey: `E_K(0^128)`
3. Предвычисляет таблицу умножения для GHASH

**Пример:**
```go
gcm, err := NewGCM(key)
if err != nil {
    return fmt.Errorf("ошибка создания GCM: %v", err)
}
```

### `Encrypt(plaintext, aad []byte) ([]byte, error)`
Шифрует данные в режиме GCM.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `aad []byte`: Additional Authenticated Data (может быть пустым)

**Возвращает:**
- `[]byte`: Зашифрованные данные в формате `[nonce][шифротекст][тег]`
- `error`: При ошибке шифрования

**Формат вывода:**
```
[12 байт nonce][шифротекст][16 байт тег]
```

**Алгоритм:**
1. Генерирует случайный nonce (12 байт)
2. Вычисляет J0 из nonce
3. Шифрует в режиме CTR с счетчиком J0+1, J0+2, ...
4. Вычисляет тег аутентификации с помощью GHASH

**Пример:**
```go
ciphertext, err := gcm.Encrypt([]byte("secret"), []byte("metadata"))
if err != nil {
    return fmt.Errorf("ошибка шифрования: %v", err)
}
```

### `Decrypt(data, aad []byte) ([]byte, error)`
Дешифрует данные в режиме GCM.

**Параметры:**
- `data []byte`: Данные в формате `[nonce][шифротекст][тег]`
- `aad []byte`: Additional Authenticated Data

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке аутентификации или дешифрования

**Требования:**
- Минимальная длина данных: 28 байт (12 nonce + 16 tag)

**Аутентификация:**
1. Проверяет тег перед дешифрованием
2. Если проверка не прошла - возвращает ошибку без вывода данных

**Пример:**
```go
plaintext, err := gcm.Decrypt(ciphertextWithNonceAndTag, aad)
if err != nil {
    return fmt.Errorf("ошибка аутентификации: %v", err)
}
```

### `SetNonce(nonce []byte) error`
Устанавливает nonce для шифрования.

**Параметры:**
- `nonce []byte`: Nonce (12 байт)

**Возвращает:**
- `error`: При некорректной длине nonce

**Использование:**
- Только для тестирования с фиксированным nonce
- В продакшене используйте случайный nonce

**Пример:**
```go
err := gcm.SetNonce([]byte{0,1,2,3,4,5,6,7,8,9,10,11})
if err != nil {
    return fmt.Errorf("ошибка установки nonce: %v", err)
}
```

### `GetNonce() []byte`
Возвращает текущий nonce.

**Возвращает:**
- `[]byte`: Nonce или `nil`

### Внутренние методы GCM

#### `ghash(aad, ciphertext []byte) [16]byte`
Вычисляет GHASH в поле Галуа GF(2^128).

**Параметры:**
- `aad []byte`: Additional Authenticated Data
- `ciphertext []byte`: Шифротекст

**Возвращает:**
- `[16]byte`: Значение GHASH

**Полином:** `x^128 + x^7 + x^2 + x + 1`

#### `gctr(icb [16]byte, x []byte) ([]byte, error)`
Реализация GCTR (режим CTR для GCM).

**Параметры:**
- `icb [16]byte`: Initial Counter Block
- `x []byte`: Данные для шифрования/дешифрования

#### `multiply(x, y [2]uint64) [2]uint64`
Умножение в поле Галуа GF(2^128).

### `EncryptThenMac`
```go
type EncryptThenMac struct {
    encryptionKey []byte // Ключ шифрования (16 байт)
    macKey        []byte // Ключ MAC (32 байта)
    mode          string // Режим шифрования
}
```
Реализация парадигмы Encrypt-then-MAC.

### `NewEncryptThenMac(masterKey []byte, mode string) (*EncryptThenMac, error)`
Создает новый объект Encrypt-then-MAC.

**Параметры:**
- `masterKey []byte`: Мастер-ключ (48 байт для ETM)
- `mode string`: Режим шифрования ("cbc", "ctr", и т.д.)

**Возвращает:**
- `*EncryptThenMac`: Объект ETM
- `error`: При некорректных параметрах

**Поддерживаемые режимы:** "ecb", "cbc", "cfb", "ofb", "ctr"

**Пример:**
```go
// 48-байтный ключ: 16 для шифрования + 32 для MAC
masterKey := make([]byte, 48)
etm, err := NewEncryptThenMac(masterKey, "cbc")
if err != nil {
    return fmt.Errorf("ошибка создания ETM: %v", err)
}
```

### `Encrypt(plaintext, aad []byte) ([]byte, error)`
Шифрует данные по парадигме Encrypt-then-MAC.

**Параметры:**
- `plaintext []byte`: Открытый текст
- `aad []byte`: Additional Authenticated Data

**Возвращает:**
- `[]byte`: Данные в формате `[шифротекст][HMAC]` (или с IV)

**Алгоритм:**
1. Шифрует данные в выбранном режиме
2. Вычисляет HMAC от `шифротекст || AAD`
3. Возвращает конкатенацию

**Пример:**
```go
ciphertext, err := etm.Encrypt([]byte("data"), []byte("metadata"))
if err != nil {
    return fmt.Errorf("ошибка шифрования: %v", err)
}
```

### `Decrypt(data, aad []byte) ([]byte, error)`
Дешифрует данные с проверкой MAC.

**Параметры:**
- `data []byte`: Данные в формате ETM
- `aad []byte`: Additional Authenticated Data

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: При ошибке аутентификации

**Аутентификация:**
1. Проверяет HMAC перед дешифрованием
2. Если проверка не прошла - возвращает ошибку

**Пример:**
```go
plaintext, err := etm.Decrypt(ciphertext, aad)
if err != nil {
    return fmt.Errorf("ошибка аутентификации: %v", err)
}
```

### `Verify(data, aad []byte) (bool, error)`
Проверяет аутентификацию без дешифрования.

**Параметры:**
- `data []byte`: Данные в формате ETM
- `aad []byte`: Additional Authenticated Data

**Возвращает:**
- `bool`: `true` если аутентификация успешна
- `error`: При ошибке вычисления

**Пример:**
```go
valid, err := etm.Verify(ciphertext, aad)
if err != nil {
    return fmt.Errorf("ошибка проверки: %v", err)
}
if !valid {
    return errors.New("данные не прошли аутентификацию")
}
```

### `GenerateMasterKey() ([]byte, error)`
Генерирует мастер-ключ для ETM.

**Возвращает:**
- `[]byte`: 48-байтный ключ (16 + 32)
- `error`: При ошибке генерации

**Пример:**
```go
masterKey, err := GenerateMasterKey()
if err != nil {
    return fmt.Errorf("ошибка генерации ключа: %v", err)
}
```

---

## Модуль: kdf

### `PBKDF2HMACSHA256(password []byte, salt []byte, iterations int, dkLen int) ([]byte, error)`
Реализация PBKDF2-HMAC-SHA256 согласно RFC 2898.

**Параметры:**
- `password []byte`: Пароль (любой длины)
- `salt []byte`: Соль (не пустая)
- `iterations int`: Количество итераций (≥ 1)
- `dkLen int`: Длина производного ключа (≥ 1)

**Возвращает:**
- `[]byte`: Производный ключ
- `error`: При некорректных параметрах

**Ограничения:**
- Максимальная длина: `(2^32 - 1) * 32` байт
- Минимальные рекомендации: `iterations ≥ 1000`, `len(salt) ≥ 8`

**Алгоритм:**
```
DK = T1 || T2 || ... || Tdklen/hLen
Ti = F(P, S, c, i) = U1 ⊕ U2 ⊕ ... ⊕ Uc
U1 = PRF(P, S || INT_32_BE(i))
Uj = PRF(P, Uj-1)
```

**Пример:**
```go
dk, err := PBKDF2HMACSHA256(
    []byte("password"),
    []byte("salt"),
    100000,
    32,
)
if err != nil {
    return fmt.Errorf("ошибка KDF: %v", err)
}
```

### `DeriveKey(masterKey []byte, context string, length int) ([]byte, error)`
Выводит ключ из мастер-ключа с использованием контекста.

**Параметры:**
- `masterKey []byte`: Мастер-ключ (не пустой)
- `context string`: Контекст (идентификатор назначения)
- `length int`: Длина ключа (≥ 1)

**Возвращает:**
- `[]byte`: Производный ключ
- `error`: При некорректных параметрах

**Алгоритм:**
```
DerivedKey = HMAC(masterKey, context || counter)
```

**Пример:**
```go
// Разные контексты дают разные ключи
encKey, _ := DeriveKey(masterKey, "encryption", 16)
macKey, _ := DeriveKey(masterKey, "authentication", 32)
// encKey != macKey
```

### `HKDFExtract(hashFunc string, salt, ikm []byte) ([]byte, error)`
Реализация фазы извлечения HKDF.

**Параметры:**
- `hashFunc string`: Хеш-функция (только "sha256")
- `salt []byte`: Соль (пустая = нули)
- `ikm []byte`: Input Key Material

**Возвращает:**
- `[]byte`: Псевдослучайный ключ (PRK)

**Пример:**
```go
prk, err := HKDFExtract("sha256", salt, ikm)
if err != nil {
    return fmt.Errorf("ошибка извлечения: %v", err)
}
```

### `HKDFExpand(prk []byte, info []byte, length int) ([]byte, error)`
Реализация фазы расширения HKDF.

**Параметры:**
- `prk []byte`: Псевдослучайный ключ
- `info []byte`: Информация контекста
- `length int`: Длина вывода (≥ 1)

**Возвращает:**
- `[]byte`: Производный ключ
- `error`: При некорректных параметрах

**Ограничение:** `length ≤ 255 * 32`

**Пример:**
```go
okm, err := HKDFExpand(prk, []byte("session key"), 32)
if err != nil {
    return fmt.Errorf("ошибка расширения: %v", err)
}
```

### `HKDFFull(hashFunc string, ikm, salt, info []byte, length int) ([]byte, error)`
Полная реализация HKDF.

**Параметры:**
- `hashFunc string`: Хеш-функция
- `ikm []byte`: Input Key Material
- `salt []byte`: Соль
- `info []byte`: Информация
- `length int`: Длина вывода

**Возвращает:**
- `[]byte`: Производный ключ

**Пример:**
```go
key, err := HKDFFull("sha256", ikm, salt, info, 32)
if err != nil {
    return fmt.Errorf("ошибка HKDF: %v", err)
}
```

### `DeriveMultipleKeys(masterKey []byte, contexts map[string]int) (map[string][]byte, error)`
Выводит несколько ключей для разных контекстов.

**Параметры:**
- `masterKey []byte`: Мастер-ключ
- `contexts map[string]int`: Карта контекст → длина ключа

**Возвращает:**
- `map[string][]byte`: Карта контекст → ключ
- `error`: При ошибке вывода

**Пример:**
```go
contexts := map[string]int{
    "encryption": 16,
    "authentication": 32,
    "iv_generation": 16,
}

keys, err := DeriveMultipleKeys(masterKey, contexts)
if err != nil {
    return fmt.Errorf("ошибка: %v", err)
}

encKey := keys["encryption"]
macKey := keys["authentication"]
```

### `DeriveAEADKeys(masterKey []byte, keySize int) (encKey, macKey []byte, err error)`
Выводит ключи для AEAD режимов.

**Параметры:**
- `masterKey []byte`: Мастер-ключ
- `keySize int`: Требуемый размер (16, 24, 32 или 48)

**Возвращает:**
- `encKey []byte`: Ключ шифрования
- `macKey []byte`: Ключ MAC (только для keySize=48)
- `error`: При некорректном размере

**Пример:**
```go
// Для GCM: 16-байтный ключ
gcmKey, _, err := DeriveAEADKeys(masterKey, 16)

// Для ETM: 16-байтный ключ шифрования + 32-байтный ключ MAC
encKey, macKey, err := DeriveAEADKeys(masterKey, 48)
```

### `DeriveWithInfo(masterKey []byte, context, info string, length int) ([]byte, error)`
Выводит ключ с дополнительной информацией.

**Параметры:**
- `masterKey []byte`: Мастер-ключ
- `context string`: Базовый контекст
- `info string`: Дополнительная информация
- `length int`: Длина ключа

**Возвращает:**
- `[]byte`: Производный ключ

**Формат:** `context + "|" + info`

**Пример:**
```go
// Разные info дают разные ключи
key1, _ := DeriveWithInfo(masterKey, "user", "alice@example.com", 32)
key2, _ := DeriveWithInfo(masterKey, "user", "bob@example.com", 32)
// key1 != key2
```

### `VerifyKeyDerivation(masterKey []byte, context string, derivedKey []byte) (bool, error)`
Проверяет, что ключ был корректно выведен.

**Параметры:**
- `masterKey []byte`: Мастер-ключ
- `context string`: Контекст
- `derivedKey []byte`: Производный ключ для проверки

**Возвращает:**
- `bool`: `true` если ключ совпадает
- `error`: При ошибке вывода

**Пример:**
```go
valid, err := VerifyKeyDerivation(masterKey, "encryption", storedKey)
if err != nil {
    return fmt.Errorf("ошибка проверки: %v", err)
}
if !valid {
    return errors.New("ключ не соответствует мастер-ключу")
}
```

---

## Модуль: csprng

### Структура `CSPRNGError`
```go
type CSPRNGError struct {
    RequestedBytes int   // Запрошенное количество байт
    Err            error // Исходная ошибка
}
```
Ошибка генерации криптографически безопасных случайных чисел.

### `GenerateRandomBytes(numBytes int) ([]byte, error)`
Генерирует криптографически безопасные случайные байты.

**Параметры:**
- `numBytes int`: Количество байт для генерации (≥ 1)

**Возвращает:**
- `[]byte`: Случайные байты
- `error`: `CSPRNGError` при ошибке

**Источник:** `crypto/rand.Reader` (системный источник энтропии)

**Пример:**
```go
// Генерация ключа
key, err := GenerateRandomBytes(16)
if err != nil {
    return fmt.Errorf("ошибка генерации ключа: %v", err)
}

// Генерация IV
iv, err := GenerateRandomBytes(16)
if err != nil {
    return fmt.Errorf("ошибка генерации IV: %v", err)
}

// Генерация nonce для GCM
nonce, err := GenerateRandomBytes(12)
if err != nil {
    return fmt.Errorf("ошибка генерации nonce: %v", err)
}
```

### Обработка ошибок

#### `CSPRNGError.Error() string`
Форматирует сообщение об ошибке.

**Формат:**
```
ошибка генерации случайных байт (запрошено N байт): ОПИСАНИЕ_ОШИБКИ
```

**Примеры ошибок:**
- `numBytes ≤ 0`: "количество байт должно быть положительным"
- Системная ошибка: "невозможно прочитать из /dev/urandom"

---

## Приложение A: Константы и типы

### Константы хеширования

#### SHA-256
```go
// Начальные значения хеша (первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
h0 = 0x6a09e667
h1 = 0xbb67ae85
h2 = 0x3c6ef372
h3 = 0xa54ff53a
h4 = 0x510e527f
h5 = 0x9b05688c
h6 = 0x1f83d9ab
h7 = 0x5be0cd19

// Константы раундов (первые 32 бита дробных частей кубических корней первых 64 простых чисел)
k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    // ... 56 констант
    0xc67178f2
]
```

#### SHA3-256
```go
// Константы раундов Keccak-f
roundConstants = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808a, 0x8000000080008000,
    // ... 20 констант
    0x8000000080008008
]

// Параметры губки
rate = 136     // bytes (1088 bits)
capacity = 64  // bytes (512 bits)
outputSize = 32 // bytes (256 bits)
```

#### GCM
```go
// Неприводимый полином для GF(2^128)
polynomial = x^128 + x^7 + x^2 + x + 1

// Константы режимов
gcmNonceSize = 12    // рекомендуемый размер nonce
gcmTagSize = 16      // размер тега аутентификации
aesBlockSize = 16    // размер блока AES
```

### Форматы данных

#### Ключи
```go
// AES-128: 16 байт, 32 hex символа
key := "00112233445566778899aabbccddeeff"

// Для ETM: 48 байт, 96 hex символов
etmKey := "0011...1e1f2021...3e3f4041...5e5f"

// HMAC: любая длина, hex формат
hmacKey := "01"                    // 1 байт
hmacKey := "0011223344556677"     // 8 байт
hmacKey := "0011...eeff" * 100    // 100 байт
```

#### IV/Nonce
```go
// Стандартные режимы: 16 байт, 32 hex символа
iv := "aabbccddeeff00112233445566778899"

// GCM: 12 байт, 24 hex символа
nonce := "aabbccddeeff001122334455"
```

#### Форматы файлов
```
# ECB: [шифротекст]
# CBC/CFB/OFB/CTR: [16 байт IV][шифротекст]
# GCM: [12 байт nonce][шифротекст][16 байт тег]
# ETM (с IV): [16 байт IV][шифротекст][32 байт HMAC]
# ETM (ECB): [шифротекст][32 байт HMAC]
```

## Приложение B: Совместимость

### С OpenSSL
```bash
# Шифрование совместимо
openssl enc -aes-128-cbc -K KEY -iv IV -in file.txt -out file.bin
cryptocore --algorithm aes --mode cbc --key KEY --iv IV --input file.txt --output file.bin

# PBKDF2 совместимость
openssl kdf -keylen 32 -kdfopt pass:PASSWORD -kdfopt salt:SALT -kdfopt iter:ITERATIONS PBKDF2
cryptocore derive --password PASSWORD --salt SALT --iterations ITERATIONS --length 32

# HMAC совместимость
openssl dgst -sha256 -hmac KEY file.txt
cryptocore dgst --algorithm sha256 --hmac --key KEY --input file.txt
```

### С Python hashlib
```python
import hashlib
import binascii

# SHA-256
hashlib.sha256(b"data").hexdigest()
# CryptoCore: cryptocore dgst --algorithm sha256 --input <(echo -n "data")

# PBKDF2
hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 100000, dklen=32).hex()
# CryptoCore: cryptocore derive --password "password" --salt 73616c74 --iterations 100000 --length 32
```

## Приложение C: Тестовые векторы

### PBKDF2-HMAC-SHA256
```bash
# RFC 6070 (адаптировано для SHA-256)
Input:  P = "password" (8 octets)
        S = "salt" (4 octets)
        c = 1
        dkLen = 20

Output: DK = 120fb6cffcf8b32c43e7225256c4f837a86548c9
        (20 octets)

# Проверка:
cryptocore derive --password "password" --salt 73616c74 --iterations 1 --length 20
```

### HMAC-SHA-256
```bash
# RFC 4231 Test Case 1
Key:    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
Data:   4869205468657265 ("Hi There")
HMAC:   b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7

# Проверка:
echo -n "Hi There" > test.txt
cryptocore dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input test.txt
```

---

## Лицензия и авторские права

Copyright © 2025 CryptoCore Project. Все права защищены.

Данная документация является частью проекта CryptoCore и распространяется на тех же условиях, что и исходный код.