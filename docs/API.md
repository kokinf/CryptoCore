# CryptoCore API Documentation

## Оглавление
1. [Общая информация](#общая-информация)
2. [Модуль: cryptocore/src/modes](#модуль-cryptocoresrcmodes)
3. [Модуль: cryptocore/src/aead](#модуль-cryptocoresrcaead)
4. [Модуль: cryptocore/src/hash](#модуль-cryptocoresrchash)
5. [Модуль: cryptocore/src/mac](#модуль-cryptocoresrcmac)
6. [Модуль: cryptocore/src/kdf](#модуль-cryptocoresrckdf)
7. [Модуль: cryptocore/src/csprng](#модуль-cryptocoresrccsprng)
8. [Зависимости модулей](#зависимости-модулей)
9. [Версия и совместимость](#версия-и-совместимость)

## Общая информация

**CryptoCore** — это библиотека криптографических функций на языке Go, реализующая:
- Шифрование AES-128 с различными режимами
- Хеш-функции SHA-256 и SHA3-256
- Аутентификацию сообщений HMAC-SHA256
- Выработку ключей PBKDF2-HMAC-SHA256
- AEAD режимы (GCM, Encrypt-then-MAC)
- Криптографически безопасную генерацию случайных чисел

**Версия:** 1.0.0
**Go версия:** 1.25+
**Лицензия:** Проприетарная

## Модуль: cryptocore/src/modes

### `PKCS7Pad(data []byte, blockSize int) []byte`
Добавляет padding PKCS#7 к данным.

**Параметры:**
- `data` ([]byte): Исходные данные
- `blockSize` (int): Размер блока для выравнивания (обычно 16 для AES)

**Возвращает:**
- `[]byte`: Данные с добавленным padding

**Вызывает исключения:**
- Нет (паника при некорректных параметрах)

**Пример:**
```go
import "cryptocore/src/modes"

data := []byte("hello")
padded := modes.PKCS7Pad(data, 16)
// padded содержит 11 байт padding со значением 0x0b
```

### `PKCS7Unpad(data []byte) ([]byte, error)`
Удаляет padding PKCS#7 из данных.

**Параметры:**
- `data` ([]byte): Данные с padding

**Возвращает:**
- `[]byte`: Данные без padding
- `error`: Ошибка при некорректном padding

**Вызывает исключения:**
- `error`: "пустые данные" если data пустой
- `error`: "некорректный padding" если padding неправильный

**Пример:**
```go
import "cryptocore/src/modes"

data := []byte{...} // данные с padding
unpadded, err := modes.PKCS7Unpad(data)
if err != nil {
    // обработка ошибки
}
```

### `ECBEncrypt(plaintext, key []byte) ([]byte, error)`
Шифрует данные в режиме ECB.

**Параметры:**
- `plaintext` ([]byte): Открытый текст для шифрования
- `key` ([]byte): 16-байтный ключ шифрования

**Возвращает:**
- `[]byte`: Зашифрованный текст
- `error`: Ошибка при шифровании

**Вызывает исключения:**
- `error`: Ошибки crypto/aes.NewCipher при некорректном ключе

**Пример:**
```go
import "cryptocore/src/modes"

key := []byte("0123456789abcdef")
plaintext := []byte("secret message")
ciphertext, err := modes.ECBEncrypt(plaintext, key)
```

**Меры безопасности:** Режим ECB не рекомендуется для шифрования структурированных данных, так как не скрывает шаблоны.

### `ECBDecrypt(ciphertext, key []byte) ([]byte, error)`
Дешифрует данные в режиме ECB.

**Параметры:**
- `ciphertext` ([]byte): Зашифрованный текст
- `key` ([]byte): 16-байтный ключ шифрования

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании

**Вызывает исключения:**
- `error`: "длина зашифрованных данных не кратна размеру блока"
- `error`: Ошибки crypto/aes.NewCipher
- `error`: Ошибки PKCS7Unpad

### `CBCEncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме CBC с указанным IV.

**Параметры:**
- `plaintext` ([]byte): Открытый текст для шифрования
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Зашифрованный текст
- `error`: Ошибка при шифровании

**Вызывает исключения:**
- `error`: "некорректная длина IV" если IV не 16 байт
- `error`: Ошибки crypto/aes.NewCipher

**Пример:**
```go
import "cryptocore/src/modes"

key := make([]byte, 16)
iv := make([]byte, 16)
plaintext := []byte("confidential data")
ciphertext, err := modes.CBCEncryptWithIV(plaintext, key, iv)
```

### `CBCDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме CBC.

**Параметры:**
- `ciphertext` ([]byte): Зашифрованный текст
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании

**Вызывает исключения:**
- `error`: "длина зашифрованных данных не кратна размеру блока"
- `error`: "некорректная длина IV"
- `error`: Ошибки crypto/aes.NewCipher
- `error`: Ошибки PKCS7Unpad

### `CFBEncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме CFB.

**Параметры:**
- `plaintext` ([]byte): Открытый текст для шифрования
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Зашифрованный текст (той же длины что и plaintext)
- `error`: Ошибка при шифровании

**Вызывает исключения:**
- `error`: "некорректная длина IV"

**Особенности:** CFB — потоковый режим, не требует padding.

### `CFBDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме CFB.

**Параметры:**
- `ciphertext` ([]byte): Зашифрованный текст
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании

### `OFBEncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме OFB.

**Параметры:**
- `plaintext` ([]byte): Открытый текст для шифрования
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Зашифрованный текст
- `error`: Ошибка при шифровании

### `OFBDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме OFB.

**Параметры:**
- `ciphertext` ([]byte): Зашифрованный текст
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании

### `CTREncryptWithIV(plaintext, key, iv []byte) ([]byte, error)`
Шифрует данные в режиме CTR.

**Параметры:**
- `plaintext` ([]byte): Открытый текст для шифрования
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Зашифрованный текст
- `error`: Ошибка при шифровании

**Особенности:** CTR позволяет параллельное шифрование.

### `CTRDecrypt(ciphertext, key, iv []byte) ([]byte, error)`
Дешифрует данные в режиме CTR.

**Параметры:**
- `ciphertext` ([]byte): Зашифрованный текст
- `key` ([]byte): 16-байтный ключ шифрования
- `iv` ([]byte): 16-байтный вектор инициализации

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании

## Модуль: cryptocore/src/aead

### `NewGCM(key []byte) (*GCM, error)`
Создает новый объект GCM для аутентифицированного шифрования.

**Параметры:**
- `key` ([]byte): Ключ шифрования (16, 24 или 32 байта)

**Возвращает:**
- `*GCM`: Объект GCM
- `error`: Ошибка при создании

**Вызывает исключения:**
- `error`: "ключ GCM должен быть 16, 24 или 32 байта"
- `error`: Ошибки crypto/aes.NewCipher

**Пример:**
```go
import "cryptocore/src/aead"

key := make([]byte, 16)
gcm, err := aead.NewGCM(key)
if err != nil {
    // обработка ошибки
}
```

### `GCM.Encrypt(plaintext, aad []byte) ([]byte, error)`
Шифрует данные в режиме GCM.

**Параметры:**
- `plaintext` ([]byte): Открытый текст для шифрования
- `aad` ([]byte): Дополнительные аутентифицированные данные (опционально)

**Возвращает:**
- `[]byte`: Зашифрованные данные в формате: nonce(12) + ciphertext + tag(16)
- `error`: Ошибка при шифровании

**Вызывает исключения:**
- `error`: "ошибка генерации nonce"
- `error`: "ошибка GCTR шифрования"
- `error`: "ошибка вычисления тега"

**Пример:**
```go
plaintext := []byte("secret data")
aad := []byte("metadata")
ciphertext, err := gcm.Encrypt(plaintext, aad)
// ciphertext[0:12] - nonce
// ciphertext[12:len(ciphertext)-16] - шифротекст
// ciphertext[len(ciphertext)-16:] - тег аутентификации
```

### `GCM.Decrypt(data, aad []byte) ([]byte, error)`
Дешифрует данные в режиме GCM.

**Параметры:**
- `data` ([]byte): Зашифрованные данные в формате nonce+ciphertext+tag
- `aad` ([]byte): Дополнительные аутентифицированные данные (такие же как при шифровании)

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании

**Вызывает исключения:**
- `error`: "данные слишком короткие для GCM" если меньше 28 байт
- `error`: "ошибка аутентификации: неверный тег" при несовпадении тега
- `error`: "ошибка GCTR дешифрования"

### `GCM.SetNonce(nonce []byte) error`
Устанавливает nonce для GCM (опционально).

**Параметры:**
- `nonce` ([]byte): 12-байтный nonce

**Возвращает:**
- `error`: Ошибка если nonce некорректного размера

**Вызывает исключения:**
- `error`: "nonce должен быть 12 байт для GCM"

### `GCM.GetNonce() []byte`
Возвращает установленный nonce.

**Возвращает:**
- `[]byte`: Текущий nonce или пустой срез

### `NewEncryptThenMac(masterKey []byte, mode string) (*EncryptThenMac, error)`
Создает объект Encrypt-then-MAC.

**Параметры:**
- `masterKey` ([]byte): Мастер-ключ (16 или 48 байт)
- `mode` (string): Режим шифрования ("ecb", "cbc", "cfb", "ofb", "ctr")

**Возвращает:**
- `*EncryptThenMac`: Объект ETM
- `error`: Ошибка при создании

**Вызывает исключения:**
- `error`: "неподдерживаемый режим для Encrypt-then-MAC"
- `error`: "ошибка KDF"

### `EncryptThenMac.Encrypt(plaintext, aad []byte) ([]byte, error)`
Шифрует данные с последующей аутентификацией.

**Параметры:**
- `plaintext` ([]byte): Открытый текст
- `aad` ([]byte): Дополнительные аутентифицированные данные

**Возвращает:**
- `[]byte`: Данные в формате: ciphertext || tag(32 байта HMAC-SHA256)
- `error`: Ошибка при шифровании

### `EncryptThenMac.Decrypt(data, aad []byte) ([]byte, error)`
Дешифрует данные с проверкой аутентификации.

**Параметры:**
- `data` ([]byte): Данные в формате ciphertext || tag
- `aad` ([]byte): Дополнительные аутентифицированные данные

**Возвращает:**
- `[]byte`: Открытый текст
- `error`: Ошибка при дешифровании или аутентификации

**Вызывает исключения:**
- `error`: "данные слишком короткие" если меньше 32 байт
- `error`: "ошибка аутентификации: неверный MAC"

## Модуль: cryptocore/src/hash

### `HashAlgorithm`
Тип перечисления для алгоритмов хеширования.

**Значения:**
- `SHA256`: Алгоритм SHA-256
- `SHA3_256`: Алгоритм SHA3-256

### `NewHasher(algorithm HashAlgorithm) (Hasher, error)`
Создает новый объект хеш-функции.

**Параметры:**
- `algorithm` (HashAlgorithm): Алгоритм хеширования

**Возвращает:**
- `Hasher`: Интерфейс хеш-функции
- `error`: Ошибка при создании

**Вызывает исключения:**
- `*UnsupportedAlgorithmError`: "неподдерживаемый алгоритм хеширования"

### `ComputeHash(algorithm HashAlgorithm, inputFile string) (*HashResult, error)`
Вычисляет хеш файла.

**Параметры:**
- `algorithm` (HashAlgorithm): Алгоритм хеширования
- `inputFile` (string): Путь к входному файлу

**Возвращает:**
- `*HashResult`: Результат хеширования
- `error`: Ошибка при вычислении

**Вызывает исключения:**
- `*FileIOError`: Ошибки ввода-вывода
- `*UnsupportedAlgorithmError`: Неподдерживаемый алгоритм

### `ComputeHashFromReader(algorithm HashAlgorithm, reader io.Reader) ([]byte, error)`
Вычисляет хеш из io.Reader.

**Параметры:**
- `algorithm` (HashAlgorithm): Алгоритм хеширования
- `reader` (io.Reader): Источник данных

**Возвращает:**
- `[]byte`: Хеш-значение
- `error`: Ошибка при вычислении

### Интерфейс `Hasher`
```go
type Hasher interface {
    Update(data []byte)
    Finalize() []byte
    Reset()
    BlockSize() int
}
```

### `NewSHA256() *SHA256Impl`
Создает новый объект SHA-256.

**Возвращает:**
- `*SHA256Impl`: Реализация SHA-256

### `NewSHA3_256() *SHA3_256Impl`
Создает новый объект SHA3-256.

**Возвращает:**
- `*SHA3_256Impl`: Реализация SHA3-256

### `SHA256Impl.Update(data []byte)`
Добавляет данные к хешу.

### `SHA256Impl.Finalize() []byte`
Завершает вычисление хеша и возвращает результат.

### `SHA256Impl.Reset()`
Сбрасывает состояние хеш-функции.

### `SHA256Impl.BlockSize() int`
Возвращает размер блока (64 байта).

## Модуль: cryptocore/src/mac

### `NewHMAC(key []byte) (*HMAC, error)`
Создает новый объект HMAC-SHA256.

**Параметры:**
- `key` ([]byte): Ключ HMAC (любой длины)

**Возвращает:**
- `*HMAC`: Объект HMAC
- `error`: Ошибка при создании

**Вызывает исключения:**
- `error`: "ключ HMAC не может быть пустым"

### `HMAC.Compute(message []byte) []byte`
Вычисляет HMAC для сообщения.

**Параметры:**
- `message` ([]byte): Сообщение для аутентификации

**Возвращает:**
- `[]byte`: 32-байтный HMAC-SHA256

### `HMAC.ComputeFromFile(filename string) ([]byte, error)`
Вычисляет HMAC для файла.

**Параметры:**
- `filename` (string): Путь к файлу

**Возвращает:**
- `[]byte`: HMAC-значение
- `error`: Ошибка ввода-вывода

### `HMAC.Verify(message []byte, expectedMAC []byte) bool`
Проверяет HMAC сообщения.

**Параметры:**
- `message` ([]byte): Сообщение
- `expectedMAC` ([]byte): Ожидаемый HMAC (32 байта)

**Возвращает:**
- `bool`: true если HMAC верен

**Меры безопасности:** Использует constant-time сравнение.

### `HMAC.VerifyFromFile(filename string, expectedMAC []byte) (bool, error)`
Проверяет HMAC файла.

**Параметры:**
- `filename` (string): Путь к файлу
- `expectedMAC` ([]byte): Ожидаемый HMAC

**Возвращает:**
- `bool`: true если HMAC верен
- `error`: Ошибка ввода-вывода

### `ComputeHMAC(key, message []byte) ([]byte, error)`
Утилитарная функция для вычисления HMAC.

### `ComputeHMACHex(key, message []byte) (string, error)`
Вычисляет HMAC и возвращает в hex-формате.

### `VerifyHMAC(key, message, expectedMAC []byte) (bool, error)`
Утилитарная функция для проверки HMAC.

## Модуль: cryptocore/src/kdf

### `PBKDF2HMACSHA256(password []byte, salt []byte, iterations int, dkLen int) ([]byte, error)`
Реализация PBKDF2-HMAC-SHA256.

**Параметры:**
- `password` ([]byte): Пароль
- `salt` ([]byte): Соль (минимум 8 байт рекомендуется)
- `iterations` (int): Количество итераций (минимум 1000 рекомендуется)
- `dkLen` (int): Длина производного ключа в байтах

**Возвращает:**
- `[]byte`: Производный ключ
- `error`: Ошибка при выработке

**Вызывает исключения:**
- `error`: "пароль не может быть пустым"
- `error`: "соль не может быть пустой"
- `error`: "количество итераций должно быть положительным"
- `error`: "длина ключа должна быть положительной"
- `error`: "производный ключ слишком длинный"

**Пример:**
```go
import "cryptocore/src/kdf"

password := []byte("MyPassword123")
salt := []byte("randomsalt")
iterations := 100000
dkLen := 32

derivedKey, err := kdf.PBKDF2HMACSHA256(password, salt, iterations, dkLen)
```

### `DeriveKey(masterKey []byte, context string, length int) ([]byte, error)`
Вырабатывает ключ из мастер-ключа по контексту (HKDF-стиль).

**Параметры:**
- `masterKey` ([]byte): Мастер-ключ
- `context` (string): Контекст выработки
- `length` (int): Длина ключа в байтах

**Возвращает:**
- `[]byte`: Производный ключ
- `error`: Ошибка при выработке

**Алгоритм:** HMAC(master_key, context || counter)

### `DeriveMultipleKeys(masterKey []byte, contexts map[string]int) (map[string][]byte, error)`
Вырабатывает несколько ключей из одного мастер-ключа.

**Параметры:**
- `masterKey` ([]byte): Мастер-ключ
- `contexts` (map[string]int): Карта контекст->длина

**Возвращает:**
- `map[string][]byte`: Карта производных ключей
- `error`: Ошибка при выработке

### `DeriveAEADKeys(masterKey []byte, keySize int) (encKey, macKey []byte, err error)`
Вырабатывает ключи для AEAD режимов.

**Параметры:**
- `masterKey` ([]byte): Мастер-ключ
- `keySize` (int): Размер ключа (16, 24, 32 или 48)

**Возвращает:**
- `encKey` ([]byte): Ключ шифрования
- `macKey` ([]byte): Ключ MAC (только для keySize=48)
- `error`: Ошибка при выработке

## Модуль: cryptocore/src/csprng

### `CSPRNGError`
Структура ошибки генерации случайных чисел.

**Поля:**
- `RequestedBytes` (int): Запрошенное количество байт
- `Err` (error): Исходная ошибка

### `GenerateRandomBytes(numBytes int) ([]byte, error)`
Генерирует криптографически безопасные случайные байты.

**Параметры:**
- `numBytes` (int): Количество байт для генерации

**Возвращает:**
- `[]byte`: Случайные байты
- `error`: Ошибка при генерации

**Вызывает исключения:**
- `*CSPRNGError`: "ошибка генерации случайных байт"

**Источник энтропии:** crypto/rand.Reader (системный CSPRNG)

**Пример:**
```go
import "cryptocore/src/csprng"

// Генерация ключа
key, err := csprng.GenerateRandomBytes(16)
if err != nil {
    // обработка ошибки
}

// Генерация IV
iv, err := csprng.GenerateRandomBytes(16)
```

## Зависимости модулей

```
┌─────────────────┐
│   Основная CLI  │
│    (main.go)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Парсер CLI    │◄──►│  Работа с       │◄──►│   Режимы AES    │
│ (cli_parser.go) │    │  файлами        │    │   (modes/)      │
└─────────────────┘    │ (file_io.go)    │    └─────────────────┘
         │             └─────────────────┘            │
         ▼                      │                     │
┌─────────────────┐            │                     │
│   Операции      │            ▼                     ▼
│  хеширования    │    ┌─────────────────┐    ┌─────────────────┐
│  (hash/)        │    │      AEAD       │◄──►│      MAC        │
└─────────────────┘    │     (aead/)     │    │     (mac/)      │
         │             └─────────────────┘    └─────────────────┘
         ▼                      │                     │
┌─────────────────┐            │                     │
│      KDF        │            ▼                     ▼
│     (kdf/)      │    ┌─────────────────┐    ┌─────────────────┐
└─────────────────┘    │     CSPRNG      │    │   Тестирование  │
         │             │    (csprng/)    │    │     (tests/)    │
         ▼             └─────────────────┘    └─────────────────┘
┌─────────────────┐
│   Зависимости   │
│    внешние      │
└─────────────────┘
```

## Версия и совместимость

### Версия 1.0.0 (Текущая)
- **Стабильность:** Production-ready
- **Совместимость:**
  - Go 1.25+
  - Linux, macOS, Windows
  - 64-битные и 32-битные архитектуры

### Совместимость с другими библиотеками

#### OpenSSL
```bash
# Шифрование CBC совместимо
openssl enc -aes-128-cbc -K <key_hex> -iv <iv_hex> -in file.txt -out encrypted.bin

# Хеширование SHA-256 совместимо
openssl dgst -sha256 file.txt

# HMAC-SHA256 совместимо
openssl dgst -sha256 -hmac <key> file.txt

# PBKDF2-HMAC-SHA256 совместимо с Python hashlib
python3 -c "import hashlib, binascii; print(hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 100000, 32).hex())"
```

#### Криптографические стандарты
- **AES:** FIPS 197
- **SHA-256:** FIPS 180-4
- **SHA3-256:** FIPS 202
- **HMAC:** RFC 2104, RFC 4231
- **PBKDF2:** RFC 2898, RFC 6070
- **GCM:** NIST SP 800-38D

### Известные ограничения
1. Поддерживается только AES-128 (16-байтные ключи)
2. GCM поддерживает только 12-байтные nonce
3. Нет поддержки асинхронных операций
4. Нет встроенной поддержки аппаратного ускорения