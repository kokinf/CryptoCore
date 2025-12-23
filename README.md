# CryptoCore

Командная утилита для криптографических операций: шифрование, дешифрование, хеширование, HMAC и выработка ключей с использованием AES-128, SHA-256, SHA3-256 и PBKDF2.

## Возможности

### Шифрование и дешифрование
- Шифрование и дешифрование файлов с помощью AES-128
- Поддержка режимов: ECB, CBC, CFB, OFB, CTR, GCM
- AEAD режимы с аутентификацией: GCM и Encrypt-then-MAC
- Автоматическая генерация ключей при шифровании
- Автоматическое добавление и удаление padding по стандарту PKCS#7 (для ECB, CBC)
- Потоковые режимы без padding (CFB, OFB, CTR, GCM)
- Работа с бинарными и текстовыми файлами
- Автоматическая генерация IV/nonce и поддержка внешних IV

### Хеширование
- Вычисление криптографических хешей SHA-256 и SHA3-256
- Проверка целостности файлов
- Совместимость со стандартными утилитами

### Аутентификация сообщений (HMAC)
- HMAC-SHA-256 реализация с нуля согласно RFC 2104
- Поддержка ключей любой длины
- Обнаружение изменений в файлах и подмены ключей
- Интеграция в Encrypt-then-MAC AEAD режим

### Функции выработки ключей (KDF)
- PBKDF2-HMAC-SHA256 - Password-Based Key Derivation Function 2
- HKDF и иерархия ключей - HMAC-based Key Derivation Function
- Автоматическая генерация солей - криптографически безопасная
- Поддержка произвольных параметров - длина пароля, соли, итераций, ключа

### Общие возможности
- Кроссплатформенная сборка (Windows, Linux, macOS)
- Подробная обработка ошибок и валидация входных данных
- Автогенерация имен выходных файлов
- Полная совместимость с OpenSSL и Python hashlib
- Криптографически безопасный ГСЧ (CSPRNG)
- Аутентификация данных перед дешифрованием
- Защита от подделки шифротекста

## Инструкции по сборке

### Требования

- Git - [Установить Git](https://git-scm.com/downloads)
- Go 1.25.1+ - [Установить Golang](https://go.dev/doc/install)

### Сборка проекта

```bash
# Клонирование репозитория
git clone https://github.com/kokinf/CryptoCore
cd CryptoCore

# Сборка для linux и macOS
make build

# Сборка для Windows
go build -o cryptocore.exe ./src
```

## Зависимости

- **Go 1.25+** - язык программирования и среда выполнения
- **Стандартная библиотека Go** - внешние зависимости не требуются
- **OpenSSL** (опционально) - для верификации результатов шифрования

## Использование

### Базовое шифрование и дешифрование

```bash
# Шифрование с автоматической генерацией ключа
./cryptocore --algorithm aes --mode cbc --encrypt --input secret.txt --output ciphertext.bin

# Шифрование файла в режиме ECB
./cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output ciphertext.bin

# Шифрование файла в режиме CBC (IV генерируется автоматически)
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output ciphertext.bin

# Дешифрование файла с автоматическим чтением IV из файла
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin --output decrypted.txt

# Дешифрование с указанием IV
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext.bin --output decrypted.txt
```

### AEAD шифрование (GCM и Encrypt-then-MAC)

#### GCM (Galois/Counter Mode):
```bash
# Шифрование GCM с автоматической генерацией ключа
./cryptocore --algorithm aes --mode gcm --encrypt \
  --input secret.txt --output encrypted.gcm
# Запишите сгенерированный ключ!

# Дешифрование GCM
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key СГЕНЕРИРОВАННЫЙ_КЛЮЧ \
  --input encrypted.gcm --output decrypted.txt

# GCM с AAD (Additional Authenticated Data)
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.pdf --output document.gcm \
  --aad "aabbccddeeff"

# Дешифрование с тем же AAD
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.gcm --output document_decrypted.pdf \
  --aad "aabbccddeeff"
```

#### Encrypt-then-MAC (требуется 48-байтный ключ):
```bash
# 48-байтный ключ для ETM
ETM_KEY="00112233445566778899aabbccddeeff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff"

# Шифрование ETM в режиме CBC
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key $ETM_KEY \
  --input sensitive.docx --output encrypted.etm

# Дешифрование ETM
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key $ETM_KEY \
  --input encrypted.etm --output decrypted.docx

# ETM с AAD
./cryptocore --algorithm aes --mode ctr --encrypt \
  --key $ETM_KEY \
  --input backup.tar --output backup.etm \
  --aad "aabbccddeeff"
```

### Хеширование файлов

```bash
# Базовое хеширование
./cryptocore dgst --algorithm sha256 --input document.pdf

# Хеширование с сохранением результата в файл
./cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

### Аутентификация сообщений (HMAC)

```bash
# Генерация HMAC
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt

# Генерация HMAC с сохранением в файл
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac

# Верификация HMAC
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected.hmac
# Вывод: [OK] HMAC verification successful
```

### Выработка ключей (PBKDF2-HMAC-SHA256)

```bash
# Базовая выработка ключа с указанной солью
./cryptocore derive --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32

# Выработка ключа с автоматической генерацией соли
./cryptocore derive --password "AnotherPassword" \
  --iterations 500000 \
  --length 16

# Выработка ключа и сохранение в файл
./cryptocore derive --password "app_key" \
  --salt fixedappsalt \
  --iterations 10000 \
  --length 32 \
  --output app_key.bin

# Проверка RFC 6070 тестовых векторов (SHA-256 версия)
./cryptocore derive --password "password" \
  --salt 73616c74 \
  --iterations 1 \
  --length 20
# Ожидаемый результат: 120fb6cffcf8b32c43e7225256c4f837a86548c9 73616c74
```

## Функции выработки ключей

### PBKDF2-HMAC-SHA256
Реализация Password-Based Key Derivation Function 2 согласно RFC 2898 с использованием HMAC-SHA256 в качестве псевдослучайной функции.

**Особенности:**
- Полная совместимость с Python `hashlib.pbkdf2_hmac('sha256', ...)`
- Поддержка произвольных длин пароля, соли и ключа
- Автоматическая генерация случайной 16-байтной соли
- Валидация параметров (итерации ≥ 1000, длина пароля ≥ 8 символов)
- Очистка чувствительных данных из памяти

**Примеры использования:**
```bash
# Базовый пример: 32-байтный ключ, 100000 итераций
./cryptocore derive --password "StrongPassword123" \
  --salt "deadbeefcafebabe0123456789abcdef" \
  --iterations 100000 \
  --length 32

# Автоматическая генерация соли
./cryptocore derive --password "AnotherPassword" \
  --iterations 500000 \
  --length 16

# Сохранение ключа в файл
./cryptocore derive --password "database_encryption_key" \
  --salt "db_salt_1234567890" \
  --iterations 200000 \
  --length 32 \
  --output db_key.bin
```

### Иерархия ключей (HKDF-стиль)
Функция для детерминированной выработки множества ключей из одного мастер-ключа:

```bash
# Пример использования в код:
import "cryptocore/src/kdf"

masterKey := []byte("master-key-32-bytes-123456789012")

// Вывод ключа шифрования
encryptionKey, _ := kdf.DeriveKey(masterKey, "encryption", 32)

// Вывод ключа аутентификации
authKey, _ := kdf.DeriveKey(masterKey, "authentication", 32)

// Вывод ключа для IV генерации
ivKey, _ := kdf.DeriveKey(masterKey, "iv_generation", 16)
```

**Принцип работы:**
```
DerivedKey = HMAC-SHA256(master_key, context || counter)
```

### Поддержка AEAD ключей
Интеграция с AEAD режимами для автоматической выработки encryption_key и mac_key:

```go
// Для Encrypt-then-MAC: 48 байт (16 + 32)
encKey, macKey, err := kdf.DeriveAEADKeys(masterKey, 48)

// Для GCM: 16, 24 или 32 байта
gcmKey, _, err := kdf.DeriveAEADKeys(masterKey, 16)
```

## Аргументы командной строки для KDF

| Аргумент | Описание | Пример | Обязательный |
|----------|-----------|---------|--------------|
| `--password` | Пароль для выработки ключа | `--password "MyPassword123"` | Да |
| `--salt` | Соль в hex-формате | `--salt a1b2c3d4e5f60123` | Нет (автогенерация) |
| `--iterations` | Количество итераций PBKDF2 | `--iterations 100000` | Нет (по умолчанию: 100000) |
| `--length` | Длина ключа в байтах | `--length 32` | Нет (по умолчанию: 32) |
| `--algorithm` | Алгоритм KDF | `--algorithm pbkdf2` | Нет (только pbkdf2) |
| `--output` | Выходной файл для ключа | `--output key.bin` | Нет |

**Формат вывода:**
```
KEY_HEX SALT_HEX
```

**Пример вывода:**
```
4cd8b5c46aee47f0d4a6a0dd7c205b1d30b54d2503c13fe7422e95ea312b7425 1234567890abcdef
```

## Тестирование KDF функций

### Проверка совместимости с Python
```bash
# Тест 1: password='password', salt='salt', iterations=1, dklen=20
./cryptocore derive --password "password" \
  --salt 73616c74 \
  --iterations 1 \
  --length 20
# Python: 120fb6cffcf8b32c43e7225256c4f837a86548c9

# Тест 2: password='password', salt='salt', iterations=2, dklen=20
./cryptocore derive --password "password" \
  --salt 73616c74 \
  --iterations 2 \
  --length 20
# Python: ae4d0c95af6b46d32d0adff928f06dd02a303f8e

# Тест 3: password='test', salt='1234567890abcdef', iterations=1000, dklen=32
./cryptocore derive --password "test" \
  --salt 1234567890abcdef \
  --iterations 1000 \
  --length 32
# Python: 4cd8b5c46aee47f0d4a6a0dd7c205b1d30b54d2503c13fe7422e95ea312b7425
```

### Запуск комплексных тестов
```bash
cd tests

# Тесты PBKDF2 с проверенными векторами
go run test_pbkdf2_vectors.go

# Комплексные тесты KDF функций
go run test_kdf_comprehensive.go
```

**Тестовое покрытие включает:**
- RFC 6070 тестовые векторы (адаптированные для SHA-256)
- Детерминированность результатов
- Различные длины ключей (1-128 байт)
- Уникальность сгенерированных солей (100+ тестов)
- Разделение ключей по контекстам
- Производительность (1000-50000 итераций)
- Совместимость с Python hashlib

### Проверка с Python
```python
# Проверка совместимости
import hashlib
import binascii

password = b'test'
salt = binascii.unhexlify('1234567890abcdef')
dk = hashlib.pbkdf2_hmac('sha256', password, salt, 1000, dklen=32)
print('Python:', binascii.hexlify(dk).decode())
# Результат: 4cd8b5c46aee47f0d4a6a0dd7c205b1d30b54d2503c13fe7422e95ea312b7425
```

## Аргументы командной строки для AEAD

### Общие аргументы шифрования/дешифрования

| Аргумент | Описание | Пример |
|----------|-----------|---------|
| `--algorithm` | Алгоритм шифрования | `--algorithm aes` |
| `--mode` | Режим работы | `--mode gcm`, `--mode ctr` |
| `--encrypt` | Режим шифрования | `--encrypt` |
| `--decrypt` | Режим дешифрования | `--decrypt` |
| `--key` | Ключ шифрования | `--key 0011...0e0f` (16 байт)<br>`--key 0011...1e1f` (48 байт для ETM) |
| `--input` | Входной файл | `--input data.txt` |
| `--output` | Выходной файл | `--output result.bin` |
| `--iv` | Вектор инициализации | `--iv aabb...8899` (16 байт для CBC/CFB/OFB/CTR)<br>`--iv aabb...4455` (12 байт для GCM) |
| `--aad` | Дополнительные аутентифицированные данные (hex) | `--aad 757365723a616c696365` |

*Требуется указать ровно один из флагов `--encrypt` или `--decrypt` для операций шифрования*

### Особенности AEAD режимов:

#### Для GCM:
- `--key`: 16, 24 или 32 байта
- `--iv` (nonce): 12 байт (рекомендуется), генерируется автоматически
- `--aad`: произвольная длина, опционально
- **Формат файла**: `[12 байт nonce][шифротекст][16 байт тег]`

#### Для Encrypt-then-MAC:
- `--key`: 48 байт (16 для шифрования + 32 для MAC)
- `--mode`: любой режим кроме GCM (CBC, CTR, CFB, OFB, ECB)
- `--aad`: произвольная длина, опционально
- **Формат файла**: `[16 байт IV][шифротекст][32 байт HMAC-SHA256]` (кроме ECB)

### Хеширование (подкоманда dgst)

| Аргумент | Описание | Пример |
|----------|-----------|---------|
| `--algorithm` | Алгоритм хеширования | `--algorithm sha256`, `--algorithm sha3-256` |
| `--input` | Входной файл | `--input document.pdf` |
| `--output` | Выходной файл (опционально) | `--output checksum.sha256` |

### HMAC (подкоманда dgst)

| Аргумент | Описание | Пример |
|----------|-----------|---------|
| `--hmac` | Включить режим HMAC | `--algorithm sha256 --hmac` |
| `--key` | Ключ HMAC в hex-формате (обязателен) | `--key 00112233445566778899aabbccddeeff` |
| `--verify` | Файл с ожидаемым HMAC для проверки | `--verify expected.hmac` |

## Особенности работы с ключами

- **При шифровании**: аргумент `--key` является опциональным. Если ключ не указан, будет автоматически сгенерирован криптографически стойкий 16-байтный ключ и выведен в консоль
- **При дешифровании**: аргумент `--key` является обязательным
- **Формат ключа**: 32 символа в шестнадцатеричном формате (16 байт) или 96 символов (48 байт для ETM)
- **ETM режим**: активируется автоматически при указании 48-байтного ключа

### HMAC
- **Ключ обязателен**: при использовании `--hmac` аргумент `--key` обязателен
- **Любая длина**: HMAC поддерживает ключи любой длины (от 1 байта)

## Автоматическая генерация ключей

При шифровании без указания ключа утилита автоматически генерирует криптографически стойкий ключ:

```bash
./cryptocore --algorithm aes --mode gcm --encrypt --input data.txt --output encrypted.bin

Вывод после выполнения:
# Ключ не указан, будет сгенерирован автоматически
# Сгенерированный ключ: 6e420871b65f5404cd7fdee5c82bb4e9
# GCM encryption completed with nonce: aabbccddeeff001122334455
# Operation completed successfully: data.txt -> encrypted.bin

# Использование сгенерированного ключа для дешифрования
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 6e420871b65f5404cd7fdee5c82bb4e9 \
  --input encrypted.bin --output decrypted.txt
```

## AEAD режимы шифрования

### GCM (Galois/Counter Mode)
- **Стандарт**: NIST SP 800-38D
- **Тип**: AEAD (аутентифицированное шифрование)
- **Nonce**: 12 байт (генерируется случайно)
- **Тег аутентификации**: 16 байт
- **AAD**: поддержка дополнительных аутентифицированных данных
- **Безопасность**: одновременная конфиденциальность и аутентификация
- **Особенность**: не требует padding, потоковый режим

### Encrypt-then-MAC
- **Парадигма**: шифрование затем MAC
- **Компоненты**: любой режим шифрования + HMAC-SHA256
- **Ключ**: 48 байт (16 для шифрования, 32 для MAC)
- **Тег аутентификации**: 32 байта HMAC-SHA256
- **Безопасность**: верификация перед дешифрованием
- **Гибкость**: работает с любым режимом шифрования

### ECB (Electronic Codebook)
- Каждый блок шифруется независимо
- Простая реализация
- Подходит для шифрования случайных данных
- **Внимание**: Не рекомендуется для шифрования структурированных данных из-за уязвимостей к анализу шаблонов
- Использует padding PKCS#7

### CBC (Cipher Block Chaining)
- Каждый блок XORится с предыдущим шифротекстом
- Повышенная безопасность по сравнению с ECB
- Использует padding PKCS#7
- Требует IV (генерируется автоматически при шифровании)

### CFB (Cipher Feedback)
- Режим потокового шифрования
- Не требует padding
- Самосинхронизирующийся
- Требует IV

### OFB (Output Feedback)
- Режим потокового шифрования  
- Генерирует keystream независимо от данных
- Не требует padding
- Требует IV

### CTR (Counter)
- Режим потокового шифрования
- Использует счетчик для генерации keystream
- Не требует padding
- Возможность параллельной обработки
- Требует IV/nonce

## Алгоритмы хеширования

### SHA-256
- **Стандарт**: NIST FIPS 180-4
- **Архитектура**: Merkle-Damgård
- **Размер блока**: 512 бит
- **Размер хеша**: 256 бит (32 байта)

### SHA3-256
- **Стандарт**: NIST FIPS 202
- **Архитектура**: Keccak sponge
- **Размер состояния**: 1600 бит
- **Размер хеша**: 256 бит (32 байта)

### HMAC-SHA-256
- **Стандарт**: RFC 2104 и RFC 4231
- **Архитектура**: HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))
- **Поддерживает**: ключи любой длины
- **Безопасность**: constant-time сравнение для верификации
- **Тест-векторы**: Полностью соответствует RFC 4231
- **Использование**: как часть Encrypt-then-MAC AEAD

## Технические детали AEAD

### GCM реализация:
- **GF(2^128) умножение**: полином x^128 + x^7 + x^2 + x + 1
- **GHASH**: аутентификация через умножение в поле Галуа
- **GCTR**: CTR mode для шифрования
- **Предвычисленные таблицы**: оптимизация производительности
- **Constant-time сравнение**: защита от timing-атак

### Encrypt-then-MAC:
- **Разделение ключей**: KDF для вывода encryption_key и mac_key
- **Порядок операций**: шифрование → MAC → верификация → дешифрование
- **Защита**: верификация MAC перед дешифрованием
- **Гибкость**: поддержка всех режимов шифрования

## Технические детали KDF

### PBKDF2-HMAC-SHA256 реализация:
- **Стандарт**: RFC 2898 и RFC 6070 (адаптировано для SHA-256)
- **Алгоритм**: PBKDF2(P, S, c, dkLen) = T1 || T2 || ... || Tdklen/hLen
- **PRF**: HMAC-SHA256 в качестве псевдослучайной функции
- **Проверено**: Полное совпадение с Python `hashlib.pbkdf2_hmac()`

### Иерархия ключей:
- **Основа**: HMAC-based KDF (HKDF-стиль)
- **Детерминированность**: DeriveKey(master_key, context, length)
- **Уникальность**: Разные контексты → разные ключи
- **Применение**: Выработка encryption_key, mac_key, iv_key из мастер-ключа

### Генерация соли:
- **Размер**: 16 байт (рекомендовано)
- **Источник**: Криптографически безопасный ГСЧ (`crypto/rand`)
- **Уникальность**: 100 сгенерированных солей → 100 уникальных значений
- **Безопасность**: Защита от rainbow table атак

## Технические детали

### Алгоритм: AES-128
- Размер блока: 16 байт
- Размер ключа: 16 байт (128 бит)
- Количество раундов: 10

### Криптографически безопасный ГСЧ
- Для генерации ключей, IV и солей используется криптографически стойкий генератор случайных чисел
- Основан на системном источнике энтропии (`crypto/rand`)
- Гарантирует уникальность и непредсказуемость генерируемых значений
- Соответствует стандартам криптографической безопасности

### Padding: PKCS#7
- Автоматическое добавление байтов заполнения для ECB и CBC
- Размер padding: от 1 до 16 байт
- Автоматическое удаление при дешифровании
- Потоковые режимы (CFB, OFB, CTR, GCM) не используют padding

### Формат ключа и IV
- Ключ: 32 символа в шестнадцатеричном формате (16 байт)
- Ключ ETM: 96 символов в шестнадцатеричном формате (48 байт)
- IV: 32 символа в шестнадцатеричном формате (16 байт)
- Nonce (GCM): 24 символа в шестнадцатеричном формате (12 байт)
- Пример ключа: `000102030405060708090a0b0c0d0e0f`
- Пример IV: `aabbccddeeff00112233445566778899`
- Пример nonce: `aabbccddeeff001122334455`

## Форматы файлов AEAD

### GCM формат:
```
[12 байт nonce][шифротекст][16 байт тег аутентификации]
```

### Encrypt-then-MAC формат (для режимов с IV):
```
[16 байт IV][шифротекст][32 байт HMAC-SHA256 тег]
```

### Encrypt-then-MAC формат (ECB):
```
[шифротекст][32 байт HMAC-SHA256 тег]
```

### Стандартные режимы с IV:
```
[16 байт IV][данные шифротекста]
```

### ECB (без IV):
```
[данные шифротекста]
```

## Примеры использования

### Пример 1: Безопасное хранение с Encrypt-then-MAC
```bash
# 48-байтный ключ для ETM
ETM_KEY="00112233445566778899aabbccddeeff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff"

# Шифрование конфиденциальных данных
./cryptocore --algorithm aes --mode ctr --encrypt \
  --key $ETM_KEY \
  --input database_backup.sql --output backup.etm \
  --aad "db_name:production|backup_type:full|encrypted_at:$(date -Iseconds)"

# Проверка целостности перед восстановлением
./cryptocore --algorithm aes --mode ctr --decrypt \
  --key $ETM_KEY \
  --input backup.etm --output /dev/null \
  --aad "db_name:production|backup_type:full|encrypted_at:2024-12-19T10:30:00Z"
```

### Пример 2: Обнаружение подделки данных
```bash
# Создаем подписанный файл
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input firmware.bin --output firmware_signed.gcm

# Злоумышленник изменяет файл
dd if=/dev/urandom of=firmware_tampered.gcm bs=1 count=1 seek=50 conv=notrunc

# Попытка дешифрования проваливается
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input firmware_tampered.gcm --output firmware.bin
# Вывод: Error: ошибка аутентификации GCM: ошибка аутентификации: неверный тег
```

### Пример 3: Проверка целостности файлов с HMAC
```bash
# Вычисляем HMAC перед отправкой
./cryptocore dgst --algorithm sha256 --hmac --key секретный_ключ --input important_file.iso --output file_auth.hmac

# Получатель проверяет HMAC
./cryptocore dgst --algorithm sha256 --hmac --key секретный_ключ --input important_file.iso --verify file_auth.hmac
# Вывод: [OK] HMAC verification successful (если файл не изменен)
```

### Пример 4: Выработка ключа для шифрования
```bash
# Генерируем ключ из пароля
./cryptocore derive --password "MyDatabasePassword!" \
  --salt "deadbeefcafebabe0123456789abcdef" \
  --iterations 100000 \
  --length 32 \
  --output db_encryption_key.bin

# Используем выведенный ключ для шифрования
DB_KEY=$(head -c 64 db_encryption_key.bin)  # Первые 32 байта в hex
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key $DB_KEY \
  --input sensitive_data.db --output encrypted_data.gcm
```

### Пример 5: Иерархия ключей для приложения
```bash
# Генерируем мастер-ключ
MASTER_KEY=$(openssl rand -hex 32)

```

### Пример 6: Работа с разными режимами
```bash
# Шифрование в режиме CFB
./cryptocore --algorithm aes --mode cfb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output data_cfb.enc

# Шифрование в режиме CTR
./cryptocore --algorithm aes --mode ctr --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output data_ctr.enc
```

### Пример 7: Автоматические имена файлов
```bash
# Шифрование с автоматическим именем файла (создаст secret_cbc.enc)
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt

# Дешифрование с автоматическим именем файла (создаст secret.dec)
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret_cbc.enc
```

### Пример 8: Работа с бинарными файлами
```bash
# Шифрование бинарного файла в режиме OFB
./cryptocore --algorithm aes --mode ofb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input image.jpg --output image_encrypted.bin

# Дешифрование обратно
./cryptocore --algorithm aes --mode ofb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input image_encrypted.bin --output image_restored.jpg
```

## Совместимость с OpenSSL

### CryptoCore -> OpenSSL (стандартные режимы):
```bash
# Шифруем файл с помощью CryptoCore
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt --output ciphertext.bin

# Извлекаем IV (первые 16 байт) и шифротекст
dd if=ciphertext.bin of=iv.bin bs=16 count=1
dd if=ciphertext.bin of=ciphertext_only.bin bs=16 skip=1

# Дешифруем с помощью OpenSSL
openssl enc -aes-128-cbc -d \
  -K 000102030405060708090A0B0C0D0E0F \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext_only.bin \
  -out openssl_decrypted.txt
```

### OpenSSL -> CryptoCore (стандартные режимы):
```bash
# Шифруем файл с помощью OpenSSL
openssl enc -aes-128-cbc \
  -K 000102030405060708090A0B0C0D0E0F \
  -iv AABBCCDDEEFF00112233445566778899 \
  -in secret.txt \
  -out openssl_ciphertext.bin

# Дешифруем с помощью CryptoCore
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv AABBCCDDEEFF00112233445566778899 \
  --input openssl_ciphertext.bin \
  --output cryptocore_decrypted.txt
```

### Команды OpenSSL для каждого режима

| Режим | Шифрование OpenSSL | Дешифрование OpenSSL |
|-------|-------------------|---------------------|
| ECB | `openssl enc -aes-128-ecb -K <key> -in <input> -out <output>` | `openssl enc -aes-128-ecb -d -K <key> -in <input> -out <output>` |
| CBC | `openssl enc -aes-128-cbc -K <key> -iv <iv> -in <input> -out <output>` | `openssl enc -aes-128-cbc -d -K <key> -iv <iv> -in <input> -out <output>` |
| CFB | `openssl enc -aes-128-cfb -K <key> -iv <iv> -in <input> -out <output>` | `openssl enc -aes-128-cfb -d -K <key> -iv <iv> -in <input> -out <output>` |
| OFB | `openssl enc -aes-128-ofb -K <key> -iv <iv> -in <input> -out <output>` | `openssl enc -aes-128-ofb -d -K <key> -iv <iv> -in <input> -out <output>` |
| CTR | `openssl enc -aes-128-ctr -K <key> -iv <iv> -in <input> -out <output>` | `openssl enc -aes-128-ctr -d -K <key> -iv <iv> -in <input> -out <output>` |

### Совместимость хеширования и HMAC

```bash
# Наша реализация SHA-256
./cryptocore dgst --algorithm sha256 --input file.txt

# Системная утилита
sha256sum file.txt  # Linux/Mac
certutil -hashfile file.txt SHA256  # Windows

# Наша реализация SHA3-256  
./cryptocore dgst --algorithm sha3-256 --input file.txt

# Системная утилита
sha3sum -a 256 file.txt  # Linux/Mac

# Наша реализация HMAC-SHA-256
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input file.txt

# OpenSSL HMAC
openssl dgst -sha256 -hmac 00112233445566778899aabbccddeeff file.txt
```

### Совместимость PBKDF2

```bash
# Наша реализация PBKDF2-HMAC-SHA256
./cryptocore derive --password "test" \
  --salt 1234567890abcdef \
  --iterations 1000 \
  --length 32

# Python hashlib (эталон)
python3 -c "
import hashlib, binascii
dk = hashlib.pbkdf2_hmac('sha256', b'test', 
                         binascii.unhexlify('1234567890abcdef'), 
                         1000, dklen=32)
print(binascii.hexlify(dk).decode())
"
# Результат должен совпадать: 4cd8b5c46aee47f0d4a6a0dd7c205b1d30b54d2503c13fe7422e95ea312b7425
```

## Тестирование безопасности

CryptoCore включает расширенную систему тестирования:

### Тестирование KDF функций:
```bash
cd tests

# Комплексные тесты PBKDF2
go run test_pbkdf2_vectors.go

# Все KDF тесты
go run test_kdf_comprehensive.go
```

**Тесты KDF включают:**
- Детерминированность PBKDF2 (1000+ тестов)
- Различные длины ключей (1-128 байт)
- Уникальность сгенерированных солей (100 солей)
- Разделение ключей по контекстам (5+ контекстов)
- Производительность (1000-50000 итераций)
- Совместимость с Python hashlib (полное совпадение)
- RFC 6070 тестовые векторы (адаптированные для SHA-256)

### Тестирование GCM безопасности:
```bash
cd tests
go run test_gcm_security.go
```

**Тесты включают:**
- Обнаружение подделки шифротекста
- Проверка аутентификации с AAD
- Обнаружение подделки тега
- Обработка пустых сообщений
- Безопасность повторного использования nonce

### Тестирование Encrypt-then-MAC безопасности:
```bash
cd tests
go run test_etm_security.go
```

**Тесты включают:**
- Аутентификация с AAD
- Обнаружение подделки данных
- Работа во всех режимах (CBC, CTR, CFB, OFB)
- Чувствительность к ключам
- Верификация перед дешифрованием
- Обработка пустых сообщений

### Модульное тестирование CSPRNG

```bash
# Запуск всех тестов криптографического ГСЧ
cd tests
go run test_csprng.go
```

**Тестовое покрытие включает:**
- Уникальность сгенерированных ключей (1000+ ключей)
- Статистическое распределение битов (энтропия ~50%)
- Корректную генерацию данных различных размеров
- Обработку граничных случаев и ошибок
- Интеграцию с основной утилитой

### Тестирование HMAC

Все тестовые векторы успешно пройдены реализацией:

**Тест 1: Basic HMAC with 20-byte key**
```bash
echo -n "Hi There" > test1.txt
./cryptocore dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input test1.txt
# Ожидаемый вывод: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7  test1.txt
```

**Тест 2: HMAC with ASCII key ("Jefe")**
```bash
echo -n "what do ya want for nothing?" > test2.txt
./cryptocore dgst --algorithm sha256 --hmac --key 4a656665 --input test2.txt
# Ожидаемый вывод: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843  test2.txt
```

**Тест 3: HMAC with binary data (50 bytes 0xdd)**
```bash
python -c "open('test3.bin', 'wb').write(b'\xdd' * 50)"
./cryptocore dgst --algorithm sha256 --hmac --key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --input test3.bin
# Ожидаемый вывод: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe  test3.bin
```

**Тест 4: HMAC with 25-byte incremental key**
```bash
python -c "open('test4.bin', 'wb').write(b'\xcd' * 50)"
./cryptocore dgst --algorithm sha256 --hmac --key 0102030405060708090a0b0c0d0e0f10111213141516171819 --input test4.bin
# Ожидаемый вывод: 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b  test4.bin
```

**Короткий ключ (1 байт)**
```bash
echo "Test" > short_key.txt
./cryptocore dgst --algorithm sha256 --hmac --key 01 --input short_key.txt
# Результат: 29509a96fbdc60371d82e416af5cef88d095af2bd303987588ba4d32f2810a49  short_key.txt
```

**Длинный ключ (100 байт)**
```bash
echo "Test" > long_key.txt
./cryptocore dgst --algorithm sha256 --hmac --key $(python -c "print('22' * 100)") --input long_key.txt
# Результат: 3c8f1c3a84cc99562789c71cc05022f8c9e39b2ec7e18a416e7f6ab45a38d802  long_key.txt
```

**Пустой файл**
```bash
echo -n "" > empty.txt
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input empty.txt
# Результат: 81482a2844d68464f2354eb65632aa95e0fee94a0dca9aec471238434a4c4bdb  empty.txt
```

**Обнаружение изменений в файле**
```bash
echo "Original content" > file.txt
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input file.txt --output original.hmac
echo "Modified content" > file.txt
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input file.txt --verify original.hmac
# Ожидаемый вывод: Error: HMAC verification failed
```

**Обнаружение неправильного ключа**
```bash
echo "Test message" > message.txt
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output correct.hmac
./cryptocore dgst --algorithm sha256 --hmac --key ffeeddccbbaa99887766554433221100 --input message.txt --verify correct.hmac
# Ожидаемый вывод: Error: HMAC verification failed
```

**Успешная верификация**
```bash
echo "Test message" > verify.txt
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input verify.txt --output verify.hmac
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input verify.txt --verify verify.hmac
# Ожидаемый вывод: [OK] HMAC verification successful
```

### NIST Statistical Test Suite

Генератор случайных чисел успешно прошел полную батарею тестов NIST STS:
- **15 статистических тестов** + 148 шаблонных тестов
- **Объем данных**: 10 MB случайных данных  
- **Результат**: 163/163 тестов успешно пройдены
- **Качество**: Соответствует стандартам криптографической безопасности

## Структура проекта (обновленная)

```
CryptoCore/
├── src/                      # Исходный код
│   ├── main.go              # Точка входа
│   ├── cli_parser.go        # Парсинг аргументов
│   ├── file_io.go           # Работа с файлами и IV
│   ├── kdf/                 # Функции выработки ключей
│   │   ├── pbkdf2.go        # PBKDF2-HMAC-SHA256 реализация
│   │   └── hkdf.go          # HKDF и иерархия ключей
│   ├── csprng/              # Криптографически безопасный ГСЧ
│   │   └── csprng.go        # Реализация CSPRNG
│   ├── aead/                # AEAD режимы
│   │   ├── gcm.go           # Режим GCM
│   │   └── encrypt_then_mac.go  # Encrypt-then-MAC парадигма
│   ├── hash/                # Реализации хеш-функций
│   │   ├── common.go        # Общие функции
│   │   ├── sha256.go        # SHA-256
│   │   └── sha3.go          # SHA3-256
│   ├── modes/               # Реализации режимов шифрования
│   │   ├── common.go        # Общие функции
│   │   ├── ecb.go           # Режим ECB
│   │   ├── cbc.go           # Режим CBC
│   │   ├── cfb.go           # Режим CFB
│   │   ├── ofb.go           # Режим OFB
│   │   └── ctr.go           # Режим CTR
│   └── mac/                 # Реализации MAC функций
│       └── hmac.go          # HMAC-SHA-256
├── tests/                   # Тесты
│   ├── test_pbkdf2_vectors.go     # Тесты PBKDF2 с векторами
│   ├── test_kdf_comprehensive.go  # Комплексные тесты KDF
│   ├── test_csprng.go       # Тесты криптографического ГСЧ
│   ├── test_gcm_security.go # Тесты безопасности GCM
│   └── test_etm_security.go # Тесты безопасности Encrypt-then-MAC
├── Makefile                 # Система сборки
├── go.mod                   # Зависимости Go
└── README.md               # Документация
```
