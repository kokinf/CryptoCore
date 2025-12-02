# CryptoCore

Командная утилита для шифрования, дешифрования, хеширования и аутентификации сообщений (HMAC) файлов с использованием AES-128 в различных режимах работы, криптографических хеш-функций и HMAC-SHA-256.

## Возможности

### Шифрование и дешифрование
- Шифрование и дешифрование файлов с помощью AES-128
- Поддержка режимов: ECB, CBC, CFB, OFB, CTR
- Автоматическая генерация ключей при шифровании
- Автоматическое добавление и удаление padding по стандарту PKCS#7 (для ECB, CBC)
- Потоковые режимы без padding (CFB, OFB, CTR)
- Работа с бинарными и текстовыми файлами
- Автоматическая генерация IV и поддержка внешних IV

### Хеширование
- Вычисление криптографических хешей SHA-256 и SHA3-256
- Проверка целостности файлов
- Совместимость со стандартными утилитами

### Аутентификация сообщений (HMAC)
- HMAC-SHA-256 реализация с нуля согласно RFC 2104
- Поддержка ключей любой длины
- Обнаружение изменений в файлах и подмены ключей

### Общие возможности
- Кроссплатформенная сборка (Windows, Linux, macOS)
- Подробная обработка ошибок и валидация входных данных
- Автогенерация имен выходных файлов
- Полная совместимость с OpenSSL
- Криптографически безопасный ГСЧ (CSPRNG)

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

### Шифрование и дешифрование

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

#### Хеширование файлов

```bash
# Базовое хеширование
./cryptocore dgst --algorithm sha256 --input document.pdf

# Хеширование с сохранением результата в файл
./cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

#### Аутентификация сообщений (HMAC)

```bash
# Генерация HMAC
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt

# Генерация HMAC с сохранением в файл
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac

# Верификация HMAC
./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected.hmac
# Вывод: [OK] HMAC verification successful
```

## Аргументы командной строки

### Шифрование/дешифрование

| Аргумент | Описание | Пример |
|----------|-----------|---------|
| `--algorithm` | Алгоритм шифрования | `--algorithm aes` |
| `--mode` | Режим работы | `--mode cbc`, `--mode ctr` |
| `--encrypt` | Режим шифрования | `--encrypt` |
| `--decrypt` | Режим дешифрования | `--decrypt` |
| `--key` | Ключ шифрования (16 байт в hex) | `--key 00112233445566778899aabbccddeeff` |
| `--input` | Входной файл | `--input data.txt` |
| `--output` | Выходной файл | `--output result.bin` |
| `--iv` | Вектор инициализации для дешифрования | `--iv aabbccddeeff00112233445566778899` |

*Требуется указать ровно один из флагов `--encrypt` или `--decrypt` для операций шифрования*

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
- **Формат ключа**: 32 символа в шестнадцатеричном формате (16 байт)

### HMAC
- **Ключ обязателен**: при использовании `--hmac` аргумент `--key` обязателен
- **Любая длина**: HMAC поддерживает ключи любой длины (от 1 байта)

## Автоматическая генерация ключей

При шифровании без указания ключа утилита автоматически генерирует криптографически стойкий ключ:

```bash
./cryptocore --algorithm aes --mode ctr --encrypt --input data.txt --output encrypted.bin

Вывод после выполнения:
# Ключ не указан, будет сгенерирован автоматически
# Сгенерированный ключ: 6e420871b65f5404cd7fdee5c82bb4e9
# Operation completed successfully: data.txt -> encrypted.bin

# Использование сгенерированного ключа для дешифрования
./cryptocore --algorithm aes --mode ctr --decrypt \
  --key 6e420871b65f5404cd7fdee5c82bb4e9 \
  --input encrypted.bin --output decrypted.txt
```

## Режимы шифрования

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

## Технические детали

### Алгоритм: AES-128

- Размер блока: 16 байт
- Размер ключа: 16 байт (128 бит)
- Количество раундов: 10

### Криптографически безопасный ГСЧ

- Для генерации ключей и IV используется криптографически стойкий генератор случайных чисел
- Основан на системном источнике энтропии (`crypto/rand`)
- Гарантирует уникальность и непредсказуемость генерируемых значений
- Соответствует стандартам криптографической безопасности

### Padding: PKCS#7

- Автоматическое добавление байтов заполнения для ECB и CBC
- Размер padding: от 1 до 16 байт
- Автоматическое удаление при дешифровании
- Потоковые режимы (CFB, OFB, CTR) не используют padding

### Формат ключа и IV

- Ключ: 32 символа в шестнадцатеричном формате
- IV: 32 символа в шестнадцатеричном формате
- Пример ключа: `000102030405060708090a0b0c0d0e0f`
- Пример IV: `aabbccddeeff00112233445566778899`

### Формат файлов

Для режимов с IV (CBC, CFB, OFB, CTR):

```
[16 байт IV][данные шифротекста]
```

Для ECB (без IV):

```
[данные шифротекста]
```

## Примеры использования

### Пример 1: Шифрование с автоматической генерацией ключа

```bash
# Создание тестового файла
echo "What's up, guys?" > secret.txt

# Шифрование с автоматической генерацией ключа
./cryptocore --algorithm aes --mode cbc --encrypt --input secret.txt --output secret.enc
# Сохраните показанный в консоли ключ для последующего дешифрования

# Дешифрование с использованием сгенерированного ключа
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key СГЕНЕРИРОВАННЫЙ_КЛЮЧ \
  --input secret.enc --output secret_decrypted.txt
```

### Пример 2: Проверка целостности файлов с HMAC

```bash
# Вычисляем HMAC перед отправкой
./cryptocore dgst --algorithm sha256 --hmac --key секретный_ключ --input important_file.iso --output file_auth.hmac

# Получатель проверяет HMAC
./cryptocore dgst --algorithm sha256 --hmac --key секретный_ключ --input important_file.iso --verify file_auth.hmac
# Вывод: [OK] HMAC verification successful (если файл не изменен)
```

### Пример 3: Работа с разными режимами

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

### Пример 4: Автоматические имена файлов

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

### Пример 5: Работа с бинарными файлами

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

CryptoCore полностью совместим с OpenSSL для всех режимов шифрования, хеширования и HMAC.

### Тестирование совместимости

#### CryptoCore → OpenSSL

```bash
# Шифруем файл с помощью CryptoCore
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output ciphertext.bin

# Извлекаем IV и шифротекст
dd if=ciphertext.bin of=iv.bin bs=16 count=1
dd if=ciphertext.bin of=ciphertext_only.bin bs=16 skip=1

# Дешифруем с помощью OpenSSL
openssl enc -aes-128-cbc -d \
  -K 000102030405060708090A0B0C0D0E0F \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext_only.bin \
  -out openssl_decrypted.txt
```

#### OpenSSL → CryptoCore

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

## Тестирование

CryptoCore включает систему тестирования для обеспечения надежности и криптографической стойкости:

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

#### Тестовые векторы HMAC-SHA-256 (RFC 4231)

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

## Структура проекта

```
CryptoCore/
├── src/                  # Исходный код
│   ├── main.go           # Точка входа
│   ├── cli_parser.go     # Парсинг аргументов
│   ├── file_io.go        # Работа с файлами и IV
│   ├── csprng.go         # Криптографически безопасный ГСЧ
│   ├── hash/             # Реализации хеш-функций
│   │   ├── common.go     # Общие функции
│   │   ├── sha256.go     # SHA-256
│   │   └── sha3.go       # SHA3-256
│   ├── modes/            # Реализации режимов шифрования
│   │   ├── common.go     # Общие функции
│   │   ├── ecb.go        # Режим ECB
│   │   ├── cbc.go        # Режим CBC
│   │   ├── cfb.go        # Режим CFB
│   │   ├── ofb.go        # Режим OFB
│   │   └── ctr.go        # Режим CTR
│   └── mac/              # Реализации MAC функций
│       └── hmac.go       # HMAC-SHA-256
├── tests/                # Тесты
│   └── test_csprng.go    # Тесты криптографического ГСЧ
├── Makefile              # Система сборки
├── go.mod                # Зависимости Go
└── README.md             # Документация
```
