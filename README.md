# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в различных режимах работы

## Возможности

- Шифрование и дешифрование файлов с помощью AES-128
- Поддержка режимов: ECB, CBC, CFB, OFB, CTR
- Автоматическое добавление и удаление padding по стандарту PKCS#7 (для ECB, CBC)
- Потоковые режимы без padding (CFB, OFB, CTR)
- Работа с бинарными и текстовыми файлами
- Автоматическая генерация IV и поддержка внешних IV
- Кроссплатформенная сборка (Windows, Linux, macOS)
- Подробная обработка ошибок и валидация входных данных
- Автогенерация имен выходных файлов
- Полная совместимость с OpenSSL

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

### Базовое использование

```bash
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

## Аргументы командной строки

| Аргумент | Описание | Пример |
|----------|-----------|---------|
| `--algorithm` | Алгоритм шифрования | `--algorithm aes` |
| `--mode` | Режим работы | `--mode ecb`, `--mode cbc`, `--mode cfb`, `--mode ofb`, `--mode ctr` |
| `--encrypt` | Режим шифрования | `--encrypt` |
| `--decrypt` | Режим дешифрования | `--decrypt` |
| `--key` | Ключ шифрования (16 байт в hex) | `--key 00112233445566778899aabbccddeeff` |
| `--input` | Входной файл | `--input data.txt` |
| `--output` | Выходной файл | `--output result.bin` |
| `--iv` | Вектор инициализации для дешифрования | `--iv aabbccddeeff00112233445566778899` |

*Требуется указать ровно один из флагов `--encrypt` или `--decrypt`

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

## Технические детали

### Алгоритм: AES-128

- Размер блока: 16 байт
- Размер ключа: 16 байт (128 бит)
- Количество раундов: 10

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

### Пример 1: Базовое шифрование и дешифрование

```bash
# Создание тестового файла
echo "What's up, guys?" > secret.txt

# Шифрование в режиме CBC
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output secret.enc

# Дешифрование (IV читается из файла)
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.enc --output secret_decrypted.txt
```

### Пример 2: Работа с разными режимами

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

### Пример 3: Автоматические имена файлов

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

### Пример 4: Работа с бинарными файлами

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

CryptoCore полностью совместим с OpenSSL для всех режимов шифрования.

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

## Структура проекта

```
CryptoCore/
├── src/                # Исходный код
│   ├── main.go         # Точка входа
│   ├── cli_parser.go   # Парсинг аргументов
│   ├── file_io.go      # Работа с файлами и IV
│   └── modes/          # Реализации режимов шифрования
│       ├── common.go   # Общие функции
│       ├── ecb.go      # Режим ECB
│       ├── cbc.go      # Режим CBC
│       ├── cfb.go      # Режим CFB
│       ├── ofb.go      # Режим OFB
│       └── ctr.go      # Режим CTR
├── Makefile            # Система сборки
├── go.mod              # Зависимости Go
└── README.md           # Документация
```
