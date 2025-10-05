# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в режиме ECB

## Возможности

-  Шифрование и дешифрование файлов с помощью AES-128
-  Поддержка режима ECB (Electronic Codebook)
-  Автоматическое добавление и удаление padding по стандарту PKCS#7
-  Работа с бинарными и текстовыми файлами
-  Кроссплатформенная сборка (Windows, Linux, macOS)
-  Подробная обработка ошибок и валидация входных данных
-  Автогенерация имен выходных файлов

## Инструкции по сборке

### Требования
- Git -[Установить Git](https://git-scm.com/downloads)
- Go 1.25.1+ -[Установить Golang](https://go.dev/doc/install)


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

- **Go 1.21+** - язык программирования и среда выполнения
- **Стандартная библиотека Go** - внешние зависимости не требуются
- **OpenSSL** (опционально) - для верификации результатов шифрования

## Использование

### Базовое использование
```bash
# Шифрование файла
./cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt --output ciphertext.bin

# Дешифрование файла
./cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin --output decrypted.txt
```

## Аргументы командной строки

| Аргумент | Описание | Пример |
|----------|-----------|---------|
| `--algorithm` | Алгоритм шифрования (только `aes`) | `--algorithm aes` |
| `--mode` | Режим работы (только `ecb`) | `--mode ecb` |
| `--encrypt` | Режим шифрования | `--encrypt` |
| `--decrypt` | Режим дешифрования | `--decrypt` |
| `--key` | Ключ шифрования (16 байт в hex) | `--key 00112233445566778899aabbccddeeff` |
| `--input` | Входной файл | `--input data.txt` |
| `--output` | Выходной файл | `--output result.bin` |

*Требуется указать ровно один из флагов `--encrypt` или `--decrypt`

## Режимы шифрования

### ECB (Electronic Codebook)
- Каждый блок шифруется независимо
- Простая реализация
- Подходит для шифрования случайных данных
- **Внимание**: Не рекомендуется для шифрования структурированных данных из-за уязвимостей к анализу шаблонов

## Технические детали

### Алгоритм: AES-128
- Размер блока: 16 байт
- Размер ключа: 16 байт (128 бит)
- Количество раундов: 10

### Padding: PKCS#7
- Автоматическое добавление байтов заполнения
- Размер padding: от 1 до 16 байт
- Автоматическое удаление при дешифровании

### Формат ключа
- 32 символа в шестнадцатеричном формате
- Пример: `000102030405060708090a0b0c0d0e0f`

## Примеры использования

### Пример 1: Базовое шифрование и дешифрование
```bash
# Создание тестового файла
echo "всем привет!!" > secret.txt

# Шифрование
./cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.txt --output secret.enc

# Дешифрование
./cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input secret.enc --output secret_decrypted.txt
```

### Пример 2: Автоматические имена файлов
```bash
# Шифрование с автоматическим именем файла (создаст document.txt.enc)
./cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input document.txt

# Дешифрование с автоматическим именем файла (создаст document.dec.txt)
./cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input document.txt.enc
```

### Пример 3: Работа с бинарными файлами
```bash
# Шифрование бинарного файла
./cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input image.jpg --output image_encrypted.bin

# Дешифрование обратно
./cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input image_encrypted.bin --output image_restored.jpg
```

## Структура проекта
```
CryptoCore/
├── src/                # Исходный код
│   ├── main.go         # Точка входа
│   ├── cli_parser.go   # Парсинг аргументов
│   ├── file_io.go      # Работа с файлами
│   └── modes/
│       └── ecb.go      # Реализация ECB
├── Makefile            # Система сборки
├── go.mod              # Зависимости Go
└── README.md           # Документация
```