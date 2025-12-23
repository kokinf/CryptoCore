# User Guide: CryptoCore

## Оглавление

1. [Введение](#введение)
2. [Установка](#установка)
3. [Быстрый старт](#быстрый-старт)
4. [Шифрование файлов](#шифрование-файлов)
5. [Дешифрование файлов](#дешифрование-файлов)
6. [Хеширование файлов](#хеширование-файлов)
7. [HMAC: Проверка целостности](#hmac-проверка-целостности)
8. [Выработка ключей](#выработка-ключей)
9. [AEAD шифрование](#aead-шифрование)
10. [Безопасность и лучшие практики](#безопасность-и-лучшие-практики)
11. [Устранение проблем](#устранение-проблем)
12. [Шпаргалка команд](#шпаргалка-команд)

## Введение

CryptoCore - это криптографическая утилита командной строки, которая предоставляет профессиональные инструменты для шифрования, дешифрования, хеширования и проверки целостности данных. Утилита реализует современные криптографические стандарты и совместима с популярными инструментами, такими как OpenSSL.

### Основные возможности:
- **Шифрование/дешифрование** файлов с использованием AES-128
- **Шесть режимов работы**: ECB, CBC, CFB, OFB, CTR, GCM
- **AEAD режимы**: GCM и Encrypt-then-MAC с аутентификацией
- **Хеширование**: SHA-256 и SHA3-256
- **HMAC**: Проверка целостности сообщений
- **KDF**: PBKDF2-HMAC-SHA256 для выработки ключей из паролей
- **Безопасный ГСЧ**: Автоматическая генерация криптографически безопасных ключей и IV
- **Кросс-платформенность**: Работает на Windows, Linux и macOS

## Установка

### Требования:
- **Go 1.25+** - [официальный сайт](https://go.dev/doc/install)
- **Git** (для сборки из исходников) - [официальный сайт](https://git-scm.com/downloads)

### Сборка из исходников:

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/kokinf/CryptoCore
cd CryptoCore

# 2. Соберите проект
# Для Linux/macOS:
make build

# Для Windows:
go build -o cryptocore.exe ./src

```

## Быстрый старт

### Пример 1: Быстрое шифрование файла

```bash
# Шифрование с автоматической генерацией ключа
cryptocore --algorithm aes --mode gcm --encrypt \
  --input secret_document.txt \
  --output encrypted.bin

# Запишите сгенерированный ключ, который появится в консоли!
# Пример: Сгенерированный ключ: 6e420871b65f5404cd7fdee5c82bb4e9
```

### Пример 2: Проверка целостности файла

```bash
# Создайте HMAC для файла
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input important_file.iso \
  --output file.hmac

# Проверьте позже, не изменился ли файл
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input important_file.iso \
  --verify file.hmac
# Если файл не изменился: [OK] HMAC verification successful
```

### Пример 3: Создание ключа из пароля

```bash
# Создайте ключ из пароля для шифрования базы данных
cryptocore derive --password "MySecurePassword123!" \
  --iterations 100000 \
  --length 32 \
  --output database_key.bin

# Используйте созданный ключ для шифрования
DATABASE_KEY=$(cat database_key.bin | xxd -p)
cryptocore --algorithm aes --mode cbc --encrypt \
  --key $DATABASE_KEY \
  --input database.sql \
  --output database.enc
```

## Шифрование файлов

### Выбор режима шифрования

| Режим | Описание | Padding | Рекомендации |
|-------|----------|---------|--------------|
| **ECB** | Каждый блок шифруется независимо | Да | Только для случайных данных |
| **CBC** | Цепочка блоков | Да | Для большинства файлов |
| **CFB** | Потоковый режим | Нет | Для потоковых данных |
| **OFB** | Потоковый режим | Нет | Для чувствительных к задержкам данных |
| **CTR** | Режим счетчика | Нет | Для параллельной обработки |
| **GCM** | AEAD с аутентификацией | Нет | Для максимальной безопасности |

### Базовое шифрование с указанием ключа

```bash
# ECB (простой режим, не для структурированных данных)
cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt \
  --output ciphertext.bin

# CBC (рекомендуется для большинства случаев)
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input document.pdf \
  --output encrypted.pdf.bin

# CTR (потоковый, не требует padding)
cryptocore --algorithm aes --mode ctr --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input video.mp4 \
  --output video.enc
```

### Шифрование с автоматической генерацией ключа

```bash
# Ключ будет сгенерирован и показан в консоли
cryptocore --algorithm aes --mode cbc --encrypt \
  --input financial_report.xlsx \
  --output report.enc

# Пример вывода:
# Ключ не указан, будет сгенерирован автоматически
# Сгенерированный ключ: 6e420871b65f5404cd7fdee5c82bb4e9
# Operation completed successfully: financial_report.xlsx -> report.enc

# Обязательно сохраните сгенерированный ключ!
```

### Формат ключей:
- **16 байт (32 hex символа)**: `000102030405060708090a0b0c0d0e0f`
- **24 байта (48 hex символов)**: `000102...1a1b1c1d1e1f202122232425`
- **32 байта (64 hex символа)**: `000102...3c3d3e3f4041424344454647`
- **48 байт (96 hex символов)**: Для Encrypt-then-MAC

### Автоматические имена файлов

Если не указать `--output`, утилита создаст имя автоматически:

```bash
# Создаст: plaintext_cbc.enc
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt

# Создаст: ciphertext.bin.dec
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin
```

## Дешифрование файлов

### Стандартное дешифрование

```bash
# ECB дешифрование
cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin \
  --output decrypted.txt

# CBC дешифрование с автоматическим чтением IV из файла
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input encrypted.bin \
  --output original.txt

# CBC дешифрование с указанием IV
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext_only.bin \
  --output plaintext.txt
```

### Форматы файлов при дешифровании

```
# Для ECB (без IV):
[шифротекст]

# Для CBC/CFB/OFB/CTR (IV в файле):
[16 байт IV][шифротекст]

# Для GCM:
[12 байт nonce][шифротекст][16 байт тег]

# Для Encrypt-then-MAC:
[16 байт IV][шифротекст][32 байт HMAC]  # или без IV для ECB
```

### Дешифрование с указанием IV

Если IV не указан и не находится в начале файла, произойдет ошибка:

```bash
# НЕПРАВИЛЬНО: IV не указан и не в файле
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext_without_iv.bin \
  --output plaintext.txt
# Ошибка: файл слишком короткий для извлечения IV

# ПРАВИЛЬНО: Укажите IV
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext_without_iv.bin \
  --output plaintext.txt
```

## Хеширование файлов

### Базовое хеширование

```bash
# SHA-256 хеш файла
cryptocore dgst --algorithm sha256 --input document.pdf

# Пример вывода:
# 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5 document.pdf

# SHA3-256 хеш файла
cryptocore dgst --algorithm sha3-256 --input backup.tar

# Сохранение хеша в файл
cryptocore dgst --algorithm sha256 --input important.iso --output checksum.sha256
```

### Проверка целостности

```bash
# 1. Вычислите хеш оригинального файла
cryptocore dgst --algorithm sha256 --input original_file.zip --output original.sha256

# 2. После передачи/хранения проверьте
cryptocore dgst --algorithm sha256 --input received_file.zip > received.sha256

# 3. Сравните
diff original.sha256 received.sha256
# Если diff ничего не выводит, файлы идентичны

# Или сравните вручную
cat original.sha256
# 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5 original_file.zip

cat received.sha256
# 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5 received_file.zip
```

### Совместимость с другими утилитами

```bash
# CryptoCore SHA-256
cryptocore dgst --algorithm sha256 --input file.txt

# Linux/Mac sha256sum
sha256sum file.txt

# Windows certutil
certutil -hashfile file.txt SHA256

# Все три команды должны давать одинаковый результат!
```

## HMAC: Проверка целостности

### Создание HMAC

HMAC (Hash-based Message Authentication Code) позволяет проверить как целостность данных, так и их аутентичность.

```bash
# Базовый HMAC
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt

# Сохранение HMAC в файл
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input firmware.bin \
  --output firmware.hmac
```

### Автоматическая проверка HMAC

```bash
# Проверка с использованием --verify
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt \
  --verify expected.hmac

# Если HMAC верный: [OK] HMAC verification successful
# Если HMAC неверный: Error: HMAC verification failed
```

### Ключи для HMAC

HMAC поддерживает ключи любой длины:

```bash
# Короткий ключ (4 байта)
cryptocore dgst --algorithm sha256 --hmac \
  --key aabbccdd \
  --input file.txt

# Длинный ключ (100 байт)
cryptocore dgst --algorithm sha256 --hmac \
  --key $(python3 -c "print('ff' * 100)") \
  --input large_file.bin

# Ключ из пароля (преобразовать в hex)
echo -n "MySecretPassword" | xxd -p
# 4d7953656372657450617373776f7264
cryptocore dgst --algorithm sha256 --hmac \
  --key 4d7953656372657450617373776f7264 \
  --input sensitive.txt
```

### Обнаружение изменений

```bash
# 1. Создайте HMAC для оригинала
echo "Важные данные" > original.txt
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input original.txt \
  --output original.hmac

# 2. Измените файл
echo "Подмененные данные" > original.txt

# 3. Попытка проверки провалится
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input original.txt \
  --verify original.hmac
# Error: HMAC verification failed
```

## Выработка ключей

### PBKDF2-HMAC-SHA256

PBKDF2 (Password-Based Key Derivation Function 2) преобразует пароль в криптографический ключ.

```bash
# Базовая выработка ключа
cryptocore derive --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32

# Пример вывода:
# 4cd8b5c46aee47f0d4a6a0dd7c205b1d30b54d2503c13fe7422e95ea312b7425 a1b2c3d4e5f601234567890123456789
# Формат: [КЛЮЧ_HEX] [СОЛЬ_HEX]
```

### Автоматическая генерация соли

```bash
# Соль будет сгенерирована автоматически
cryptocore derive --password "DatabaseEncryptionKey" \
  --iterations 500000 \
  --length 16

# Вывод:
# Соль не указана, будет сгенерирована случайная 16-байтная соль
# 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92 e3b0c44298fc1c149afbf4c8996fb924
```

### Сохранение ключа в файл

```bash
# Выработка и сохранение ключа
cryptocore derive --password "AppSecretKey" \
  --salt fixedappsalt \
  --iterations 10000 \
  --length 32 \
  --output app_key.bin

# Файл app_key.bin будет содержать:
# - Бинарный ключ (32 байта)
# - Также создастся app_key.bin.info с параметрами
```

### Проверка совместимости с Python

```bash
# Тест 1: Пароль "password", соль "salt", 1 итерация
cryptocore derive --password "password" \
  --salt 73616c74 \
  --iterations 1 \
  --length 20
# Ожидаемый результат: 120fb6cffcf8b32c43e7225256c4f837a86548c9 73616c74

# Python эквивалент:
python3 -c "
import hashlib, binascii
dk = hashlib.pbkdf2_hmac('sha256', b'password', 
                         b'salt', 1, dklen=20)
print(binascii.hexlify(dk).decode())
"
# 120fb6cffcf8b32c43e7225256c4f837a86548c9
```

### Практические примеры использования

```bash
# 1. Ключ для шифрования базы данных
cryptocore derive --password "DbAdmin@2024!" \
  --salt $(openssl rand -hex 16) \
  --iterations 200000 \
  --length 32 \
  --output db_key.bin

# 2. Ключ для шифрования бэкапов
BACKUP_KEY=$(cryptocore derive --password "BackupEncryption2024" \
  --salt "backup_system_v1" \
  --iterations 100000 \
  --length 32 | awk '{print $1}')

cryptocore --algorithm aes --mode gcm --encrypt \
  --key $BACKUP_KEY \
  --input backup.tar.gz \
  --output backup.enc

# 3. Ключ для API аутентификации
cryptocore derive --password "APISecretToken" \
  --salt "production_api_v2" \
  --iterations 50000 \
  --length 64 \
  --output api_token.bin
```

## AEAD шифрование

### GCM (Galois/Counter Mode)

GCM обеспечивает одновременную конфиденциальность и аутентификацию данных.

```bash
# Базовое шифрование GCM
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input sensitive.docx \
  --output encrypted.gcm

# Дешифрование GCM
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input encrypted.gcm \
  --output decrypted.docx
```

### GCM с AAD (Additional Authenticated Data)

AAD - это данные, которые аутентифицируются, но не шифруются.

```bash
# Шифрование с AAD
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input database.sql \
  --output database.gcm \
  --aad "db_name:production|version:3.2|encrypted:2024-12-19"

# Дешифрование с тем же AAD
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input database.gcm \
  --output database_decrypted.sql \
  --aad "db_name:production|version:3.2|encrypted:2024-12-19"
```

**Важно**: Если AAD не совпадает или шифротекст был изменен, дешифрование завершится ошибкой без вывода данных.

```bash
# Попытка дешифрования с неправильным AAD
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input database.gcm \
  --output output.sql \
  --aad "wrong_aad_data"
# Error: Authentication failed: AAD mismatch or ciphertext tampered
# Файл output.sql не будет создан
```

### Encrypt-then-MAC

Encrypt-then-MAC объединяет любое шифрование с HMAC для аутентификации.

```bash
# Создание 48-байтного ключа (16 для шифрования + 32 для MAC)
FULL_KEY="00112233445566778899aabbccddeeff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff"

# Шифрование в режиме CTR с ETM
cryptocore --algorithm aes --mode ctr --encrypt \
  --key $FULL_KEY \
  --input backup.tar \
  --output backup.etm

# Дешифрование с автоматической проверкой MAC
cryptocore --algorithm aes --mode ctr --decrypt \
  --key $FULL_KEY \
  --input backup.etm \
  --output restored.tar

# ETM также поддерживает AAD
cryptocore --algorithm aes --mode cbc --encrypt \
  --key $FULL_KEY \
  --input config.yaml \
  --output config.etm \
  --aad "environment:production"
```

### Форматы файлов AEAD

```
# GCM формат:
[12 байт nonce][шифротекст][16 байт тег]

# Encrypt-then-MAC формат (с IV):
[16 байт IV][шифротекст][32 байт HMAC]

# Encrypt-then-MAC формат (ECB):
[шифротекст][32 байт HMAC]
```

## Безопасность и лучшие практики

### Управление ключами

#### ✅ Рекомендуется:
```bash
# Генерация случайных ключей
openssl rand -hex 16  # 128-битный ключ
openssl rand -hex 32  # 256-битный ключ

# Хранение ключей в защищенных местах
export ENCRYPTION_KEY=$(openssl rand -hex 16)
# Используйте переменные окружения для временного хранения

# Регулярная ротация ключей
# Создавайте новый ключ каждые 90 дней для важных данных
```

#### ❌ Избегайте:
```bash
# Использования простых ключей
--key 00000000000000000000000000000000  # Слишком просто!
--key 0123456789abcdef0123456789abcdef  # Последовательный!

# Хранения ключей в скриптах
# ПЛОХО: ключ в открытом виде
ENCRYPTION_KEY="00112233445566778899aabbccddeeff"

# Переиспользования ключей для разных целей
# Используйте разные ключи для шифрования и аутентификации
```

### Выбор режима шифрования

| Сценарий использования | Рекомендуемый режим | Почему |
|----------------------|-------------------|--------|
| **Файлы баз данных** | GCM с AAD | Аутентификация + конфиденциальность |
| **Бэкапы** | CBC или CTR | Баланс скорости и безопасности |
| **Потоковые данные** | CFB или OFB | Не требует padding |
| **Случайные данные** | ECB | Простота, но только для случайных данных |
| **Максимальная безопасность** | GCM | AEAD с аутентификацией |
| **Совместимость с OpenSSL** | CBC | Наиболее распространенный |

### Безопасность паролей для KDF

```bash
# ✅ ХОРОШИЕ пароли:
--password "CorrectHorseBatteryStaple42!"  # Длинный, с символами
--password "Tr0ub4dor&3"                   # Умеренной сложности

# ❌ ПЛОХИЕ пароли:
--password "password123"                   # Слишком простой
--password "123456"                        # Очень короткий
--password "qwerty"                        | Распространенный

# Рекомендации по итерациям PBKDF2:
--iterations 100000    # Для рабочих нагрузок
--iterations 500000    # Для повышенной безопасности
--iterations 1000000   # Для максимальной защиты
```

### Использование соли в KDF

```bash
# ✅ ИСПОЛЬЗУЙТЕ соль:
--salt $(openssl rand -hex 16)  # Случайная соль
--salt "unique_per_user_$USER"  # Уникальная для пользователя

# ❔ Соль опциональна, но рекомендуется
# Без соли одинаковые пароли дадут одинаковые ключи!

# Минимальная длина соли: 8 байт
# Рекомендуемая длина соли: 16 байт
```

### Защита от атак

```bash
# 1. Всегда проверяйте аутентификацию перед дешифрованием
cryptocore --algorithm aes --mode gcm --decrypt \
  --key $KEY \
  --input data.gcm \
  --output /dev/null 2>/dev/null && echo "Аутентификация успешна"

# 2. Используйте разные ключи для разных целей
# Не используйте один ключ для шифрования файлов и HMAC

# 3. Регулярно обновляйте ключи
# Запланируйте ротацию ключей каждые 3-6 месяцев

# 4. Аудит и логирование
# Ведите журнал использования криптографических операций
```

### Лучшие практики для продакшена

```bash
#!/bin/bash
# Пример безопасного скрипта для продакшена

# 1. Генерация ключа
ENCRYPTION_KEY=$(openssl rand -hex 16)
echo "Ключ: $ENCRYPTION_KEY"
echo "Сохраните этот ключ в безопасном месте!"

# 2. Шифрование с GCM
cryptocore --algorithm aes --mode gcm --encrypt \
  --key $ENCRYPTION_KEY \
  --input production_data.json \
  --output encrypted.gcm \
  --aad "timestamp:$(date -Iseconds)|user:$USER"

# 3. Очистка ключа из памяти
unset ENCRYPTION_KEY

# 4. Проверка перед использованием
cryptocore --algorithm aes --mode gcm --decrypt \
  --key $STORED_KEY \
  --input encrypted.gcm \
  --output /dev/null 2>&1 | grep -q "successful" && \
  echo "Файл прошел проверку аутентификации"
```

## Устранение проблем

### Общие ошибки и решения

#### Ошибка: "некорректный формат ключа"
```bash
# ❌ НЕПРАВИЛЬНО: Нечетное количество символов
--key 00112233445566778899aabbccddeeff0

# ❌ НЕПРАВИЛЬНО: Не-hex символы
--key 00112233gg5566778899aabbccddeeff

# ✅ ПРАВИЛЬНО: 32 hex символа (16 байт)
--key 00112233445566778899aabbccddeeff
```

#### Ошибка: "файл слишком короткий для извлечения IV"
```bash
# Проблема: IV не найден в файле
cryptocore --algorithm aes --mode cbc --decrypt \
  --key $KEY \
  --input ciphertext_without_iv.bin

# Решение 1: Укажите IV явно
cryptocore --algorithm aes --mode cbc --decrypt \
  --key $KEY \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext_without_iv.bin

# Решение 2: Используйте правильный файл (с IV в начале)
```

#### Ошибка: "ошибка аутентификации"
```bash
# Для GCM/ETM: данные были изменены или неверный ключ/AAD

# 1. Проверьте ключ
echo "Ожидаемый ключ: $EXPECTED_KEY"
echo "Используемый ключ: $USED_KEY"

# 2. Проверьте AAD (для GCM/ETM с AAD)
echo "Ожидаемый AAD: $EXPECTED_AAD"
echo "Используемый AAD: $USED_AAD"

# 3. Проверьте целостность файла
ls -la encrypted.gcm
# Размер должен быть как минимум 28 байт (12 nonce + 16 tag)
```

#### Ошибка: "длина зашифрованных данных не кратна размеру блока"
```bash
# Для ECB/CBC: файл был поврежден или изменен

# Решение: Проверьте источник файла
# Перезапросите файл или проверьте целостность передачи

# Проверка размера файла
BLOCK_SIZE=16
FILE_SIZE=$(stat -f%z ciphertext.bin)
if [ $((FILE_SIZE % BLOCK_SIZE)) -ne 0 ]; then
    echo "Файл поврежден: размер $FILE_SIZE не кратен $BLOCK_SIZE"
fi
```

### Отладка проблем

#### Включение подробного вывода
```bash
# Добавьте отладочный вывод в скрипт
set -x  # Включить трассировку
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test.enc
set +x  # Выключить трассировку
```

#### Проверка параметров
```bash
# Создайте тестовый файл
echo "Test data" > test.txt

# Проверьте все режимы
for mode in ecb cbc cfb ofb ctr gcm; do
    echo "Тестирую режим: $mode"
    cryptocore --algorithm aes --mode $mode --encrypt \
      --key 00112233445566778899aabbccddeeff \
      --input test.txt --output test_$mode.enc 2>&1
    
    if [ $? -eq 0 ]; then
        echo "✅ $mode: Успешно"
    else
        echo "❌ $mode: Ошибка"
    fi
done
```

#### Сравнение с OpenSSL
```bash
# Проверка совместимости
# 1. Шифруем с CryptoCore
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input test.txt \
  --output crypto_core.bin

# 2. Шифруем с OpenSSL
openssl enc -aes-128-cbc \
  -K 000102030405060708090A0B0C0D0E0F \
  -iv 000102030405060708090a0b0c0d0e0f \
  -in test.txt \
  -out openssl.bin

# 3. Сравниваем (первые 32 байта должны совпадать)
dd if=crypto_core.bin bs=16 skip=1 count=2 | hexdump -C
dd if=openssl.bin bs=1 count=32 | hexdump -C
```

### Производительность

#### Тестирование скорости
```bash
# Создайте тестовый файл (100MB)
dd if=/dev/urandom of=test_100mb.bin bs=1M count=100

# Тест скорости шифрования
time cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_100mb.bin \
  --output /dev/null

# Тест скорости GCM
time cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_100mb.bin \
  --output /dev/null
```

#### Оптимизация KDF
```bash
# Тест различных итераций PBKDF2
for iterations in 1000 10000 100000 500000 1000000; do
    echo -n "Итераций: $iterations - "
    time cryptocore derive --password "test" \
      --salt 1234567890abcdef \
      --iterations $iterations \
      --length 32 > /dev/null 2>&1
done
```

### Восстановление после ошибок

#### Если потерян ключ
```bash
# Для шифрования с автоматической генерацией:
# Ключ выводится в консоль при шифровании
# Проверьте историю команд или логи:
history | grep cryptocore
journalctl -xe | grep "Сгенерированный ключ"

# Если ключ утерян и не был сохранен:
# Данные не могут быть восстановлены!
# Всегда сохраняйте ключи в безопасном месте.
```

#### Если поврежден файл
```bash
# Проверьте размер файла
FILE="encrypted.gcm"
EXPECTED_MIN_SIZE=28  # 12 nonce + 16 tag

if [ $(stat -f%z "$FILE") -lt $EXPECTED_MIN_SIZE ]; then
    echo "Файл поврежден: слишком маленький"
    
    # Попробуйте восстановить из бэкапа
    if [ -f "${FILE}.bak" ]; then
        echo "Восстанавливаю из бэкапа..."
        cp "${FILE}.bak" "$FILE"
    fi
fi
```

## Шпаргалка команд

### Быстрый доступ

```bash
# Шифрование
cryptocore --algorithm aes --mode MODE --encrypt --key HEX_KEY --input FILE --output FILE

# Дешифрование  
cryptocore --algorithm aes --mode MODE --decrypt --key HEX_KEY --input FILE --output FILE

# Хеширование
cryptocore dgst --algorithm sha256 --input FILE

# HMAC
cryptocore dgst --algorithm sha256 --hmac --key HEX_KEY --input FILE

# Выработка ключа
cryptocore derive --password PASSWORD --salt HEX_SALT --iterations N --length N
```

### Режимы шифрования (--mode)

| Режим | Описание | Padding | IV | Пример |
|-------|----------|---------|----|--------|
| `ecb` | Electronic Codebook | Да | Нет | `--mode ecb` |
| `cbc` | Cipher Block Chaining | Да | 16B | `--mode cbc` |
| `cfb` | Cipher Feedback | Нет | 16B | `--mode cfb` |
| `ofb` | Output Feedback | Нет | 16B | `--mode ofb` |
| `ctr` | Counter | Нет | 16B | `--mode ctr` |
| `gcm` | Galois/Counter Mode | Нет | 12B | `--mode gcm` |

### Ключи (--key)

| Назначение | Длина | Пример |
|------------|-------|--------|
| AES-128 | 16 байт (32 hex) | `00112233445566778899aabbccddeeff` |
| AES-192 | 24 байта (48 hex) | `001122...1a1b1c1d1e1f202122232425` |
| AES-256 | 32 байта (64 hex) | `001122...3c3d3e3f4041424344454647` |
| ETM | 48 байт (96 hex) | `001122...5c5d5e5f6061626364656667` |

### Параметры KDF (derive)

| Параметр | По умолчанию | Пример |
|----------|--------------|--------|
| `--password` | (обязательно) | `--password "MyPass123!"` |
| `--salt` | (автогенерация) | `--salt a1b2c3d4e5f60123` |
| `--iterations` | 100000 | `--iterations 500000` |
| `--length` | 32 | `--length 16` |
| `--output` | stdout | `--output key.bin` |
