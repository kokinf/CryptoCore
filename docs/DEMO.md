# Демонстрация работы cryptocore
```
git clone https://github.com/kokinf/CryptoCore

cd CryptoCore

make
```
## 1. Создание тестового файла

```bash
echo -n "HELP" > test.txt
```

Создаёт файл `test.txt` с содержимым "HELP" (без символа новой строки).

## 2. Шифрование файла с автоматической генерацией ключа

```bash
./cryptocore --algorithm aes --mode cbc --encrypt --input test.txt --output DECFILE.bin
```

Шифрует файл `test.txt` алгоритмом AES в режиме CBC и сохраняет результат в `DECFILE.bin`. Ключ генерируется автоматически и отображается в выводе.

## 3. Расшифрование файла с указанием ключа

```bash
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 06b4c536b16961d9b8f4e35664da88da \
  --input DECFILE.bin --output FILE.txt
```

Расшифровывает файл `DECFILE.bin` с использованием указанного ключа и сохраняет результат в `FILE.txt`.

## 4. Вычисление хеша SHA-256

```bash
./cryptocore dgst --algorithm sha256 --input FILE.txt
```

Ожидаемый вывод:
```
74b8978c760eaf4ecb45deeb701d9b51c0c45ff4f28d7efcddf2b9653564bc1c  FILE.txt
```

## 5. Проверка с помощью стандартной утилиты

```bash
sha256sum FILE.txt
```

Должен показать тот же хеш, что и в предыдущей команде.

## 6. Вычисление хеша SHA3-256

```bash
./cryptocore dgst --algorithm sha3-256 --input FILE.txt
```

## 7. Проверка с помощью стандартной утилиты

```bash
sha3sum -a 256 FILE.txt
```

Должен показать тот же хеш, что и в предыдущей команде.

## 8. Генерация ключа из пароля

```bash
./cryptocore derive --password "test" --salt 1234567890abcdef --length 32
```

Генерирует 32-байтный ключ из пароля "test" и соли "1234567890abcdef" с использованием PBKDF2.

## 9. Шифрование в режиме GCM

```bash
./cryptocore --algorithm aes --mode gcm --encrypt --input FILE.txt --output encrypted.bin
```

Шифрует файл `FILE.txt` алгоритмом AES в режиме GCM (с аутентификацией) и сохраняет результат в `encrypted.bin`.

## 10. Расшифрование в режиме GCM

```bash
./cryptocore --algorithm aes --mode gcm --decrypt --key ffa86b3fb8ea540af7442719beb33978 --input encrypted.bin --output decrypted.txt
```

Расшифровывает файл `encrypted.bin` с использованием указанного ключа и проверяет аутентификацию.

## 11. Запуск тестов
```
cd tests

go test -v ./unit/
```