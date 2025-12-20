package main

import (
	"cryptocore/src/aead"
	"cryptocore/src/csprng"
	"fmt"
	"os"
)

func main() {
	fmt.Println("Тесты безопасности Encrypt-then-MAC")

	tests := []struct {
		name string
		test func() error
	}{
		{"TestETMAADTamper", testETMAADTamper},
		{"TestETMCiphertextTamper", testETMCiphertextTamper},
		{"TestETMTagTamper", testETMTagTamper},
		{"TestETMModeConsistency", testETMModeConsistency},
		{"TestETMWrongKey", testETMWrongKey},
		{"TestETMVerifyBeforeDecrypt", testETMVerifyBeforeDecrypt},
		{"TestETMEmptyMessage", testETMEmptyMessage},
	}

	passed := 0
	failed := 0

	for _, tc := range tests {
		fmt.Printf("\nТест: %s\n", tc.name)
		err := tc.test()
		if err != nil {
			fmt.Printf("%s FAILED: %v\n", tc.name, err)
			failed++
		} else {
			fmt.Printf("%s PASSED\n", tc.name)
			passed++
		}
	}

	fmt.Printf("Итог: %d тестов пройдено, %d тестов провалено\n", passed, failed)

	if failed > 0 {
		os.Exit(1)
	}
}

func testETMAADTamper() error {
	fmt.Println("   Encrypt-then-MAC с неверным AAD должен вызывать ошибку аутентификации")

	masterKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Secret ETM message")
	aadCorrect := []byte("correct_aad")
	aadWrong := []byte("wrong_aad")

	// Зашифровать с правильным AAD (режим CBC)
	etm, err := aead.NewEncryptThenMac(masterKey, "cbc")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM: %v", err)
	}

	ciphertext, err := etm.Encrypt(plaintext, aadCorrect)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ETM: %v", err)
	}

	// Попытаться дешифровать с неверным AAD
	etm2, err := aead.NewEncryptThenMac(masterKey, "cbc")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM2: %v", err)
	}

	// Должна быть ошибка аутентификации
	_, err = etm2.Decrypt(ciphertext, aadWrong)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с неверным AAD")
	}

	// Проверяем, что ошибка именно аутентификации
	if err.Error() != "ошибка аутентификации: неверный MAC" {
		return fmt.Errorf("ожидалась ошибка аутентификации, получено: %v", err)
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с неверным AAD")
	return nil
}

func testETMCiphertextTamper() error {
	fmt.Println("   Подмена шифртекста ETM должна вызывать ошибку аутентификации")

	masterKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Another ETM secret message")
	aad := []byte("associated_data")

	// Зашифровать (режим CTR)
	etm, err := aead.NewEncryptThenMac(masterKey, "ctr")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM: %v", err)
	}

	ciphertext, err := etm.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ETM: %v", err)
	}

	// Подменить данные до тега (изменить один байт в ciphertext)
	if len(ciphertext) < 64 { // Нужно место для IV + ciphertext + tag
		return fmt.Errorf("ciphertext слишком короткий для теста подмены")
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// Изменяем байт в середине ciphertext (после IV, перед tag)
	tamperPos := 20 // После IV (16 байт) плюс немного
	if tamperPos >= len(ciphertext)-32 {
		tamperPos = len(ciphertext) - 40 // Убедимся что не трогаем tag
	}
	tampered[tamperPos] ^= 0x01

	// Попытаться дешифровать подмененный шифртекст
	etm2, err := aead.NewEncryptThenMac(masterKey, "ctr")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM2: %v", err)
	}

	_, err = etm2.Decrypt(tampered, aad)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с подмененным шифртекстом")
	}

	// Проверяем, что ошибка именно аутентификации
	if err.Error() != "ошибка аутентификации: неверный MAC" {
		return fmt.Errorf("ожидалась ошибка аутентификации, получено: %v", err)
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с подмененным шифртекстом")
	return nil
}

func testETMTagTamper() error {
	fmt.Println("   Подмена тега ETM должна вызывать ошибку аутентификации")

	masterKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Message with ETM tag")
	aad := []byte("tag_test_aad")

	// Зашифровать (режим CFB)
	etm, err := aead.NewEncryptThenMac(masterKey, "cfb")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM: %v", err)
	}

	ciphertext, err := etm.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ETM: %v", err)
	}

	// Подменить тег (последние 32 байта)
	if len(ciphertext) < 32 {
		return fmt.Errorf("ciphertext слишком короткий")
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// Изменяем последний байт тега
	tampered[len(tampered)-1] ^= 0xFF

	// Попытаться дешифровать
	etm2, err := aead.NewEncryptThenMac(masterKey, "cfb")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM2: %v", err)
	}

	_, err = etm2.Decrypt(tampered, aad)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с подмененным тегом")
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с подмененным тегом")
	return nil
}

func testETMModeConsistency() error {
	fmt.Println("   Encrypt-then-MAC со всеми режимами")

	masterKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Test message for all modes")
	aad := []byte("test_aad")

	modes := []string{"cbc", "cfb", "ofb", "ctr", "ecb"}

	for _, mode := range modes {
		fmt.Printf("   Тестирование режима %s... ", mode)

		// Шифрование
		etm, err := aead.NewEncryptThenMac(masterKey, mode)
		if err != nil {
			return fmt.Errorf("ошибка создания ETM для режима %s: %v", mode, err)
		}

		ciphertext, err := etm.Encrypt(plaintext, aad)
		if err != nil {
			return fmt.Errorf("ошибка шифрования ETM для режима %s: %v", mode, err)
		}

		// Дешифрование
		etm2, err := aead.NewEncryptThenMac(masterKey, mode)
		if err != nil {
			return fmt.Errorf("ошибка создания ETM2 для режима %s: %v", mode, err)
		}

		decrypted, err := etm2.Decrypt(ciphertext, aad)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования ETM для режима %s: %v", mode, err)
		}

		// Проверка
		if string(decrypted) != string(plaintext) {
			return fmt.Errorf("режим %s: декодированный текст не соответствует оригиналу", mode)
		}

		fmt.Println("✓")
	}
	return nil
}

func testETMWrongKey() error {
	fmt.Println("   Encrypt-then-MAC с неправильным ключом")

	correctKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации правильного ключа: %v", err)
	}

	wrongKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации неправильного ключа: %v", err)
	}

	plaintext := []byte("Key sensitivity test")
	aad := []byte("key_test_aad")

	// Шифруем с правильным ключом
	etmCorrect, err := aead.NewEncryptThenMac(correctKey, "cbc")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM с правильным ключом: %v", err)
	}

	ciphertext, err := etmCorrect.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования с правильным ключом: %v", err)
	}

	// Пробуем дешифровать с неправильным ключом
	etmWrong, err := aead.NewEncryptThenMac(wrongKey, "cbc")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM с неправильным ключом: %v", err)
	}

	_, err = etmWrong.Decrypt(ciphertext, aad)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с неправильным ключом")
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с неправильным ключом")
	return nil
}

func testETMVerifyBeforeDecrypt() error {
	fmt.Println("   Encrypt-then-MAC верифицирует перед дешифрованием")

	masterKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Verify before decrypt test")
	aad := []byte("verify_aad")

	// Шифруем
	etm, err := aead.NewEncryptThenMac(masterKey, "cbc")
	if err != nil {
		return fmt.Errorf("ошибка создания ETM: %v", err)
	}

	ciphertext, err := etm.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %v", err)
	}

	// Пробуем верифицировать с правильными данными
	verified, err := etm.Verify(ciphertext, aad)
	if err != nil {
		return fmt.Errorf("ошибка верификации: %v", err)
	}
	if !verified {
		return fmt.Errorf("верификация должна была пройти успешно")
	}

	// Портим данные и пробуем верифицировать
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[10] ^= 0x01

	verified, err = etm.Verify(tampered, aad)
	if err != nil {
		return fmt.Errorf("ошибка верификации поврежденных данных: %v", err)
	}
	if verified {
		return fmt.Errorf("верификация поврежденных данных должна была провалиться")
	}

	fmt.Println("   ✓ Верификация работает корректно")
	return nil
}

func testETMEmptyMessage() error {
	fmt.Println("   Encrypt-then-MAC с пустым сообщением")

	masterKey, err := csprng.GenerateRandomBytes(48)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte{}
	aad := []byte("empty_message_aad")

	// Тестируем все режимы
	for _, mode := range []string{"cbc", "cfb", "ofb", "ctr"} {
		fmt.Printf("   Тестирование режима %s... ", mode)

		etm, err := aead.NewEncryptThenMac(masterKey, mode)
		if err != nil {
			return fmt.Errorf("ошибка создания ETM для режима %s: %v", mode, err)
		}

		// Шифрование пустого сообщения
		ciphertext, err := etm.Encrypt(plaintext, aad)
		if err != nil {
			return fmt.Errorf("ошибка шифрования пустого сообщения (режим %s): %v", mode, err)
		}

		// Дешифрование
		etm2, err := aead.NewEncryptThenMac(masterKey, mode)
		if err != nil {
			return fmt.Errorf("ошибка создания ETM2 для режима %s: %v", mode, err)
		}

		decrypted, err := etm2.Decrypt(ciphertext, aad)
		if err != nil {
			return fmt.Errorf("ошибка дешифрования пустого сообщения (режим %s): %v", mode, err)
		}

		// Проверяем что получили пустое сообщение
		if len(decrypted) != 0 {
			return fmt.Errorf("режим %s: ожидалось пустое сообщение, получено %d байт", mode, len(decrypted))
		}

		fmt.Println("✓")
	}
	return nil
}
