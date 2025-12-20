package main

import (
	"cryptocore/src/aead"
	"cryptocore/src/csprng"
	"fmt"
	"os"
)

func main() {
	fmt.Println("Запуск тестов безопасности GCM")

	tests := []struct {
		name string
		test func() error
	}{
		{"TestGCMAADTamper", testGCMAADTamper},
		{"TestGCMCiphertextTamper", testGCMCiphertextTamper},
		{"TestGCMTagTamper", testGCMTagTamper},
		{"TestGCMEmptyMessage", testGCMEmptyMessage},
		{"TestGCMRepeatedNonce", testGCMRepeatedNonce},
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

func testGCMAADTamper() error {
	fmt.Println("   GCM с неверным AAD должен вызывать ошибку аутентификации")

	key, err := csprng.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Secret message")
	aadCorrect := []byte("correct_aad")
	aadWrong := []byte("wrong_aad")

	// Зашифровать с правильным AAD
	gcm, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM: %v", err)
	}

	ciphertext, err := gcm.Encrypt(plaintext, aadCorrect)
	if err != nil {
		return fmt.Errorf("ошибка шифрования GCM: %v", err)
	}

	// Попытаться дешифровать с неверным AAD
	gcm2, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM2: %v", err)
	}

	// Должна быть ошибка аутентификации
	_, err = gcm2.Decrypt(ciphertext, aadWrong)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с неверным AAD")
	}

	// Проверяем, что ошибка именно аутентификации
	if err.Error() != "ошибка аутентификации: неверный тег" {
		return fmt.Errorf("ожидалась ошибка аутентификации, получено: %v", err)
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с неверным AAD")
	return nil
}

func testGCMCiphertextTamper() error {
	fmt.Println("   Подмена шифртекста GCM должна вызывать ошибку аутентификации")

	key, err := csprng.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Another secret message")
	aad := []byte("associated_data")

	// Зашифровать
	gcm, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM: %v", err)
	}

	ciphertext, err := gcm.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования GCM: %v", err)
	}

	// Подменить шифртекст (изменить один байт в середине ciphertext)
	if len(ciphertext) < 30 {
		return fmt.Errorf("ciphertext слишком короткий для теста подмены")
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[20] ^= 0x01 // Изменить один бит в шифртексте

	// Попытаться дешифровать подмененный шифртекст
	gcm2, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM2: %v", err)
	}

	_, err = gcm2.Decrypt(tampered, aad)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с подмененным шифртекстом")
	}

	// Проверяем, что ошибка именно аутентификации
	if err.Error() != "ошибка аутентификации: неверный тег" {
		return fmt.Errorf("ожидалась ошибка аутентификации, получено: %v", err)
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с подмененным шифртекстом")
	return nil
}

func testGCMTagTamper() error {
	fmt.Println("   Подмена тега GCM должна вызывать ошибку аутентификации")

	key, err := csprng.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte("Message with tag")
	aad := []byte("tag_test_aad")

	// Зашифровать
	gcm, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM: %v", err)
	}

	ciphertext, err := gcm.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования GCM: %v", err)
	}

	// Подменить тег (последние 16 байт)
	if len(ciphertext) < 16 {
		return fmt.Errorf("ciphertext слишком короткий")
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// Изменяем последний байт тега
	tampered[len(tampered)-1] ^= 0xFF

	// Попытаться дешифровать
	gcm2, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM2: %v", err)
	}

	_, err = gcm2.Decrypt(tampered, aad)
	if err == nil {
		return fmt.Errorf("дешифрование должно было завершиться неудачей с подмененным тегом")
	}

	fmt.Println("   ✓ Корректно завершилось неудачей с подмененным тегом")
	return nil
}

func testGCMEmptyMessage() error {
	fmt.Println("   GCM с пустым сообщением")

	key, err := csprng.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext := []byte{}
	aad := []byte("empty_message_aad")

	gcm, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM: %v", err)
	}

	// Шифрование пустого сообщения
	ciphertext, err := gcm.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования пустого сообщения: %v", err)
	}

	// Дешифрование
	gcm2, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM2: %v", err)
	}

	decrypted, err := gcm2.Decrypt(ciphertext, aad)
	if err != nil {
		return fmt.Errorf("ошибка дешифрования пустого сообщения: %v", err)
	}

	// Проверяем что получили пустое сообщение
	if len(decrypted) != 0 {
		return fmt.Errorf("ожидалось пустое сообщение, получено %d байт", len(decrypted))
	}

	fmt.Println("   ✓ Пустое сообщение корректно обрабатывается")
	return nil
}

func testGCMRepeatedNonce() error {
	fmt.Println("   Использование одного nonce дважды в GCM")

	key, err := csprng.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	plaintext1 := []byte("First message")
	plaintext2 := []byte("Second message")
	aad := []byte("test_aad")

	// Создаем GCM с конкретным nonce
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	gcm1, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM1: %v", err)
	}
	if err := gcm1.SetNonce(nonce); err != nil {
		return fmt.Errorf("ошибка установки nonce: %v", err)
	}

	gcm2, err := aead.NewGCM(key)
	if err != nil {
		return fmt.Errorf("ошибка создания GCM2: %v", err)
	}
	if err := gcm2.SetNonce(nonce); err != nil {
		return fmt.Errorf("ошибка установки nonce: %v", err)
	}

	// Шифруем два разных сообщения с одним nonce
	ciphertext1, err := gcm1.Encrypt(plaintext1, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования первого сообщения: %v", err)
	}

	ciphertext2, err := gcm2.Encrypt(plaintext2, aad)
	if err != nil {
		return fmt.Errorf("ошибка шифрования второго сообщения: %v", err)
	}

	// Проверяем что ciphertexts разные
	if string(ciphertext1) == string(ciphertext2) {
		return fmt.Errorf("ciphertexts должны быть разными при разных сообщениях")
	}

	fmt.Println("   ✓ Разные сообщения с одинаковым nonce производят разные ciphertexts")
	return nil
}
