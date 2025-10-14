package modes

import (
	"crypto/aes"
	"errors"
)

func ECBEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	paddedPlaintext := PKCS7Pad(plaintext, blockSize)

	ciphertext := make([]byte, len(paddedPlaintext))
	for i := 0; i < len(paddedPlaintext); i += blockSize {
		block.Encrypt(ciphertext[i:], paddedPlaintext[i:i+blockSize])
	}

	return ciphertext, nil
}

func ECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("длина зашифрованных данных не кратна размеру блока")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(plaintext[i:], ciphertext[i:i+blockSize])
	}

	unpaddedPlaintext, err := PKCS7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return unpaddedPlaintext, nil
}
