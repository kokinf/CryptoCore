package modes

import (
	"crypto/aes"
	"errors"
)

func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

// ECB(enc)
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

// ECB(dec)
func ECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("ciphertext length is not multiple of block size")
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
