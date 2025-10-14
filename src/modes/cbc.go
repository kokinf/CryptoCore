package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type cbcEncrypter struct {
	block cipher.Block
	iv    []byte
	tmp   []byte
}

func newCBCEncrypter(block cipher.Block, iv []byte) *cbcEncrypter {
	if len(iv) != block.BlockSize() {
		panic("IV должен быть равен размеру блока")
	}

	return &cbcEncrypter{
		block: block,
		iv:    iv,
		tmp:   make([]byte, block.BlockSize()),
	}
}

func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%aes.BlockSize != 0 {
		panic("исходные данные не кратны размеру блока")
	}
	if len(dst) < len(src) {
		panic("буфер назначения слишком мал")
	}

	iv := x.iv

	for i := 0; i < len(src); i += aes.BlockSize {
		for j := 0; j < aes.BlockSize; j++ {
			x.tmp[j] = src[i+j] ^ iv[j]
		}

		x.block.Encrypt(dst[i:], x.tmp)

		iv = dst[i : i+aes.BlockSize]
	}
}

type cbcDecrypter struct {
	block cipher.Block
	iv    []byte
	tmp   []byte
}

func newCBCDecrypter(block cipher.Block, iv []byte) *cbcDecrypter {
	if len(iv) != block.BlockSize() {
		panic("IV должен быть равен размеру блока")
	}

	return &cbcDecrypter{
		block: block,
		iv:    iv,
		tmp:   make([]byte, block.BlockSize()),
	}
}

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%aes.BlockSize != 0 {
		panic("исходные данные не кратны размеру блока")
	}
	if len(dst) < len(src) {
		panic("буфер назначения слишком мал")
	}

	iv := x.iv

	for i := 0; i < len(src); i += aes.BlockSize {
		x.block.Decrypt(x.tmp, src[i:i+aes.BlockSize])

		for j := 0; j < aes.BlockSize; j++ {
			dst[i+j] = x.tmp[j] ^ iv[j]
		}

		iv = src[i : i+aes.BlockSize]
	}
}

func CBCEncrypt(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, nil, err
	}

	iv, err := GenerateRandomIV()
	if err != nil {
		return nil, nil, err
	}

	paddedPlaintext := PKCS7Pad(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(paddedPlaintext))

	mode := newCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, iv, nil
}

func CBCDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("длина зашифрованных данных не кратна размеру блока")
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("некорректная длина IV")
	}

	plaintext := make([]byte, len(ciphertext))

	mode := newCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpaddedPlaintext, err := PKCS7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return unpaddedPlaintext, nil
}
