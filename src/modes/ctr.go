package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type ctr struct {
	block     cipher.Block
	counter   []byte
	keystream []byte
	pos       int
}

func newCTR(block cipher.Block, iv []byte) *ctr {
	if len(iv) != aes.BlockSize {
		panic("IV должен быть длиной 16 байт")
	}

	counter := make([]byte, aes.BlockSize)
	copy(counter, iv)

	return &ctr{
		block:     block,
		counter:   counter,
		keystream: make([]byte, aes.BlockSize),
		pos:       aes.BlockSize,
	}
}

// incrementCounter увеличивает счетчик на 1
func (x *ctr) incrementCounter() {
	for i := aes.BlockSize - 1; i >= 0; i-- {
		x.counter[i]++
		if x.counter[i] != 0 {
			break
		}
	}
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("буфер назначения слишком мал")
	}

	for i := 0; i < len(src); i++ {
		if x.pos >= aes.BlockSize {
			x.block.Encrypt(x.keystream, x.counter)
			x.incrementCounter()
			x.pos = 0
		}

		dst[i] = src[i] ^ x.keystream[x.pos]
		x.pos++
	}
}

func CTREncryptWithIV(plaintext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("некорректная длина IV")
	}

	ciphertext := make([]byte, len(plaintext))

	mode := newCTR(block, iv)
	mode.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func CTRDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("некорректная длина IV")
	}

	plaintext := make([]byte, len(ciphertext))

	mode := newCTR(block, iv)
	mode.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
