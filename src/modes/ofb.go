package modes

import (
	"crypto/aes"
	"crypto/cipher"
)

type ofb struct {
	block     cipher.Block
	state     []byte
	keystream []byte
	pos       int
}

func newOFB(block cipher.Block, iv []byte) *ofb {
	if len(iv) != aes.BlockSize {
		panic("IV должен быть длиной 16 байт")
	}

	state := make([]byte, aes.BlockSize)
	copy(state, iv)

	return &ofb{
		block:     block,
		state:     state,
		keystream: make([]byte, aes.BlockSize),
		pos:       aes.BlockSize,
	}
}

func (x *ofb) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("буфер назначения слишком мал")
	}

	for i := 0; i < len(src); i++ {
		if x.pos >= aes.BlockSize {
			x.block.Encrypt(x.keystream, x.state)
			copy(x.state, x.keystream)
			x.pos = 0
		}

		dst[i] = src[i] ^ x.keystream[x.pos]
		x.pos++
	}
}

func OFBEncrypt(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, nil, err
	}

	iv, err := GenerateRandomIV()
	if err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	stream := newOFB(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, iv, nil
}

func OFBDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	stream := newOFB(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
