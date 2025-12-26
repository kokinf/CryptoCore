package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

func CFBEncryptWithIV(plaintext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("некорректная длина IV")
	}

	ciphertext := make([]byte, len(plaintext))

	encrypter := &cfbEncrypter{
		block:     block,
		iv:        make([]byte, len(iv)),
		keystream: make([]byte, aes.BlockSize),
		pos:       aes.BlockSize,
	}
	copy(encrypter.iv, iv)

	encrypter.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func CFBDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("некорректная длина IV")
	}

	plaintext := make([]byte, len(ciphertext))

	decrypter := &cfbDecrypter{
		block:     block,
		iv:        make([]byte, len(iv)),
		keystream: make([]byte, aes.BlockSize),
		pos:       aes.BlockSize,
	}
	copy(decrypter.iv, iv)

	decrypter.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

type cfbEncrypter struct {
	block     cipher.Block
	iv        []byte
	keystream []byte
	pos       int
}

func (x *cfbEncrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("буфер назначения слишком мал")
	}

	for i := 0; i < len(src); i++ {
		if x.pos >= aes.BlockSize {
			x.block.Encrypt(x.keystream, x.iv)
			x.pos = 0
		}

		dst[i] = src[i] ^ x.keystream[x.pos]

		copy(x.iv, x.iv[1:])
		x.iv[aes.BlockSize-1] = dst[i]
		x.pos++
	}
}

type cfbDecrypter struct {
	block     cipher.Block
	iv        []byte
	keystream []byte
	pos       int
}

func (x *cfbDecrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("буфер назначения слишком мал")
	}

	for i := 0; i < len(src); i++ {
		if x.pos >= aes.BlockSize {
			x.block.Encrypt(x.keystream, x.iv)
			x.pos = 0
		}

		ciphertextByte := src[i]

		dst[i] = ciphertextByte ^ x.keystream[x.pos]

		copy(x.iv, x.iv[1:])
		x.iv[aes.BlockSize-1] = ciphertextByte
		x.pos++
	}
}

// Потоковое CFB шифрование
func streamCFBEncrypt(reader io.Reader, writer io.Writer, block cipher.Block, iv []byte) error {
	if len(iv) != aes.BlockSize {
		return errors.New("некорректная длина IV")
	}

	encrypter := &cfbEncrypter{
		block:     block,
		iv:        make([]byte, len(iv)),
		keystream: make([]byte, aes.BlockSize),
		pos:       aes.BlockSize,
	}
	copy(encrypter.iv, iv)

	buffer := make([]byte, 8192)
	outputBuffer := make([]byte, 8192)

	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if n > 0 {
			encrypter.XORKeyStream(outputBuffer[:n], buffer[:n])
			if _, err := writer.Write(outputBuffer[:n]); err != nil {
				return err
			}
		}
	}

	return nil
}

// Потоковое CFB дешифрование
func streamCFBDecrypt(reader io.Reader, writer io.Writer, block cipher.Block, iv []byte) error {
	if len(iv) != aes.BlockSize {
		return errors.New("некорректная длина IV")
	}

	decrypter := &cfbDecrypter{
		block:     block,
		iv:        make([]byte, len(iv)),
		keystream: make([]byte, aes.BlockSize),
		pos:       aes.BlockSize,
	}
	copy(decrypter.iv, iv)

	buffer := make([]byte, 8192)
	outputBuffer := make([]byte, 8192)

	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if n > 0 {
			decrypter.XORKeyStream(outputBuffer[:n], buffer[:n])
			if _, err := writer.Write(outputBuffer[:n]); err != nil {
				return err
			}
		}
	}

	return nil
}
