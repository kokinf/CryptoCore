package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
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

func CBCEncryptWithIV(plaintext, key, iv []byte) ([]byte, error) {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("некорректная длина IV")
	}

	paddedPlaintext := PKCS7Pad(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(paddedPlaintext))

	mode := newCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, nil
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

// Потоковое CBC шифрование
func streamCBCEncrypt(reader io.Reader, writer io.Writer, block cipher.Block, iv []byte) error {
	if len(iv) != block.BlockSize() {
		return errors.New("некорректная длина IV")
	}

	blockSize := block.BlockSize()
	buffer := make([]byte, blockSize)
	temp := make([]byte, blockSize)
	encryptedBlock := make([]byte, blockSize)

	currentIV := make([]byte, blockSize)
	copy(currentIV, iv)

	var lastBlock []byte
	eof := false

	for !eof {
		n, err := io.ReadFull(reader, buffer)
		if err == io.EOF {
			break
		} else if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}

		if n < blockSize {
			// Последний неполный блок
			paddedBlock := PKCS7Pad(buffer[:n], blockSize)

			// XOR с IV и шифрование
			for i := 0; i < blockSize; i++ {
				temp[i] = paddedBlock[i] ^ currentIV[i]
			}
			block.Encrypt(encryptedBlock, temp)

			lastBlock = encryptedBlock
			eof = true
		} else {
			// Полный блок
			for i := 0; i < blockSize; i++ {
				temp[i] = buffer[i] ^ currentIV[i]
			}
			block.Encrypt(encryptedBlock, temp)

			if _, err := writer.Write(encryptedBlock); err != nil {
				return err
			}

			// Обновляем IV
			copy(currentIV, encryptedBlock)
		}
	}

	// Записываем последний блок с padding если нужно
	if lastBlock != nil {
		if _, err := writer.Write(lastBlock); err != nil {
			return err
		}
	}

	return nil
}

// Потоковое CBC дешифрование
func streamCBCDecrypt(reader io.Reader, writer io.Writer, block cipher.Block, iv []byte) error {
	if len(iv) != block.BlockSize() {
		return errors.New("некорректная длина IV")
	}

	blockSize := block.BlockSize()
	buffer := make([]byte, blockSize)
	temp := make([]byte, blockSize)
	decryptedBlock := make([]byte, blockSize)

	currentIV := make([]byte, blockSize)
	copy(currentIV, iv)

	var prevCiphertext []byte
	var needsUnpad bool
	var lastDecryptedBlock []byte

	for {
		n, err := io.ReadFull(reader, buffer)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if n == 0 {
			break
		}

		if n < blockSize {
			return errors.New("данные не кратны размеру блока")
		}

		// Расшифровываем блок
		block.Decrypt(temp, buffer[:n])
		for i := 0; i < blockSize; i++ {
			decryptedBlock[i] = temp[i] ^ currentIV[i]
		}

		// Сохраняем текущий шифротекст как IV для следующего блока
		if prevCiphertext != nil {
			copy(currentIV, prevCiphertext)
		}

		prevCiphertext = make([]byte, blockSize)
		copy(prevCiphertext, buffer[:n])

		// Проверяем, есть ли еще данные
		peekBuffer := make([]byte, 1)
		_, peekErr := io.ReadFull(reader, peekBuffer)

		if peekErr == io.EOF {
			// Это последний блок - нужно удалить padding позже
			needsUnpad = true
			lastDecryptedBlock = make([]byte, len(decryptedBlock))
			copy(lastDecryptedBlock, decryptedBlock)
		} else if peekErr == nil {
			// Не последний блок - пишем как есть
			if _, err := writer.Write(decryptedBlock); err != nil {
				return err
			}
		}
	}

	// Обработка последнего блока с удалением padding
	if needsUnpad && lastDecryptedBlock != nil {
		unpadded, err := PKCS7Unpad(lastDecryptedBlock)
		if err != nil {
			return err
		}
		if _, err := writer.Write(unpadded); err != nil {
			return err
		}
	}

	return nil
}
