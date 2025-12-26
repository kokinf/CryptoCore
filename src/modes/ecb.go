package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
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

// Потоковое ECB шифрование
func streamECBEncrypt(reader io.Reader, writer io.Writer, block cipher.Block) error {
	blockSize := block.BlockSize()
	buffer := make([]byte, blockSize)
	encryptedBlock := make([]byte, blockSize)

	var lastBlock []byte
	eof := false

	for !eof {
		// Читаем полный блок
		n, err := io.ReadFull(reader, buffer)
		if err == io.EOF {
			break
		} else if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}

		if n < blockSize {
			// Последний неполный блок
			paddedBlock := PKCS7Pad(buffer[:n], blockSize)
			block.Encrypt(encryptedBlock, paddedBlock)
			lastBlock = encryptedBlock
			eof = true
		} else {
			block.Encrypt(encryptedBlock, buffer)
			if _, err := writer.Write(encryptedBlock); err != nil {
				return err
			}
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

// Потоковое ECB дешифрование
func streamECBDecrypt(reader io.Reader, writer io.Writer, block cipher.Block) error {
	blockSize := block.BlockSize()
	buffer := make([]byte, blockSize)
	decryptedBlock := make([]byte, blockSize)

	var prevBlock []byte
	var needsUnpad bool

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

		block.Decrypt(decryptedBlock, buffer[:n])

		// Проверяем, есть ли еще данные
		peekBuffer := make([]byte, 1)
		_, peekErr := io.ReadFull(reader, peekBuffer)

		if peekErr == io.EOF {
			// Это последний блок - нужно удалить padding
			needsUnpad = true
		} else if peekErr == nil {
			// Не последний блок - пишем как есть
			if prevBlock != nil {
				if _, err := writer.Write(prevBlock); err != nil {
					return err
				}
			}
			prevBlock = make([]byte, len(decryptedBlock))
			copy(prevBlock, decryptedBlock)
		}
	}

	// Обработка последнего блока с удалением padding
	if needsUnpad {
		if prevBlock != nil {
			unpadded, err := PKCS7Unpad(prevBlock)
			if err != nil {
				return err
			}
			if _, err := writer.Write(unpadded); err != nil {
				return err
			}
		} else {
			unpadded, err := PKCS7Unpad(decryptedBlock)
			if err != nil {
				return err
			}
			if _, err := writer.Write(unpadded); err != nil {
				return err
			}
		}
	} else if prevBlock != nil {
		// Записываем последний сохраненный блок
		if _, err := writer.Write(prevBlock); err != nil {
			return err
		}
	}

	return nil
}
