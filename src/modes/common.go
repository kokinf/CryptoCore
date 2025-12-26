package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

func CreateCipherBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

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
		return nil, errors.New("пустые данные")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("некорректный padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("некорректный padding")
		}
	}

	return data[:len(data)-padding], nil
}

// Потоковое шифрование для больших файлов
func StreamEncrypt(reader io.Reader, writer io.Writer, key []byte, mode string, iv []byte) error {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return err
	}

	switch mode {
	case "ecb":
		return streamECBEncrypt(reader, writer, block)
	case "cbc":
		return streamCBCEncrypt(reader, writer, block, iv)
	case "cfb":
		return streamCFBEncrypt(reader, writer, block, iv)
	case "ofb":
		return streamOFBEncrypt(reader, writer, block, iv)
	case "ctr":
		return streamCTREncrypt(reader, writer, block, iv)
	default:
		return fmt.Errorf("неподдерживаемый режим для потокового шифрования: %s", mode)
	}
}

// Потоковое дешифрование для больших файлов
func StreamDecrypt(reader io.Reader, writer io.Writer, key []byte, mode string, iv []byte) error {
	block, err := CreateCipherBlock(key)
	if err != nil {
		return err
	}

	switch mode {
	case "ecb":
		return streamECBDecrypt(reader, writer, block)
	case "cbc":
		return streamCBCDecrypt(reader, writer, block, iv)
	case "cfb":
		return streamCFBDecrypt(reader, writer, block, iv)
	case "ofb":
		return streamOFBDecrypt(reader, writer, block, iv)
	case "ctr":
		return streamCTRDecrypt(reader, writer, block, iv)
	default:
		return fmt.Errorf("неподдерживаемый режим для потокового дешифрования: %s", mode)
	}
}
