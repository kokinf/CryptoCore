package csprng

import (
	"crypto/rand"
	"fmt"
	"io"
)

type CSPRNGError struct {
	RequestedBytes int
	Err            error
}

func (e *CSPRNGError) Error() string {
	return fmt.Sprintf("ошибка генерации случайных байт (запрошено %d байт): %v", e.RequestedBytes, e.Err)
}

func GenerateRandomBytes(numBytes int) ([]byte, error) {
	if numBytes <= 0 {
		return nil, &CSPRNGError{
			RequestedBytes: numBytes,
			Err:            fmt.Errorf("количество байт должно быть положительным"),
		}
	}

	buffer := make([]byte, numBytes)

	_, err := io.ReadFull(rand.Reader, buffer)
	if err != nil {
		return nil, &CSPRNGError{
			RequestedBytes: numBytes,
			Err:            err,
		}
	}

	return buffer, nil
}
