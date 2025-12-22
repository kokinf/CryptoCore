package kdf

import (
	"cryptocore/src/mac"
	"encoding/binary"
	"errors"
)

func PBKDF2HMACSHA256(password []byte, salt []byte, iterations int, dkLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("пароль не может быть пустым")
	}

	if len(salt) == 0 {
		return nil, errors.New("соль не может быть пустой")
	}

	if iterations <= 0 {
		return nil, errors.New("количество итераций должно быть положительным")
	}

	if dkLen <= 0 {
		return nil, errors.New("длина ключа должна быть положительной")
	}

	hLen := 32

	maxLen := (1<<32 - 1) * uint64(hLen)
	if uint64(dkLen) > maxLen {
		return nil, errors.New("производный ключ слишком длинный")
	}

	l := (dkLen + hLen - 1) / hLen
	r := dkLen - (l-1)*hLen

	derivedKey := make([]byte, 0, dkLen)

	for i := 1; i <= l; i++ {
		t, err := f(password, salt, iterations, i)
		if err != nil {
			return nil, err
		}

		if i == l {
			derivedKey = append(derivedKey, t[:r]...)
		} else {
			derivedKey = append(derivedKey, t...)
		}
	}

	return derivedKey, nil
}

func f(password, salt []byte, iterations, blockIndex int) ([]byte, error) {
	intBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(intBytes, uint32(blockIndex))

	data := make([]byte, len(salt)+4)
	copy(data, salt)
	copy(data[len(salt):], intBytes)

	hmac, err := mac.NewHMAC(password)
	if err != nil {
		return nil, err
	}

	uPrev := hmac.Compute(data)
	uCurr := uPrev
	result := make([]byte, len(uPrev))
	copy(result, uPrev)

	for j := 2; j <= iterations; j++ {
		hmac, err = mac.NewHMAC(password)
		if err != nil {
			return nil, err
		}

		uCurr = hmac.Compute(uPrev)

		for k := 0; k < len(result); k++ {
			result[k] ^= uCurr[k]
		}

		uPrev = uCurr
	}

	return result, nil
}
