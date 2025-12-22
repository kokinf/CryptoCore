package kdf

import (
	"cryptocore/src/mac"
	"encoding/binary"
	"errors"
	"fmt"
)

// HMAC(master_key, context || counter)
func DeriveKey(masterKey []byte, context string, length int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("мастер-ключ не может быть пустым")
	}

	if length <= 0 {
		return nil, errors.New("длина ключа должна быть положительной")
	}

	contextBytes := []byte(context)

	derived := make([]byte, 0, length)
	counter := 1

	for len(derived) < length {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))

		// context || counter
		data := make([]byte, len(contextBytes)+4)
		copy(data, contextBytes)
		copy(data[len(contextBytes):], counterBytes)

		hmac, err := mac.NewHMAC(masterKey)
		if err != nil {
			return nil, err
		}

		block := hmac.Compute(data)
		derived = append(derived, block...)
		counter++
	}

	return derived[:length], nil
}

func HKDFExtract(hashFunc string, salt, ikm []byte) ([]byte, error) {
	if len(salt) == 0 {

		salt = make([]byte, 32)
	}

	hmac, err := mac.NewHMAC(salt)
	if err != nil {
		return nil, err
	}

	return hmac.Compute(ikm), nil
}

func HKDFExpand(prk []byte, info []byte, length int) ([]byte, error) {
	if len(prk) == 0 {
		return nil, errors.New("псевдослучайный ключ не может быть пустым")
	}

	if length <= 0 {
		return nil, errors.New("длина ключа должна быть положительной")
	}

	hLen := 32
	n := (length + hLen - 1) / hLen

	if n > 255 {
		return nil, errors.New("слишком большая длина для расширения")
	}

	okm := make([]byte, 0, length)
	t := []byte{}

	for i := 1; i <= n; i++ {
		data := make([]byte, len(t)+len(info)+1)
		copy(data, t)
		copy(data[len(t):], info)
		data[len(t)+len(info)] = byte(i)

		hmac, err := mac.NewHMAC(prk)
		if err != nil {
			return nil, err
		}

		t = hmac.Compute(data)
		okm = append(okm, t...)
	}

	return okm[:length], nil
}

func HKDFFull(hashFunc string, ikm, salt, info []byte, length int) ([]byte, error) {
	prk, err := HKDFExtract(hashFunc, salt, ikm)
	if err != nil {
		return nil, err
	}

	return HKDFExpand(prk, info, length)
}

func DeriveMultipleKeys(masterKey []byte, contexts map[string]int) (map[string][]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("мастер-ключ не может быть пустым")
	}

	if len(contexts) == 0 {
		return nil, errors.New("не указаны контексты для выработки ключей")
	}

	results := make(map[string][]byte)

	for context, length := range contexts {
		key, err := DeriveKey(masterKey, context, length)
		if err != nil {
			return nil, fmt.Errorf("ошибка выработки ключа для контекста '%s': %v", context, err)
		}
		results[context] = key
	}

	return results, nil
}

func DeriveAEADKeys(masterKey []byte, keySize int) (encKey, macKey []byte, err error) {
	if len(masterKey) == 0 {
		return nil, nil, errors.New("мастер-ключ не может быть пустым")
	}

	if keySize <= 0 {
		return nil, nil, errors.New("размер ключа должен быть положительным")
	}

	if keySize == 16 || keySize == 24 || keySize == 32 {
		encKey, err = DeriveKey(masterKey, "aes-encryption", keySize)
		if err != nil {
			return nil, nil, err
		}
		return encKey, nil, nil
	}

	if keySize == 48 {
		encKey, err = DeriveKey(masterKey, "aes-encryption", 16)
		if err != nil {
			return nil, nil, err
		}

		macKey, err = DeriveKey(masterKey, "hmac-authentication", 32)
		if err != nil {
			return nil, nil, err
		}

		return encKey, macKey, nil
	}

	return nil, nil, fmt.Errorf("неподдерживаемый размер ключа: %d", keySize)
}

func DeriveWithInfo(masterKey []byte, context, info string, length int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("мастер-ключ не может быть пустым")
	}

	fullContext := context + "|" + info
	return DeriveKey(masterKey, fullContext, length)
}

func VerifyKeyDerivation(masterKey []byte, context string, derivedKey []byte) (bool, error) {
	if len(masterKey) == 0 {
		return false, errors.New("мастер-ключ не может быть пустым")
	}

	if len(derivedKey) == 0 {
		return false, errors.New("производный ключ не может быть пустым")
	}

	recreatedKey, err := DeriveKey(masterKey, context, len(derivedKey))
	if err != nil {
		return false, err
	}

	if len(recreatedKey) != len(derivedKey) {
		return false, nil
	}

	for i := 0; i < len(derivedKey); i++ {
		if recreatedKey[i] != derivedKey[i] {
			return false, nil
		}
	}

	return true, nil
}
