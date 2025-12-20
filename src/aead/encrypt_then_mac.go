package aead

import (
	"crypto/subtle"
	"cryptocore/src/csprng"
	"cryptocore/src/mac"
	"cryptocore/src/modes"
	"errors"
	"fmt"
)

const (
	encKeySize = 16
	macKeySize = 32
)

type EncryptThenMac struct {
	encryptionKey []byte
	macKey        []byte
	mode          string
}

func NewEncryptThenMac(masterKey []byte, mode string) (*EncryptThenMac, error) {
	if len(masterKey) == encKeySize+macKeySize {
		etm := &EncryptThenMac{
			encryptionKey: make([]byte, encKeySize),
			macKey:        make([]byte, macKeySize),
			mode:          mode,
		}
		copy(etm.encryptionKey, masterKey[:encKeySize])
		copy(etm.macKey, masterKey[encKeySize:])
		return etm, nil
	}

	return NewEncryptThenMacWithKDF(masterKey, mode)
}

func deriveKeysHKDF(masterKey []byte) ([]byte, []byte, error) {
	if len(masterKey) == 0 {
		return nil, nil, errors.New("мастер-ключ не может быть пустым")
	}

	hmacInst, err := mac.NewHMAC(masterKey)
	if err != nil {
		return nil, nil, err
	}

	// Простой KDF: HMAC(masterKey, "encryption" + counter)
	encKey := make([]byte, 0, encKeySize)
	for len(encKey) < encKeySize {
		data := []byte(fmt.Sprintf("encryption-key-%d", len(encKey)))
		chunk := hmacInst.Compute(data)
		encKey = append(encKey, chunk...)
	}

	// MAC ключ: HMAC(masterKey, "mac" + counter)
	macKey := make([]byte, 0, macKeySize)
	for len(macKey) < macKeySize {
		data := []byte(fmt.Sprintf("mac-key-%d", len(macKey)))
		chunk := hmacInst.Compute(data)
		macKey = append(macKey, chunk...)
	}

	return encKey[:encKeySize], macKey[:macKeySize], nil
}

func NewEncryptThenMacWithKDF(masterKey []byte, mode string) (*EncryptThenMac, error) {
	supportedModes := map[string]bool{
		"ecb": true,
		"cbc": true,
		"cfb": true,
		"ofb": true,
		"ctr": true,
	}
	if !supportedModes[mode] {
		return nil, fmt.Errorf("неподдерживаемый режим для Encrypt-then-MAC: %s", mode)
	}

	encKey, macKey, err := deriveKeysHKDF(masterKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка KDF: %v", err)
	}

	return &EncryptThenMac{
		encryptionKey: encKey,
		macKey:        macKey,
		mode:          mode,
	}, nil
}

func GenerateMasterKey() ([]byte, error) {
	return csprng.GenerateRandomBytes(encKeySize + macKeySize)
}

func (etm *EncryptThenMac) Encrypt(plaintext, aad []byte) ([]byte, error) {
	ciphertext, err := etm.encryptData(plaintext)
	if err != nil {
		return nil, fmt.Errorf("ошибка шифрования: %v", err)
	}

	tag, err := etm.computeMAC(ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления MAC: %v", err)
	}

	// ciphertext || tag
	result := make([]byte, len(ciphertext)+len(tag))
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag)

	return result, nil
}

func (etm *EncryptThenMac) Decrypt(data, aad []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("данные слишком короткие")
	}

	// ciphertext и tag
	tagStart := len(data) - 32
	ciphertext := data[:tagStart]
	tag := data[tagStart:]

	if err := etm.verifyMAC(ciphertext, aad, tag); err != nil {
		return nil, err
	}

	plaintext, err := etm.decryptData(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ошибка дешифрования: %v", err)
	}

	return plaintext, nil
}

func (etm *EncryptThenMac) encryptData(plaintext []byte) ([]byte, error) {
	switch etm.mode {
	case "ecb":
		return modes.ECBEncrypt(plaintext, etm.encryptionKey)

	case "cbc":
		iv, err := csprng.GenerateRandomBytes(16)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации IV: %v", err)
		}
		ciphertext, err := modes.CBCEncryptWithIV(plaintext, etm.encryptionKey, iv)
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(iv)+len(ciphertext))
		copy(result[:16], iv)
		copy(result[16:], ciphertext)
		return result, nil

	case "cfb":
		iv, err := csprng.GenerateRandomBytes(16)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации IV: %v", err)
		}
		ciphertext, err := modes.CFBEncryptWithIV(plaintext, etm.encryptionKey, iv)
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(iv)+len(ciphertext))
		copy(result[:16], iv)
		copy(result[16:], ciphertext)
		return result, nil

	case "ofb":
		iv, err := csprng.GenerateRandomBytes(16)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации IV: %v", err)
		}
		ciphertext, err := modes.OFBEncryptWithIV(plaintext, etm.encryptionKey, iv)
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(iv)+len(ciphertext))
		copy(result[:16], iv)
		copy(result[16:], ciphertext)
		return result, nil

	case "ctr":
		iv, err := csprng.GenerateRandomBytes(16)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации IV: %v", err)
		}
		ciphertext, err := modes.CTREncryptWithIV(plaintext, etm.encryptionKey, iv)
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(iv)+len(ciphertext))
		copy(result[:16], iv)
		copy(result[16:], ciphertext)
		return result, nil

	default:
		return nil, fmt.Errorf("неподдерживаемый режим: %s", etm.mode)
	}
}

func (etm *EncryptThenMac) decryptData(ciphertext []byte) ([]byte, error) {
	switch etm.mode {
	case "ecb":
		return modes.ECBDecrypt(ciphertext, etm.encryptionKey)

	case "cbc":
		if len(ciphertext) < 16 {
			return nil, errors.New("ciphertext слишком короткий для извлечения IV")
		}
		iv := ciphertext[:16]
		actualCiphertext := ciphertext[16:]
		return modes.CBCDecrypt(actualCiphertext, etm.encryptionKey, iv)

	case "cfb":
		if len(ciphertext) < 16 {
			return nil, errors.New("ciphertext слишком короткий для извлечения IV")
		}
		iv := ciphertext[:16]
		actualCiphertext := ciphertext[16:]
		return modes.CFBDecrypt(actualCiphertext, etm.encryptionKey, iv)

	case "ofb":
		if len(ciphertext) < 16 {
			return nil, errors.New("ciphertext слишком короткий для извлечения IV")
		}
		iv := ciphertext[:16]
		actualCiphertext := ciphertext[16:]
		return modes.OFBDecrypt(actualCiphertext, etm.encryptionKey, iv)

	case "ctr":
		if len(ciphertext) < 16 {
			return nil, errors.New("ciphertext слишком короткий для извлечения IV")
		}
		iv := ciphertext[:16]
		actualCiphertext := ciphertext[16:]
		return modes.CTRDecrypt(actualCiphertext, etm.encryptionKey, iv)

	default:
		return nil, fmt.Errorf("неподдерживаемый режим: %s", etm.mode)
	}
}

// computeMAC вычисляет HMAC-SHA256 от ciphertext || AAD
func (etm *EncryptThenMac) computeMAC(ciphertext, aad []byte) ([]byte, error) {
	hmac, err := mac.NewHMAC(etm.macKey)
	if err != nil {
		return nil, err
	}

	macData := make([]byte, len(ciphertext)+len(aad))
	copy(macData, ciphertext)
	copy(macData[len(ciphertext):], aad)

	return hmac.Compute(macData), nil
}

func (etm *EncryptThenMac) verifyMAC(ciphertext, aad, expectedTag []byte) error {
	computedTag, err := etm.computeMAC(ciphertext, aad)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(computedTag, expectedTag) != 1 {
		return errors.New("ошибка аутентификации: неверный MAC")
	}

	return nil
}

func (etm *EncryptThenMac) GetMode() string {
	return etm.mode
}

func (etm *EncryptThenMac) Verify(data, aad []byte) (bool, error) {
	if len(data) < 32 {
		return false, errors.New("данные слишком короткие")
	}

	tagStart := len(data) - 32
	ciphertext := data[:tagStart]
	tag := data[tagStart:]

	computedTag, err := etm.computeMAC(ciphertext, aad)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(computedTag, tag) == 1, nil
}
