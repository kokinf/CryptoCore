package mac

import (
	"crypto/subtle"
	"cryptocore/src/hash"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

type HMAC struct {
	hashFunc   hash.Hasher
	blockSize  int
	outputSize int
	key        []byte
}

func NewHMAC(key []byte) (*HMAC, error) {
	if len(key) == 0 {
		return nil, errors.New("ключ HMAC не может быть пустым")
	}

	hasher, err := hash.NewHasher(hash.SHA256)
	if err != nil {
		return nil, err
	}

	hmac := &HMAC{
		hashFunc:   hasher,
		blockSize:  64,
		outputSize: 32,
	}

	hmac.key = hmac.processKey(key)

	return hmac, nil
}

func (h *HMAC) processKey(key []byte) []byte {
	if len(key) > h.blockSize {
		h.hashFunc.Reset()
		h.hashFunc.Update(key)
		key = h.hashFunc.Finalize()
	}

	paddedKey := make([]byte, h.blockSize)
	copy(paddedKey, key)

	return paddedKey
}

func (h *HMAC) Compute(message []byte) []byte {
	ipad := make([]byte, h.blockSize)
	for i := 0; i < h.blockSize; i++ {
		ipad[i] = h.key[i] ^ 0x36
	}

	h.hashFunc.Reset()
	h.hashFunc.Update(ipad)
	h.hashFunc.Update(message)
	innerHash := h.hashFunc.Finalize()

	opad := make([]byte, h.blockSize)
	for i := 0; i < h.blockSize; i++ {
		opad[i] = h.key[i] ^ 0x5c
	}

	h.hashFunc.Reset()
	h.hashFunc.Update(opad)
	h.hashFunc.Update(innerHash)

	return h.hashFunc.Finalize()
}

func (h *HMAC) ComputeFromReader(reader io.Reader) ([]byte, error) {
	ipad := make([]byte, h.blockSize)
	for i := 0; i < h.blockSize; i++ {
		ipad[i] = h.key[i] ^ 0x36
	}

	h.hashFunc.Reset()
	h.hashFunc.Update(ipad)

	buffer := make([]byte, 8192)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			h.hashFunc.Update(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	innerHash := h.hashFunc.Finalize()

	opad := make([]byte, h.blockSize)
	for i := 0; i < h.blockSize; i++ {
		opad[i] = h.key[i] ^ 0x5c
	}

	h.hashFunc.Reset()
	h.hashFunc.Update(opad)
	h.hashFunc.Update(innerHash)

	return h.hashFunc.Finalize(), nil
}

func (h *HMAC) ComputeFromFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return h.ComputeFromReader(file)
}

func (h *HMAC) Verify(message []byte, expectedMAC []byte) bool {
	computedMAC := h.Compute(message)
	return subtle.ConstantTimeCompare(computedMAC, expectedMAC) == 1
}

func (h *HMAC) VerifyFromReader(reader io.Reader, expectedMAC []byte) (bool, error) {
	computedMAC, err := h.ComputeFromReader(reader)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(computedMAC, expectedMAC) == 1, nil
}

func (h *HMAC) VerifyFromFile(filename string, expectedMAC []byte) (bool, error) {
	computedMAC, err := h.ComputeFromFile(filename)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(computedMAC, expectedMAC) == 1, nil
}

func (h *HMAC) ComputeHex(message []byte) string {
	return hex.EncodeToString(h.Compute(message))
}

func (h *HMAC) ComputeHexFromReader(reader io.Reader) (string, error) {
	mac, err := h.ComputeFromReader(reader)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac), nil
}

func (h *HMAC) ComputeHexFromFile(filename string) (string, error) {
	mac, err := h.ComputeFromFile(filename)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac), nil
}

func (h *HMAC) GetKey() []byte {
	keyCopy := make([]byte, len(h.key))
	copy(keyCopy, h.key)
	return keyCopy
}

func (h *HMAC) GetBlockSize() int {
	return h.blockSize
}

func (h *HMAC) GetOutputSize() int {
	return h.outputSize
}

func (h *HMAC) Reset() {
	h.hashFunc.Reset()
}

func ComputeHMAC(key, message []byte) ([]byte, error) {
	hmac, err := NewHMAC(key)
	if err != nil {
		return nil, err
	}
	return hmac.Compute(message), nil
}

func ComputeHMACHex(key, message []byte) (string, error) {
	hmac, err := ComputeHMAC(key, message)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hmac), nil
}

func VerifyHMAC(key, message, expectedMAC []byte) (bool, error) {
	hmac, err := NewHMAC(key)
	if err != nil {
		return false, err
	}
	return hmac.Verify(message, expectedMAC), nil
}
