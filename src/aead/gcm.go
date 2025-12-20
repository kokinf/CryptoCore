package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"cryptocore/src/csprng"
	"encoding/binary"
	"errors"
	"fmt"
)

type GCM struct {
	block    cipher.Block
	hashKey  [16]byte
	mulTable [16][256][16]byte
	nonce    []byte
}

func NewGCM(key []byte) (*GCM, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("ключ GCM должен быть 16, 24 или 32 байта")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm := &GCM{
		block: block,
	}

	var zeroBlock [16]byte
	gcm.block.Encrypt(gcm.hashKey[:], zeroBlock[:])

	gcm.precomputeTable()

	return gcm, nil
}

func (g *GCM) precomputeTable() {
	h := g.bytesToElement(g.hashKey[:])

	for i := 0; i < 16; i++ {
		for byteVal := 0; byteVal < 256; byteVal++ {
			var elem [16]byte
			elem[i] = byte(byteVal)

			product := g.multiply(g.bytesToElement(elem[:]), h)

			resultBytes := g.elementToBytes(product)
			copy(g.mulTable[i][byteVal][:], resultBytes[:])
		}
	}
}

func (g *GCM) bytesToElement(b []byte) [2]uint64 {
	if len(b) != 16 {
		panic("требуется 16 байт для элемента GF(2^128)")
	}

	return [2]uint64{
		binary.BigEndian.Uint64(b[0:8]),
		binary.BigEndian.Uint64(b[8:16]),
	}
}

func (g *GCM) elementToBytes(elem [2]uint64) [16]byte {
	var result [16]byte
	binary.BigEndian.PutUint64(result[0:8], elem[0])
	binary.BigEndian.PutUint64(result[8:16], elem[1])
	return result
}

func (g *GCM) multiply(x, y [2]uint64) [2]uint64 {
	z := [2]uint64{0, 0}
	v := y

	for i := 127; i >= 0; i-- {
		var bit uint64
		if i >= 64 {
			bit = (x[0] >> uint(i-64)) & 1
		} else {
			bit = (x[1] >> uint(i)) & 1
		}

		if bit == 1 {
			z[0] ^= v[0]
			z[1] ^= v[1]
		}

		carry := v[1] & 1
		v[1] = (v[1] >> 1) | ((v[0] & 1) << 63)
		v[0] = v[0] >> 1

		if carry == 1 {
			v[0] ^= 0xE100000000000000
		}
	}

	return z
}

func (g *GCM) ghash(aad, ciphertext []byte) [16]byte {
	var data []byte
	data = append(data, aad...)
	data = append(data, ciphertext...)

	paddingLen := (16 - len(data)%16) % 16
	for i := 0; i < paddingLen; i++ {
		data = append(data, 0)
	}

	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[0:8], uint64(len(aad)*8))
	binary.BigEndian.PutUint64(lenBlock[8:16], uint64(len(ciphertext)*8))
	data = append(data, lenBlock...)

	y := [16]byte{}

	for i := 0; i < len(data); i += 16 {
		block := data[i : i+16]
		if len(block) < 16 {
			paddedBlock := make([]byte, 16)
			copy(paddedBlock, block)
			block = paddedBlock
		}

		for j := 0; j < 16; j++ {
			y[j] ^= block[j]
		}

		yElem := g.bytesToElement(y[:])
		hElem := g.bytesToElement(g.hashKey[:])
		product := g.multiply(yElem, hElem)
		y = g.elementToBytes(product)
	}

	return y
}

func (g *GCM) gctr(icb [16]byte, x []byte) ([]byte, error) {
	if len(x) == 0 {
		return []byte{}, nil
	}

	n := (len(x) + 15) / 16
	y := make([]byte, len(x))
	cb := icb

	for i := 0; i < n; i++ {
		var encryptedCB [16]byte
		g.block.Encrypt(encryptedCB[:], cb[:])

		blockSize := 16
		if i == n-1 && len(x)%16 != 0 {
			blockSize = len(x) % 16
		}

		start := i * 16
		for j := 0; j < blockSize; j++ {
			y[start+j] = x[start+j] ^ encryptedCB[j]
		}

		counter := binary.BigEndian.Uint32(cb[12:16])
		counter++
		binary.BigEndian.PutUint32(cb[12:16], counter)
	}

	return y, nil
}

func (g *GCM) generateJ0(nonce []byte) ([16]byte, error) {
	var j0 [16]byte

	if len(nonce) == 12 {
		copy(j0[:12], nonce)
		binary.BigEndian.PutUint32(j0[12:16], 1)
	} else {
		paddingLen := (16 - len(nonce)%16) % 16
		nonceWithPadding := make([]byte, len(nonce)+paddingLen+16)
		copy(nonceWithPadding, nonce)

		for i := 0; i < paddingLen; i++ {
			nonceWithPadding[len(nonce)+i] = 0
		}

		binary.BigEndian.PutUint64(nonceWithPadding[len(nonce)+paddingLen:], uint64(len(nonce)*8))

		ghashResult := g.ghash(nonceWithPadding, []byte{})
		copy(j0[:], ghashResult[:])
	}

	return j0, nil
}

// nonce(12) || ciphertext || tag(16)
func (g *GCM) Encrypt(plaintext, aad []byte) ([]byte, error) {
	var nonce []byte
	if len(g.nonce) > 0 {
		nonce = g.nonce
	} else {
		var err error
		nonce, err = csprng.GenerateRandomBytes(12)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации nonce: %v", err)
		}
	}

	j0, err := g.generateJ0(nonce)
	if err != nil {
		return nil, err
	}

	var icb [16]byte
	copy(icb[:], j0[:])

	counter := binary.BigEndian.Uint32(icb[12:16])
	counter++
	binary.BigEndian.PutUint32(icb[12:16], counter)

	ciphertext, err := g.gctr(icb, plaintext)
	if err != nil {
		return nil, fmt.Errorf("ошибка GCTR шифрования: %v", err)
	}

	tag, err := g.computeTag(j0, aad, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления тега: %v", err)
	}

	// nonce(12) || ciphertext || tag(16)
	result := make([]byte, 12+len(ciphertext)+16)
	copy(result[:12], nonce)
	copy(result[12:12+len(ciphertext)], ciphertext)
	copy(result[12+len(ciphertext):], tag)

	return result, nil
}

func (g *GCM) Decrypt(data, aad []byte) ([]byte, error) {
	if len(data) < 28 {
		return nil, errors.New("данные слишком короткие для GCM")
	}

	// Извлекаем nonce, ciphertext и tag
	nonce := data[:12]
	tag := data[len(data)-16:]
	ciphertext := data[12 : len(data)-16]

	j0, err := g.generateJ0(nonce)
	if err != nil {
		return nil, err
	}

	if !g.verifyTag(j0, aad, ciphertext, tag) {
		return nil, errors.New("ошибка аутентификации: неверный тег")
	}

	var icb [16]byte
	copy(icb[:], j0[:])

	counter := binary.BigEndian.Uint32(icb[12:16])
	counter++
	binary.BigEndian.PutUint32(icb[12:16], counter)

	plaintext, err := g.gctr(icb, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ошибка GCTR дешифрования: %v", err)
	}

	return plaintext, nil
}

func (g *GCM) computeTag(j0 [16]byte, aad, ciphertext []byte) ([]byte, error) {
	s := g.ghash(aad, ciphertext)

	var encryptedJ0 [16]byte
	g.block.Encrypt(encryptedJ0[:], j0[:])

	tag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		tag[i] = s[i] ^ encryptedJ0[i]
	}

	return tag[:], nil
}

func (g *GCM) verifyTag(j0 [16]byte, aad, ciphertext, expectedTag []byte) bool {
	computedTag, err := g.computeTag(j0, aad, ciphertext)
	if err != nil {
		return false
	}

	if len(computedTag) != len(expectedTag) {
		return false
	}

	result := byte(0)
	for i := 0; i < len(computedTag); i++ {
		result |= computedTag[i] ^ expectedTag[i]
	}

	return result == 0
}

func (g *GCM) SetNonce(nonce []byte) error {
	if len(nonce) != 12 {
		return fmt.Errorf("nonce должен быть 12 байт для GCM, получено %d байт", len(nonce))
	}

	g.nonce = make([]byte, len(nonce))
	copy(g.nonce, nonce)
	return nil
}

func (g *GCM) GetNonce() []byte {
	nonce := make([]byte, len(g.nonce))
	copy(nonce, g.nonce)
	return nonce
}
