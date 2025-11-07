package hash

import (
	"encoding/binary"
)

type SHA256Impl struct {
	state     [8]uint32
	count     uint64
	buffer    [64]byte
	bufferLen int
}

func NewSHA256() *SHA256Impl {
	sha := &SHA256Impl{}
	sha.Reset()
	return sha
}

// Reset сбрасывает состояние хеш функции к начальному
func (sha *SHA256Impl) Reset() {
	sha.state[0] = 0x6a09e667
	sha.state[1] = 0xbb67ae85
	sha.state[2] = 0x3c6ef372
	sha.state[3] = 0xa54ff53a
	sha.state[4] = 0x510e527f
	sha.state[5] = 0x9b05688c
	sha.state[6] = 0x1f83d9ab
	sha.state[7] = 0x5be0cd19

	sha.count = 0
	sha.bufferLen = 0
}

// BlockSize возвращает размер блока SHA-256
func (sha *SHA256Impl) BlockSize() int {
	return 64
}

// Update добавляет данные к хешу
func (sha *SHA256Impl) Update(data []byte) {
	index := 0
	dataLen := len(data)

	for dataLen > 0 {
		n := copy(sha.buffer[sha.bufferLen:], data[index:])
		sha.bufferLen += n
		index += n
		dataLen -= n
		sha.count += uint64(n) * 8

		if sha.bufferLen == 64 {
			sha.processBlock(sha.buffer[:])
			sha.bufferLen = 0
		}
	}
}

func (sha *SHA256Impl) Finalize() []byte {
	temp := *sha
	return temp.finalize()
}

func (sha *SHA256Impl) finalize() []byte {
	sha.buffer[sha.bufferLen] = 0x80
	sha.bufferLen++

	if sha.bufferLen > 56 {
		for sha.bufferLen < 64 {
			sha.buffer[sha.bufferLen] = 0
			sha.bufferLen++
		}
		sha.processBlock(sha.buffer[:])
		sha.bufferLen = 0
	}

	for sha.bufferLen < 56 {
		sha.buffer[sha.bufferLen] = 0
		sha.bufferLen++
	}

	length := sha.count
	sha.buffer[63] = byte(length)
	sha.buffer[62] = byte(length >> 8)
	sha.buffer[61] = byte(length >> 16)
	sha.buffer[60] = byte(length >> 24)
	sha.buffer[59] = byte(length >> 32)
	sha.buffer[58] = byte(length >> 40)
	sha.buffer[57] = byte(length >> 48)
	sha.buffer[56] = byte(length >> 56)

	sha.processBlock(sha.buffer[:])

	hash := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(hash[i*4:], sha.state[i])
	}

	return hash
}

// Константы SHA-256
var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func (sha *SHA256Impl) processBlock(block []byte) {
	var w [64]uint32

	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}

	for i := 16; i < 64; i++ {
		s0 := rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	a, b, c, d, e, f, g, h := sha.state[0], sha.state[1], sha.state[2], sha.state[3],
		sha.state[4], sha.state[5], sha.state[6], sha.state[7]

	// Основной цикл сжатия
	for i := 0; i < 64; i++ {
		S1 := rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := h + S1 + ch + k[i] + w[i]
		S0 := rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}

	// Добавляем сжатый блок к текущему хешу
	sha.state[0] += a
	sha.state[1] += b
	sha.state[2] += c
	sha.state[3] += d
	sha.state[4] += e
	sha.state[5] += f
	sha.state[6] += g
	sha.state[7] += h
}

func rightRotate(n uint32, d uint) uint32 {
	return (n >> d) | (n << (32 - d))
}
