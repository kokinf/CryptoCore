package hash

import (
	"encoding/binary"
)

type SHA3_256Impl struct {
	state      [25]uint64
	buffer     [136]byte
	bufferLen  int
	rate       int
	outputSize int
}

func NewSHA3_256() *SHA3_256Impl {
	sha3 := &SHA3_256Impl{
		rate:       136,
		outputSize: 32,
	}
	sha3.Reset()
	return sha3
}

// Reset сбрасывает состояние хеш-функции к начальному
func (sha3 *SHA3_256Impl) Reset() {
	for i := range sha3.state {
		sha3.state[i] = 0
	}
	sha3.bufferLen = 0
}

func (sha3 *SHA3_256Impl) BlockSize() int {
	return sha3.rate
}

// Update добавляет данные к хешу
func (sha3 *SHA3_256Impl) Update(data []byte) {
	dataLen := len(data)
	dataIndex := 0

	for dataLen > 0 {
		if sha3.bufferLen == sha3.rate {
			sha3.absorbBuffer()
			sha3.bufferLen = 0
		}

		toCopy := min(dataLen, sha3.rate-sha3.bufferLen)
		copy(sha3.buffer[sha3.bufferLen:], data[dataIndex:dataIndex+toCopy])
		sha3.bufferLen += toCopy
		dataIndex += toCopy
		dataLen -= toCopy
	}
}

// Finalize завершает вычисление хеша и возвращает результат
func (sha3 *SHA3_256Impl) Finalize() []byte {
	temp := *sha3
	return temp.finalize()
}

func (sha3 *SHA3_256Impl) finalize() []byte {
	sha3.buffer[sha3.bufferLen] = 0x06
	sha3.bufferLen++

	for i := sha3.bufferLen; i < sha3.rate; i++ {
		sha3.buffer[i] = 0
	}

	sha3.buffer[sha3.rate-1] ^= 0x80

	sha3.absorbBuffer()

	return sha3.squeeze()
}

// absorbBuffer поглощает буфер в состояние
func (sha3 *SHA3_256Impl) absorbBuffer() {
	for i := 0; i < sha3.rate; i += 8 {
		word := binary.LittleEndian.Uint64(sha3.buffer[i:])
		sha3.state[i/8] ^= word
	}

	sha3.keccakF()
}

func (sha3 *SHA3_256Impl) squeeze() []byte {
	output := make([]byte, sha3.outputSize)
	outputIndex := 0

	for outputIndex < sha3.outputSize {
		for i := 0; i < sha3.rate/8 && outputIndex < sha3.outputSize; i++ {
			word := sha3.state[i]
			bytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(bytes, word)

			toCopy := min(8, sha3.outputSize-outputIndex)
			copy(output[outputIndex:], bytes[:toCopy])
			outputIndex += toCopy
		}

		if outputIndex < sha3.outputSize {
			sha3.keccakF()
		}
	}

	return output
}

func (sha3 *SHA3_256Impl) keccakF() {
	// Константы раундов для Keccak-f
	roundConstants := [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}

	for round := 0; round < 24; round++ {
		var C [5]uint64
		var D [5]uint64

		for x := 0; x < 5; x++ {
			C[x] = sha3.state[x] ^ sha3.state[x+5] ^ sha3.state[x+10] ^ sha3.state[x+15] ^ sha3.state[x+20]
		}

		for x := 0; x < 5; x++ {
			D[x] = C[(x+4)%5] ^ rot64(C[(x+1)%5], 1)
		}

		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				sha3.state[x+5*y] ^= D[x]
			}
		}

		var temp [25]uint64
		copy(temp[:], sha3.state[:])

		rotations := [25]uint{
			0, 1, 62, 28, 27,
			36, 44, 6, 55, 20,
			3, 10, 43, 25, 39,
			41, 45, 15, 21, 8,
			18, 2, 61, 56, 14,
		}

		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				newX := (0*x + 1*y) % 5
				newY := (2*x + 3*y) % 5
				sha3.state[newX+5*newY] = rot64(temp[x+5*y], rotations[x+5*y])
			}
		}

		copy(temp[:], sha3.state[:])

		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				sha3.state[x+5*y] = temp[x+5*y] ^ (^temp[(x+1)%5+5*y] & temp[(x+2)%5+5*y])
			}
		}

		sha3.state[0] ^= roundConstants[round]
	}
}

func rot64(x uint64, k uint) uint64 {
	k %= 64
	return (x << k) | (x >> (64 - k))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
