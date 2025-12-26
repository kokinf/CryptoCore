package aead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"cryptocore/src/csprng"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type GCM struct {
	block    cipher.Block
	hashKey  [16]byte
	mulTable [16][256][16]byte
	nonce    []byte
}

// streamGCMEncryptor - потоковый шифратор GCM
type streamGCMEncryptor struct {
	gcm    *GCM
	aad    []byte
	nonce  []byte
	state  gcmState
	writer io.Writer
}

// streamGCMDecryptor - потоковый дешифратор GCM
type streamGCMDecryptor struct {
	gcm    *GCM
	aad    []byte
	nonce  []byte
	tag    []byte
	state  gcmState
	reader io.Reader
}

type gcmState struct {
	counter      [16]byte
	keystream    [16]byte
	keystreamPos int
	y            [16]byte
	yPos         int
	aadLen       uint64
	dataLen      uint64
	buffer       []byte
	bufferPos    int
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

	// Инициализируем хеш-ключ: E_K(0^128)
	var zeroBlock [16]byte
	gcm.block.Encrypt(gcm.hashKey[:], zeroBlock[:])

	gcm.precomputeTable()

	return gcm, nil
}

func (g *GCM) precomputeTable() {
	h := g.bytesToElement(g.hashKey[:])

	// Предвычисляем таблицу умножения для оптимизации GHASH
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

	// Добавляем padding до кратного 16 байтам
	paddingLen := (16 - len(data)%16) % 16
	for i := 0; i < paddingLen; i++ {
		data = append(data, 0)
	}

	// Добавляем длины AAD и ciphertext (в битах)
	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[0:8], uint64(len(aad)*8))
	binary.BigEndian.PutUint64(lenBlock[8:16], uint64(len(ciphertext)*8))
	data = append(data, lenBlock...)

	y := [16]byte{}

	// Вычисляем GHASH
	for i := 0; i < len(data); i += 16 {
		block := data[i : i+16]
		if len(block) < 16 {
			paddedBlock := make([]byte, 16)
			copy(paddedBlock, block)
			block = paddedBlock
		}

		// XOR с текущим состоянием
		for j := 0; j < 16; j++ {
			y[j] ^= block[j]
		}

		// Умножение на H в GF(2^128)
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

		// Увеличиваем счетчик (последние 4 байта)
		counter := binary.BigEndian.Uint32(cb[12:16])
		counter++
		binary.BigEndian.PutUint32(cb[12:16], counter)
	}

	return y, nil
}

func (g *GCM) generateJ0(nonce []byte) ([16]byte, error) {
	var j0 [16]byte

	if len(nonce) == 12 {
		// Для 96-битного nonce: J0 = nonce || 0^31 || 1
		copy(j0[:12], nonce)
		binary.BigEndian.PutUint32(j0[12:16], 1)
	} else {
		// Для nonce произвольной длины: J0 = GHASH(nonce || 0^(s+64) || len64(nonce))
		paddingLen := (16 - len(nonce)%16) % 16
		nonceWithPadding := make([]byte, len(nonce)+paddingLen+16)
		copy(nonceWithPadding, nonce)

		// Padding нулями
		for i := 0; i < paddingLen; i++ {
			nonceWithPadding[len(nonce)+i] = 0
		}

		// Добавляем длину nonce в битах
		binary.BigEndian.PutUint64(nonceWithPadding[len(nonce)+paddingLen:], uint64(len(nonce)*8))

		// GHASH от padded nonce
		ghashResult := g.ghash(nonceWithPadding, []byte{})
		copy(j0[:], ghashResult[:])
	}

	return j0, nil
}

// Encrypt - обычное (не потоковое) шифрование GCM
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

	// Начинаем счетчик с J0 + 1
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

// Decrypt - обычное (не потоковое) дешифрование GCM
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

	// Начинаем счетчик с J0 + 1
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

// ============================================
// Потоковая реализация GCM
// ============================================

// NewStreamGCMEncryptor создает потоковый шифратор GCM
func (g *GCM) NewStreamEncryptor(nonce, aad []byte) (*streamGCMEncryptor, error) {
	if len(nonce) == 0 {
		var err error
		nonce, err = csprng.GenerateRandomBytes(12)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации nonce: %v", err)
		}
	}

	if len(nonce) != 12 {
		return nil, errors.New("nonce должен быть 12 байт")
	}

	j0, err := g.generateJ0(nonce)
	if err != nil {
		return nil, err
	}

	// Начинаем счетчик с J0 + 1
	var icb [16]byte
	copy(icb[:], j0[:])
	counter := binary.BigEndian.Uint32(icb[12:16])
	counter++
	binary.BigEndian.PutUint32(icb[12:16], counter)

	encryptor := &streamGCMEncryptor{
		gcm:   g,
		aad:   aad,
		nonce: nonce,
		state: gcmState{
			counter:      icb,
			keystreamPos: 16, // Начинаем с пустого keystream
			buffer:       make([]byte, 8192),
		},
	}

	// Инициализируем GHASH для AAD
	if len(aad) > 0 {
		encryptor.updateGHASH(aad, true)
	}

	return encryptor, nil
}

// NewStreamGCMDecryptor создает потоковый дешифратор GCM
func (g *GCM) NewStreamDecryptor(nonce, aad, tag []byte) (*streamGCMDecryptor, error) {
	if len(tag) != 16 {
		return nil, errors.New("тег должен быть 16 байт")
	}

	if len(nonce) != 12 {
		return nil, errors.New("nonce должен быть 12 байт")
	}

	j0, err := g.generateJ0(nonce)
	if err != nil {
		return nil, err
	}

	// Начинаем счетчик с J0 + 1
	var icb [16]byte
	copy(icb[:], j0[:])
	counter := binary.BigEndian.Uint32(icb[12:16])
	counter++
	binary.BigEndian.PutUint32(icb[12:16], counter)

	decryptor := &streamGCMDecryptor{
		gcm:   g,
		aad:   aad,
		nonce: nonce,
		tag:   tag,
		state: gcmState{
			counter:      icb,
			keystreamPos: 16, // Начинаем с пустого keystream
			buffer:       make([]byte, 8192),
		},
	}

	// Инициализируем GHASH для AAD
	if len(aad) > 0 {
		decryptor.updateGHASH(aad, true)
	}

	return decryptor, nil
}

// updateGHASH обновляет состояние GHASH (для шифратора)
func (s *streamGCMEncryptor) updateGHASH(data []byte, isAAD bool) {
	for i := 0; i < len(data); i++ {
		s.state.y[s.state.yPos] ^= data[i]
		s.state.yPos++

		if s.state.yPos == 16 {
			s.processGHASHBlock()
			s.state.yPos = 0
		}
	}

	if isAAD {
		s.state.aadLen += uint64(len(data)) * 8
	} else {
		s.state.dataLen += uint64(len(data)) * 8
	}
}

// updateGHASH обновляет состояние GHASH (для дешифратора)
func (s *streamGCMDecryptor) updateGHASH(data []byte, isAAD bool) {
	for i := 0; i < len(data); i++ {
		s.state.y[s.state.yPos] ^= data[i]
		s.state.yPos++

		if s.state.yPos == 16 {
			s.processGHASHBlock()
			s.state.yPos = 0
		}
	}

	if isAAD {
		s.state.aadLen += uint64(len(data)) * 8
	} else {
		s.state.dataLen += uint64(len(data)) * 8
	}
}

func (s *streamGCMEncryptor) processGHASHBlock() {
	yElem := s.gcm.bytesToElement(s.state.y[:])
	hElem := s.gcm.bytesToElement(s.gcm.hashKey[:])
	product := s.gcm.multiply(yElem, hElem)
	s.state.y = s.gcm.elementToBytes(product)
}

func (s *streamGCMDecryptor) processGHASHBlock() {
	yElem := s.gcm.bytesToElement(s.state.y[:])
	hElem := s.gcm.bytesToElement(s.gcm.hashKey[:])
	product := s.gcm.multiply(yElem, hElem)
	s.state.y = s.gcm.elementToBytes(product)
}

// getNextKeystreamBlock получает следующий блок keystream
func (s *streamGCMEncryptor) getNextKeystreamBlock() {
	s.gcm.block.Encrypt(s.state.keystream[:], s.state.counter[:])

	// Увеличиваем счетчик (последние 4 байта)
	counter := binary.BigEndian.Uint32(s.state.counter[12:16])
	counter++
	binary.BigEndian.PutUint32(s.state.counter[12:16], counter)

	s.state.keystreamPos = 0
}

func (s *streamGCMDecryptor) getNextKeystreamBlock() {
	s.gcm.block.Encrypt(s.state.keystream[:], s.state.counter[:])

	// Увеличиваем счетчик (последние 4 байта)
	counter := binary.BigEndian.Uint32(s.state.counter[12:16])
	counter++
	binary.BigEndian.PutUint32(s.state.counter[12:16], counter)

	s.state.keystreamPos = 0
}

// Write шифрует данные и записывает их в writer
func (s *streamGCMEncryptor) Write(data []byte) (int, error) {
	if s.writer == nil {
		return 0, errors.New("writer не установлен")
	}

	totalWritten := 0

	for i := 0; i < len(data); i++ {
		if s.state.keystreamPos >= 16 {
			s.getNextKeystreamBlock()
		}

		// Шифруем байт
		ciphertextByte := data[i] ^ s.state.keystream[s.state.keystreamPos]
		s.state.keystreamPos++

		// Записываем зашифрованный байт
		s.state.buffer[s.state.bufferPos] = ciphertextByte
		s.state.bufferPos++

		// Обновляем GHASH с зашифрованным байтом
		s.state.y[s.state.yPos] ^= ciphertextByte
		s.state.yPos++
		s.state.dataLen += 8

		// Обрабатываем полный блок GHASH
		if s.state.yPos == 16 {
			s.processGHASHBlock()
			s.state.yPos = 0
		}

		// Записываем буфер когда он заполнен
		if s.state.bufferPos == len(s.state.buffer) {
			if _, err := s.writer.Write(s.state.buffer); err != nil {
				return totalWritten, err
			}
			totalWritten += s.state.bufferPos
			s.state.bufferPos = 0
		}
	}

	return totalWritten, nil
}

// Read читает и дешифрует данные
func (s *streamGCMDecryptor) Read(data []byte) (int, error) {
	if s.reader == nil {
		return 0, errors.New("reader не установлен")
	}

	// Читаем зашифрованные данные
	n, err := s.reader.Read(data)
	if err != nil && err != io.EOF {
		return 0, err
	}

	if n == 0 {
		return 0, err
	}

	// Дешифруем
	for i := 0; i < n; i++ {
		if s.state.keystreamPos >= 16 {
			s.getNextKeystreamBlock()
		}

		ciphertextByte := data[i]

		// Дешифруем байт
		plaintextByte := ciphertextByte ^ s.state.keystream[s.state.keystreamPos]
		s.state.keystreamPos++

		// Сохраняем результат
		data[i] = plaintextByte

		// Обновляем GHASH с зашифрованным байтом
		s.state.y[s.state.yPos] ^= ciphertextByte
		s.state.yPos++
		s.state.dataLen += 8

		// Обрабатываем полный блок GHASH
		if s.state.yPos == 16 {
			s.processGHASHBlock()
			s.state.yPos = 0
		}
	}

	return n, err
}

// Finalize завершает шифрование, записывает оставшиеся данные и возвращает тег
func (s *streamGCMEncryptor) Finalize() ([]byte, error) {
	// Записываем оставшиеся данные в буфере
	if s.state.bufferPos > 0 {
		if _, err := s.writer.Write(s.state.buffer[:s.state.bufferPos]); err != nil {
			return nil, err
		}
	}

	// Обрабатываем оставшиеся байты в GHASH
	if s.state.yPos > 0 {
		s.processGHASHBlock()
	}

	// Добавляем длины AAD и данных (в битах)
	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[0:8], s.state.aadLen)
	binary.BigEndian.PutUint64(lenBlock[8:16], s.state.dataLen)

	for i := 0; i < 16; i++ {
		s.state.y[i] ^= lenBlock[i]
	}
	s.processGHASHBlock()

	// Вычисляем тег
	j0, err := s.gcm.generateJ0(s.nonce)
	if err != nil {
		return nil, err
	}

	var encryptedJ0 [16]byte
	s.gcm.block.Encrypt(encryptedJ0[:], j0[:])

	tag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		tag[i] = s.state.y[i] ^ encryptedJ0[i]
	}

	return tag, nil
}

// Verify проверяет тег после дешифрования
func (s *streamGCMDecryptor) Verify() (bool, error) {
	// Обрабатываем оставшиеся байты в GHASH
	if s.state.yPos > 0 {
		s.processGHASHBlock()
	}

	// Добавляем длины AAD и данных (в битах)
	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[0:8], s.state.aadLen)
	binary.BigEndian.PutUint64(lenBlock[8:16], s.state.dataLen)

	for i := 0; i < 16; i++ {
		s.state.y[i] ^= lenBlock[i]
	}
	s.processGHASHBlock()

	// Вычисляем тег
	j0, err := s.gcm.generateJ0(s.nonce)
	if err != nil {
		return false, err
	}

	var encryptedJ0 [16]byte
	s.gcm.block.Encrypt(encryptedJ0[:], j0[:])

	computedTag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		computedTag[i] = s.state.y[i] ^ encryptedJ0[i]
	}

	// Сравниваем теги constant-time
	result := byte(0)
	for i := 0; i < 16; i++ {
		result |= computedTag[i] ^ s.tag[i]
	}

	return result == 0, nil
}

func (s *streamGCMEncryptor) SetWriter(writer io.Writer) {
	s.writer = writer
}

func (s *streamGCMDecryptor) SetReader(reader io.Reader) {
	s.reader = reader
}

// EncryptStream выполняет потоковое шифрование GCM
func (g *GCM) EncryptStream(reader io.Reader, writer io.Writer, nonce, aad []byte) ([]byte, error) {
	encryptor, err := g.NewStreamEncryptor(nonce, aad)
	if err != nil {
		return nil, err
	}

	encryptor.SetWriter(writer)

	// Записываем nonce в начало
	if _, err := writer.Write(nonce); err != nil {
		return nil, fmt.Errorf("ошибка записи nonce: %v", err)
	}

	// Шифруем данные
	buffer := make([]byte, 64*1024) // 64KB chunks
	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ошибка чтения: %v", err)
		}

		if n > 0 {
			if _, err := encryptor.Write(buffer[:n]); err != nil {
				return nil, fmt.Errorf("ошибка шифрования: %v", err)
			}
		}
	}

	// Получаем тег
	tag, err := encryptor.Finalize()
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления тега: %v", err)
	}

	// Записываем тег в конец
	if _, err := writer.Write(tag); err != nil {
		return nil, fmt.Errorf("ошибка записи тега: %v", err)
	}

	return tag, nil
}

// DecryptStream выполняет потоковое дешифрование GCM
func (g *GCM) DecryptStream(reader io.Reader, writer io.Writer, nonce, aad []byte) error {
	// Для потокового дешифрования нужно прочитать nonce и tag
	// Читаем nonce из начала потока
	nonceBuffer := make([]byte, 12)
	if _, err := io.ReadFull(reader, nonceBuffer); err != nil {
		return fmt.Errorf("ошибка чтения nonce: %v", err)
	}

	// Используем предоставленный nonce или прочитанный
	actualNonce := nonce
	if actualNonce == nil {
		actualNonce = nonceBuffer
	}

	// Читаем весь остальной поток во временный буфер чтобы получить тег
	// В реальном приложении нужно использовать seek или отдельный буфер для тега
	var ciphertextBuffer bytes.Buffer
	if _, err := io.Copy(&ciphertextBuffer, reader); err != nil {
		return fmt.Errorf("ошибка чтения данных: %v", err)
	}

	data := ciphertextBuffer.Bytes()
	if len(data) < 16 {
		return errors.New("данные слишком короткие для GCM")
	}

	// Извлекаем tag (последние 16 байт)
	tag := data[len(data)-16:]
	ciphertext := data[:len(data)-16]

	// Создаем дешифратор
	decryptor, err := g.NewStreamDecryptor(actualNonce, aad, tag)
	if err != nil {
		return err
	}

	// Дешифруем данные
	decryptor.SetReader(bytes.NewReader(ciphertext))

	outputBuffer := make([]byte, 64*1024)
	for {
		n, err := decryptor.Read(outputBuffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ошибка дешифрования: %v", err)
		}

		if n > 0 {
			if _, err := writer.Write(outputBuffer[:n]); err != nil {
				return fmt.Errorf("ошибка записи: %v", err)
			}
		}
	}

	// Проверяем тег
	valid, err := decryptor.Verify()
	if err != nil {
		return fmt.Errorf("ошибка проверки тега: %v", err)
	}

	if !valid {
		return errors.New("ошибка аутентификации: неверный тег")
	}

	return nil
}
