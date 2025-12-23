package unit

import (
	"cryptocore/src/modes"
	"cryptocore/tests"
	"fmt"
	"testing"
)

func TestECB_EncryptDecrypt(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"OneBlock", th.GenerateTestData(16)},
		{"TwoBlocks", th.GenerateTestData(32)},
		{"PartialBlock", th.GenerateTestData(20)},
		{"LargeData", th.GenerateTestData(1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Шифруем
			ciphertext, err := modes.ECBEncrypt(tc.plaintext, key)
			th.AssertNoErrorf(err, "ECB encryption failed")

			// Проверяем, что ciphertext имеет правильную длину (кратную 16)
			if len(ciphertext)%16 != 0 {
				t.Errorf("Ciphertext length %d not multiple of 16", len(ciphertext))
			}

			// Дешифруем
			decrypted, err := modes.ECBDecrypt(ciphertext, key)
			th.AssertNoErrorf(err, "ECB decryption failed")

			// Проверяем совпадение
			if !th.CompareBytes(tc.plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
				t.Logf("Original: %d bytes", len(tc.plaintext))
				t.Logf("Decrypted: %d bytes", len(decrypted))
			}
		})
	}
}

func TestCBC_EncryptDecrypt(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)
	iv := th.GenerateTestData(16)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"OneBlock", th.GenerateTestData(16)},
		{"TwoBlocks", th.GenerateTestData(32)},
		{"PartialBlock", th.GenerateTestData(20)},
		{"LargeData", th.GenerateTestData(1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Шифруем с IV
			ciphertext, err := modes.CBCEncryptWithIV(tc.plaintext, key, iv)
			th.AssertNoErrorf(err, "CBC encryption failed")

			// Проверяем, что ciphertext имеет правильную длину (кратную 16)
			if len(ciphertext)%16 != 0 {
				t.Errorf("Ciphertext length %d not multiple of 16", len(ciphertext))
			}

			// Дешифруем
			decrypted, err := modes.CBCDecrypt(ciphertext, key, iv)
			th.AssertNoErrorf(err, "CBC decryption failed")

			// Проверяем совпадение
			if !th.CompareBytes(tc.plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
			}
		})
	}
}

func TestCFB_EncryptDecrypt(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)
	iv := th.GenerateTestData(16)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"Short", th.GenerateTestData(10)},
		{"OneBlock", th.GenerateTestData(16)},
		{"TwoBlocks", th.GenerateTestData(32)},
		{"PartialBlock", th.GenerateTestData(20)},
		{"LargeData", th.GenerateTestData(1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Шифруем
			ciphertext, err := modes.CFBEncryptWithIV(tc.plaintext, key, iv)
			th.AssertNoErrorf(err, "CFB encryption failed")

			// Длина ciphertext должна быть равна длине plaintext (без padding)
			if len(ciphertext) != len(tc.plaintext) {
				t.Errorf("Ciphertext length %d != plaintext length %d",
					len(ciphertext), len(tc.plaintext))
			}

			// Дешифруем
			decrypted, err := modes.CFBDecrypt(ciphertext, key, iv)
			th.AssertNoErrorf(err, "CFB decryption failed")

			// Проверяем совпадение
			if !th.CompareBytes(tc.plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
			}
		})
	}
}

func TestOFB_EncryptDecrypt(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)
	iv := th.GenerateTestData(16)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"Short", th.GenerateTestData(10)},
		{"OneBlock", th.GenerateTestData(16)},
		{"TwoBlocks", th.GenerateTestData(32)},
		{"PartialBlock", th.GenerateTestData(20)},
		{"LargeData", th.GenerateTestData(1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Шифруем
			ciphertext, err := modes.OFBEncryptWithIV(tc.plaintext, key, iv)
			th.AssertNoErrorf(err, "OFB encryption failed")

			// Длина ciphertext должна быть равна длине plaintext
			if len(ciphertext) != len(tc.plaintext) {
				t.Errorf("Ciphertext length %d != plaintext length %d",
					len(ciphertext), len(tc.plaintext))
			}

			// Дешифруем
			decrypted, err := modes.OFBDecrypt(ciphertext, key, iv)
			th.AssertNoErrorf(err, "OFB decryption failed")

			// Проверяем совпадение
			if !th.CompareBytes(tc.plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
			}
		})
	}
}

func TestCTR_EncryptDecrypt(t *testing.T) {
	th := tests.NewTestHelper(t)

	key := th.GenerateTestData(16)
	iv := th.GenerateTestData(16)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"Short", th.GenerateTestData(10)},
		{"OneBlock", th.GenerateTestData(16)},
		{"TwoBlocks", th.GenerateTestData(32)},
		{"PartialBlock", th.GenerateTestData(20)},
		{"LargeData", th.GenerateTestData(1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Шифруем
			ciphertext, err := modes.CTREncryptWithIV(tc.plaintext, key, iv)
			th.AssertNoErrorf(err, "CTR encryption failed")

			// Длина ciphertext должна быть равна длине plaintext
			if len(ciphertext) != len(tc.plaintext) {
				t.Errorf("Ciphertext length %d != plaintext length %d",
					len(ciphertext), len(tc.plaintext))
			}

			// Дешифруем
			decrypted, err := modes.CTRDecrypt(ciphertext, key, iv)
			th.AssertNoErrorf(err, "CTR decryption failed")

			// Проверяем совпадение
			if !th.CompareBytes(tc.plaintext, decrypted) {
				t.Error("Decrypted text doesn't match original")
			}
		})
	}
}

func TestModes_InvalidParameters(t *testing.T) {
	th := tests.NewTestHelper(t)

	validKey := th.GenerateTestData(16)
	validIV := th.GenerateTestData(16)
	validData := th.GenerateTestData(32)

	testCases := []struct {
		name      string
		mode      string
		key       []byte
		iv        []byte
		data      []byte
		encrypt   bool
		expectErr bool
	}{
		// ECB - не требует IV
		{
			name:      "ECB valid",
			mode:      "ecb",
			key:       validKey,
			iv:        nil,
			data:      validData,
			encrypt:   true,
			expectErr: false,
		},
		{
			name:      "ECB wrong key size",
			mode:      "ecb",
			key:       th.GenerateTestData(15),
			iv:        nil,
			data:      validData,
			encrypt:   true,
			expectErr: true,
		},

		// CBC
		{
			name:      "CBC valid",
			mode:      "cbc",
			key:       validKey,
			iv:        validIV,
			data:      validData,
			encrypt:   true,
			expectErr: false,
		},
		{
			name:      "CBC wrong IV size",
			mode:      "cbc",
			key:       validKey,
			iv:        th.GenerateTestData(15),
			data:      validData,
			encrypt:   true,
			expectErr: true,
		},
		{
			name:      "CBC wrong key size",
			mode:      "cbc",
			key:       th.GenerateTestData(15),
			iv:        validIV,
			data:      validData,
			encrypt:   true,
			expectErr: true,
		},

		// CFB
		{
			name:      "CFB valid",
			mode:      "cfb",
			key:       validKey,
			iv:        validIV,
			data:      validData,
			encrypt:   true,
			expectErr: false,
		},

		// OFB
		{
			name:      "OFB valid",
			mode:      "ofb",
			key:       validKey,
			iv:        validIV,
			data:      validData,
			encrypt:   true,
			expectErr: false,
		},

		// CTR
		{
			name:      "CTR valid",
			mode:      "ctr",
			key:       validKey,
			iv:        validIV,
			data:      validData,
			encrypt:   true,
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			switch tc.mode {
			case "ecb":
				if tc.encrypt {
					_, err = modes.ECBEncrypt(tc.data, tc.key)
				} else {
					_, err = modes.ECBDecrypt(tc.data, tc.key)
				}
			case "cbc":
				if tc.encrypt {
					_, err = modes.CBCEncryptWithIV(tc.data, tc.key, tc.iv)
				} else {
					_, err = modes.CBCDecrypt(tc.data, tc.key, tc.iv)
				}
			case "cfb":
				if tc.encrypt {
					_, err = modes.CFBEncryptWithIV(tc.data, tc.key, tc.iv)
				} else {
					_, err = modes.CFBDecrypt(tc.data, tc.key, tc.iv)
				}
			case "ofb":
				if tc.encrypt {
					_, err = modes.OFBEncryptWithIV(tc.data, tc.key, tc.iv)
				} else {
					_, err = modes.OFBDecrypt(tc.data, tc.key, tc.iv)
				}
			case "ctr":
				if tc.encrypt {
					_, err = modes.CTREncryptWithIV(tc.data, tc.key, tc.iv)
				} else {
					_, err = modes.CTRDecrypt(tc.data, tc.key, tc.iv)
				}
			}

			if tc.expectErr {
				th.AssertErrorf(err, "Expected error for %s", tc.name)
			} else {
				th.AssertNoErrorf(err, "Operation should succeed for %s", tc.name)
			}
		})
	}
}

func TestPKCS7_Padding(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name      string
		data      []byte
		blockSize int
	}{
		{"Empty", []byte{}, 16},
		{"OneByte", []byte{0x01}, 16},
		{"FullBlock", th.GenerateTestData(16), 16},
		{"PartialBlock", th.GenerateTestData(15), 16},
		{"TwoBlocks", th.GenerateTestData(32), 16},
		{"TwoBlocksPlusOne", th.GenerateTestData(33), 16},
		{"DifferentBlockSize", th.GenerateTestData(10), 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Добавляем padding
			padded := modes.PKCS7Pad(tc.data, tc.blockSize)

			// Проверяем длину
			if len(padded)%tc.blockSize != 0 {
				t.Errorf("Padded data length %d not multiple of block size %d",
					len(padded), tc.blockSize)
			}

			// Проверяем значение padding
			paddingByte := padded[len(padded)-1]
			if int(paddingByte) > tc.blockSize || int(paddingByte) == 0 {
				t.Errorf("Invalid padding byte: %d", paddingByte)
			}

			// Проверяем все байты padding
			for i := 0; i < int(paddingByte); i++ {
				if padded[len(padded)-1-i] != paddingByte {
					t.Errorf("Padding byte at position %d is %d, expected %d",
						len(padded)-1-i, padded[len(padded)-1-i], paddingByte)
				}
			}

			// Удаляем padding
			unpadded, err := modes.PKCS7Unpad(padded)
			th.AssertNoErrorf(err, "PKCS7Unpad failed")

			// Проверяем, что получили исходные данные
			if !th.CompareBytes(tc.data, unpadded) {
				t.Error("Unpadded data doesn't match original")
			}
		})
	}
}

func TestPKCS7_InvalidPadding(t *testing.T) {
	testCases := []struct {
		name      string
		data      []byte
		expectErr bool
	}{
		{
			name:      "Zero padding byte",
			data:      []byte{0x01, 0x02, 0x00},
			expectErr: true,
		},
		{
			name:      "Padding longer than data",
			data:      []byte{0x01, 0x10}, // padding = 16, data length = 2
			expectErr: true,
		},
		{
			name: "Inconsistent padding - действительно неконсистентный",
			// padding = 2, но предпоследний байт = 1 (должен быть 2)
			data:      []byte{0x01, 0x02, 0x03, 0x01, 0x02},
			expectErr: true,
		},
		{
			name: "Inconsistent padding - несколько байтов не совпадают",
			// padding = 3, но не все последние 3 байта равны 3
			data:      []byte{0x01, 0x02, 0x03, 0x02, 0x03, 0x03},
			expectErr: true,
		},
		{
			name:      "Empty data",
			data:      []byte{},
			expectErr: true,
		},
		{
			name:      "Valid padding - один байт padding",
			data:      []byte{0x01, 0x02, 0x03, 0x04, 0x01},
			expectErr: false,
		},
		{
			name:      "Valid padding - три байта padding",
			data:      []byte{0x01, 0x02, 0x03, 0x03, 0x03, 0x03},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := modes.PKCS7Unpad(tc.data)

			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected error for invalid padding in %s", tc.name)
				}
			} else {
				if err != nil {
					t.Errorf("Should accept valid padding in %s: %v", tc.name, err)
				}
			}
		})
	}
}

func TestCreateCipherBlock(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name      string
		key       []byte
		expectErr bool
	}{
		{"AES-128", th.GenerateTestData(16), false},
		{"AES-192", th.GenerateTestData(24), false},
		{"AES-256", th.GenerateTestData(32), false},
		{"Too short", th.GenerateTestData(15), true},
		{"Too long", th.GenerateTestData(33), true},
		{"Empty", []byte{}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block, err := modes.CreateCipherBlock(tc.key)

			if tc.expectErr {
				th.AssertErrorf(err, "Expected error for invalid key in %s", tc.name)
			} else {
				th.AssertNoErrorf(err, "Should create cipher block for %s", tc.name)
				if block == nil {
					t.Error("Block should not be nil")
				}
				// Проверяем размер блока
				if block.BlockSize() != 16 {
					t.Errorf("Expected block size 16, got %d", block.BlockSize())
				}
			}
		})
	}
}

func TestModes_DifferentKeySizes(t *testing.T) {
	th := tests.NewTestHelper(t)

	keySizes := []int{16, 24, 32}
	iv := th.GenerateTestData(16)
	plaintext := th.GenerateTestData(100)

	modesToTest := []struct {
		name     string
		testFunc func(key, iv, plaintext []byte) error
	}{
		{"CBC", func(key, iv, plaintext []byte) error {
			ciphertext, err := modes.CBCEncryptWithIV(plaintext, key, iv)
			if err != nil {
				return err
			}
			_, err = modes.CBCDecrypt(ciphertext, key, iv)
			return err
		}},
		{"CFB", func(key, iv, plaintext []byte) error {
			ciphertext, err := modes.CFBEncryptWithIV(plaintext, key, iv)
			if err != nil {
				return err
			}
			_, err = modes.CFBDecrypt(ciphertext, key, iv)
			return err
		}},
		{"OFB", func(key, iv, plaintext []byte) error {
			ciphertext, err := modes.OFBEncryptWithIV(plaintext, key, iv)
			if err != nil {
				return err
			}
			_, err = modes.OFBDecrypt(ciphertext, key, iv)
			return err
		}},
		{"CTR", func(key, iv, plaintext []byte) error {
			ciphertext, err := modes.CTREncryptWithIV(plaintext, key, iv)
			if err != nil {
				return err
			}
			_, err = modes.CTRDecrypt(ciphertext, key, iv)
			return err
		}},
	}

	for _, keySize := range keySizes {
		for _, mode := range modesToTest {
			t.Run(fmt.Sprintf("%s-Key%d", mode.name, keySize*8), func(t *testing.T) {
				key := th.GenerateTestData(keySize)

				err := mode.testFunc(key, iv, plaintext)
				th.AssertNoErrorf(err, "%s with key size %d failed", mode.name, keySize*8)
			})
		}
	}
}
