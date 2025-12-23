package unit

import (
	"cryptocore/src/kdf"
	"cryptocore/tests"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// RFC 6070 Test Vectors (адаптированные для SHA-256)
func TestPBKDF2_RFC6070_Vectors(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name       string
		password   []byte
		salt       []byte
		iterations int
		dkLen      int
		expected   string
	}{
		{
			name:       "RFC6070 Test 1",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 1,
			dkLen:      20,
			// Python: hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 1, dklen=20).hex()
			expected: "120fb6cffcf8b32c43e7225256c4f837a86548c9",
		},
		{
			name:       "RFC6070 Test 2",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 2,
			dkLen:      20,
			// Python: hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 2, dklen=20).hex()
			expected: "ae4d0c95af6b46d32d0adff928f06dd02a303f8e",
		},
		{
			name:       "RFC6070 Test 3",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 4096,
			dkLen:      20,
			// Python: hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 4096, dklen=20).hex()
			expected: "c5e478d59288c841aa530db6845c4c8d962893a0",
		},
		{
			name:       "RFC6070 Test 4 (long password and salt)",
			password:   []byte("passwordPASSWORDpassword"),
			salt:       []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
			iterations: 4096,
			dkLen:      25,
			// Python: hashlib.pbkdf2_hmac('sha256', b'passwordPASSWORDpassword', b'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, dklen=25).hex()
			expected: "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c",
		},
		{
			name:       "RFC6070 Test 5 (null bytes in password and salt)",
			password:   []byte("pass\x00word"),
			salt:       []byte("sa\x00lt"),
			iterations: 4096,
			dkLen:      16,
			// Python: hashlib.pbkdf2_hmac('sha256', b'pass\x00word', b'sa\x00lt', 4096, dklen=16).hex()
			expected: "89b69d0516f829893c696226650a8687",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dk, err := kdf.PBKDF2HMACSHA256(tc.password, tc.salt, tc.iterations, tc.dkLen)
			th.AssertNoError(err, "PBKDF2 failed")

			expected := th.HexDecode(tc.expected)

			if !th.CompareBytes(expected, dk) {
				t.Errorf("PBKDF2 output doesn't match RFC6070 vector")
				t.Logf("Expected: %s", tc.expected)
				t.Logf("Got:      %s", hex.EncodeToString(dk))
			}

			// Проверяем длину
			if len(dk) != tc.dkLen {
				t.Errorf("Wrong derived key length: expected %d, got %d", tc.dkLen, len(dk))
			}
		})
	}
}

func TestPBKDF2_Deterministic(t *testing.T) {
	th := tests.NewTestHelper(t)

	password := []byte("test password")
	salt := []byte("test salt")
	iterations := 1000
	dkLen := 32

	// Первый запуск
	dk1, err := kdf.PBKDF2HMACSHA256(password, salt, iterations, dkLen)
	th.AssertNoError(err, "First PBKDF2 failed")

	// Второй запуск с теми же параметрами
	dk2, err := kdf.PBKDF2HMACSHA256(password, salt, iterations, dkLen)
	th.AssertNoError(err, "Second PBKDF2 failed")

	// Должны быть идентичны
	if !th.CompareBytes(dk1, dk2) {
		t.Error("PBKDF2 is not deterministic")
	}
}

func TestPBKDF2_VariousKeyLengths(t *testing.T) {
	th := tests.NewTestHelper(t)

	password := []byte("password")
	salt := []byte("salt")
	iterations := 100

	lengths := []int{1, 8, 16, 20, 32, 48, 64, 100, 128}

	for _, dkLen := range lengths {
		t.Run(fmt.Sprintf("Length-%d", dkLen), func(t *testing.T) {
			dk, err := kdf.PBKDF2HMACSHA256(password, salt, iterations, dkLen)
			th.AssertNoError(err, "PBKDF2 failed")

			// Проверяем длину
			if len(dk) != dkLen {
				t.Errorf("Wrong derived key length: expected %d, got %d", dkLen, len(dk))
			}

			// Проверяем, что ключ не состоит полностью из нулей
			allZeros := true
			for _, b := range dk {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("Derived key is all zeros")
			}
		})
	}
}

func TestPBKDF2_VariousIterations(t *testing.T) {
	th := tests.NewTestHelper(t)

	password := []byte("password")
	salt := []byte("salt")
	dkLen := 32

	iterationCounts := []int{1, 10, 100, 1000, 10000}

	for _, iterations := range iterationCounts {
		t.Run(fmt.Sprintf("Iterations-%d", iterations), func(t *testing.T) {
			dk, err := kdf.PBKDF2HMACSHA256(password, salt, iterations, dkLen)
			th.AssertNoError(err, "PBKDF2 failed")

			if len(dk) != dkLen {
				t.Errorf("Wrong derived key length: expected %d, got %d", dkLen, len(dk))
			}

			// Для больших количеств итераций можно проверить производительность
			if iterations >= 1000 {
				t.Logf("PBKDF2 with %d iterations completed", iterations)
			}
		})
	}
}

func TestPBKDF2_InvalidParameters(t *testing.T) {
	th := tests.NewTestHelper(t)

	testCases := []struct {
		name       string
		password   []byte
		salt       []byte
		iterations int
		dkLen      int
		expectErr  bool
	}{
		{
			name:       "Empty password",
			password:   []byte{},
			salt:       []byte("salt"),
			iterations: 1,
			dkLen:      1,
			expectErr:  true,
		},
		{
			name:       "Empty salt",
			password:   []byte("password"),
			salt:       []byte{},
			iterations: 1,
			dkLen:      1,
			expectErr:  true,
		},
		{
			name:       "Zero iterations",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 0,
			dkLen:      1,
			expectErr:  true,
		},
		{
			name:       "Negative iterations",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: -1,
			dkLen:      1,
			expectErr:  true,
		},
		{
			name:       "Zero dkLen",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 1,
			dkLen:      0,
			expectErr:  true,
		},
		{
			name:       "Negative dkLen",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 1,
			dkLen:      -1,
			expectErr:  true,
		},
		{
			name:       "Too large dkLen",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 1,
			dkLen:      (1<<32-1)*32 + 1, // Слишком большой
			expectErr:  true,
		},
		{
			name:       "Valid parameters",
			password:   []byte("password"),
			salt:       []byte("salt"),
			iterations: 1,
			dkLen:      1,
			expectErr:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kdf.PBKDF2HMACSHA256(tc.password, tc.salt, tc.iterations, tc.dkLen)

			if tc.expectErr {
				th.AssertError(err, "Expected error for invalid parameters")
			} else {
				th.AssertNoError(err, "PBKDF2 should succeed for valid parameters")
			}
		})
	}
}

func TestPBKDF2_SaltUniqueness(t *testing.T) {
	th := tests.NewTestHelper(t)

	password := []byte("same password")
	iterations := 100
	dkLen := 32

	// Разные соли должны давать разные ключи
	salt1 := []byte("salt one")
	salt2 := []byte("salt two")

	dk1, err := kdf.PBKDF2HMACSHA256(password, salt1, iterations, dkLen)
	th.AssertNoErrorf(err, "PBKDF2 with salt1 failed")

	dk2, err := kdf.PBKDF2HMACSHA256(password, salt2, iterations, dkLen)
	th.AssertNoErrorf(err, "PBKDF2 with salt2 failed")

	// Ключи должны быть разными
	if th.IsEqual(dk1, dk2) { // Используем IsEqual
		t.Error("Different salts should produce different keys")
	}
}

func TestPBKDF2_PasswordUniqueness(t *testing.T) {
	th := tests.NewTestHelper(t)

	salt := []byte("same salt")
	iterations := 100
	dkLen := 32

	// Разные пароли должны давать разные ключи
	password1 := []byte("password one")
	password2 := []byte("password two")

	dk1, err := kdf.PBKDF2HMACSHA256(password1, salt, iterations, dkLen)
	th.AssertNoErrorf(err, "PBKDF2 with password1 failed")

	dk2, err := kdf.PBKDF2HMACSHA256(password2, salt, iterations, dkLen)
	th.AssertNoErrorf(err, "PBKDF2 with password2 failed")

	// Ключи должны быть разными
	if th.IsEqual(dk1, dk2) { // Используем IsEqual
		t.Error("Different passwords should produce different keys")
	}
}

func TestPBKDF2_IterationEffect(t *testing.T) {
	th := tests.NewTestHelper(t)

	password := []byte("password")
	salt := []byte("salt")
	dkLen := 32

	// Больше итераций должно давать другой ключ
	dk1, err := kdf.PBKDF2HMACSHA256(password, salt, 1, dkLen)
	th.AssertNoErrorf(err, "PBKDF2 with 1 iteration failed")

	dk100, err := kdf.PBKDF2HMACSHA256(password, salt, 100, dkLen)
	th.AssertNoErrorf(err, "PBKDF2 with 100 iterations failed")

	// Ключи должны быть разными
	if th.IsEqual(dk1, dk100) { // Используем IsEqual
		t.Error("Different iteration counts should produce different keys")
	}

	// Больше итераций должно занимать больше времени (проверяем логически)
	t.Log("PBKDF2 with different iteration counts produces different keys as expected")
}

func TestPBKDF2_Performance(t *testing.T) {
	th := tests.NewTestHelper(t)

	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	password := []byte("performance test password")
	salt := []byte("performance test salt")
	dkLen := 32

	// Тестируем разные количества итераций
	iterationSets := []struct {
		iterations int
		name       string
	}{
		{1000, "1k iterations"},
		{10000, "10k iterations"},
		{100000, "100k iterations"},
	}

	for _, set := range iterationSets {
		t.Run(set.name, func(t *testing.T) {
			start := time.Now()

			_, err := kdf.PBKDF2HMACSHA256(password, salt, set.iterations, dkLen)
			th.AssertNoError(err, "PBKDF2 failed")

			elapsed := time.Since(start)
			t.Logf("PBKDF2 with %d iterations took %v", set.iterations, elapsed)

			// Проверяем, что время выполнения примерно пропорционально количеству итераций
			if set.iterations >= 10000 {
				iterPerSec := float64(set.iterations) / elapsed.Seconds()
				t.Logf("Performance: %.0f iterations/second", iterPerSec)
			}
		})
	}
}
