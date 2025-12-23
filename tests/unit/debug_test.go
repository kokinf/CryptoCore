package unit

import (
	"cryptocore/src/kdf"
	"cryptocore/src/modes"
	"cryptocore/tests"
	"fmt"
	"testing"
)

func TestDebugPKCS7_Detailed(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x02, 0x01}

	fmt.Println("\n=== Debug PKCS7Unpad ===")
	fmt.Printf("Input data: %v\n", data)
	fmt.Printf("Data hex: %x\n", data)
	fmt.Printf("Length: %d\n", len(data))
	fmt.Printf("Last byte: 0x%02x = %d (this is padding value)\n",
		data[len(data)-1], data[len(data)-1])

	// Проверяем вручную то, что должен делать PKCS7Unpad
	padding := int(data[len(data)-1])
	fmt.Printf("\nPadding value from last byte: %d\n", padding)

	if padding == 0 {
		fmt.Println("Padding is 0 → should error")
	}

	if padding > len(data) {
		fmt.Printf("Padding %d > data length %d → should error\n", padding, len(data))
	}

	fmt.Println("\nChecking padding bytes (should all equal padding value):")
	allGood := true
	for i := 1; i <= padding; i++ {
		idx := len(data) - i
		val := data[idx]
		expected := byte(padding)
		good := val == expected
		fmt.Printf("  data[%d] = 0x%02x (expected 0x%02x) → %v\n",
			idx, val, expected, good)
		if !good {
			allGood = false
		}
	}

	if !allGood {
		fmt.Println("Padding bytes inconsistent → should error")
	} else {
		fmt.Println("All padding bytes consistent → should succeed")
	}

	// Теперь вызываем реальную функцию
	fmt.Println("\nCalling actual PKCS7Unpad:")
	result, err := modes.PKCS7Unpad(data)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %v\n", result)
		fmt.Printf("Result hex: %x\n", result)
		fmt.Printf("Result length: %d\n", len(result))
	}
}

func TestDebugHKDF(t *testing.T) {
	th := tests.NewTestHelper(t)

	// Воспроизводим тест из kdf_test.go
	salt1 := th.GenerateTestData(32)
	salt2 := th.GenerateTestData(32)
	ikm := th.GenerateTestData(64)

	fmt.Printf("Salt1: %x...\n", salt1[:8])
	fmt.Printf("Salt2: %x...\n", salt2[:8])
	fmt.Printf("Are salts equal? %v\n", th.CompareBytes(salt1, salt2))

	prk1, err1 := kdf.HKDFExtract("sha256", salt1, ikm)
	prk2, err2 := kdf.HKDFExtract("sha256", salt2, ikm)

	if err1 != nil || err2 != nil {
		t.Fatalf("HKDFExtract failed: err1=%v, err2=%v", err1, err2)
	}

	fmt.Printf("PRK1: %x...\n", prk1[:8])
	fmt.Printf("PRK2: %x...\n", prk2[:8])
	fmt.Printf("Are PRKs equal? %v\n", th.CompareBytes(prk1, prk2))

	if th.CompareBytes(prk1, prk2) {
		t.Error("PRKs should be different with different salts")
	}
}

func TestDebugVerifyKey(t *testing.T) {
	th := tests.NewTestHelper(t)

	masterKey1 := th.GenerateTestData(32)
	masterKey2 := th.GenerateTestData(32) // Другой ключ
	context := "test-context"
	length := 32

	fmt.Printf("MasterKey1: %x...\n", masterKey1[:8])
	fmt.Printf("MasterKey2: %x...\n", masterKey2[:8])
	fmt.Printf("Are keys equal? %v\n", th.CompareBytes(masterKey1, masterKey2))

	// Вырабатываем ключ с первым мастер-ключом
	derivedKey, err := kdf.DeriveKey(masterKey1, context, length)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	fmt.Printf("DerivedKey: %x...\n", derivedKey[:8])

	// Проверяем с правильным ключом
	valid1, err1 := kdf.VerifyKeyDerivation(masterKey1, context, derivedKey)
	fmt.Printf("Verify with correct key: valid=%v, err=%v\n", valid1, err1)

	// Проверяем с неправильным ключом
	valid2, err2 := kdf.VerifyKeyDerivation(masterKey2, context, derivedKey)
	fmt.Printf("Verify with wrong key: valid=%v, err=%v\n", valid2, err2)

	if valid2 {
		t.Error("Verification should fail with wrong master key")
	}
}
