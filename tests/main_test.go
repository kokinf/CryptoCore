package tests

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

var (
	runUnitTests        bool
	runIntegrationTests bool
	runVectorTests      bool
	runBenchmarks       bool
	runNegativeTests    bool
	runMemoryTests      bool
	runAllTests         bool
	testVerbose         bool
)

func init() {
	flag.BoolVar(&runUnitTests, "unit", false, "Run unit tests")
	flag.BoolVar(&runIntegrationTests, "integration", false, "Run integration tests")
	flag.BoolVar(&runVectorTests, "vectors", false, "Run known-answer vector tests")
	flag.BoolVar(&runBenchmarks, "bench", false, "Run benchmarks")
	flag.BoolVar(&runNegativeTests, "negative", false, "Run negative/error tests")
	flag.BoolVar(&runMemoryTests, "memory", false, "Run memory safety tests")
	flag.BoolVar(&runAllTests, "all", false, "Run all tests")
	flag.BoolVar(&testVerbose, "v", false, "Verbose output")
	flag.Parse()
}

func TestMain(m *testing.M) {
	if runAllTests {
		runUnitTests = true
		runIntegrationTests = true
		runVectorTests = true
		runNegativeTests = true
		runMemoryTests = true
	}

	if !runUnitTests && !runIntegrationTests && !runVectorTests &&
		!runNegativeTests && !runMemoryTests && !runAllTests {
		runAllTests = true
	}

	fmt.Println("=== CryptoCore Test Suite ===")
	fmt.Println("Test categories to run:")
	if runUnitTests {
		fmt.Println("  - Unit tests")
	}
	if runIntegrationTests {
		fmt.Println("  - Integration tests")
	}
	if runVectorTests {
		fmt.Println("  - Known-answer vector tests")
	}
	if runBenchmarks {
		fmt.Println("  - Benchmarks")
	}
	if runNegativeTests {
		fmt.Println("  - Negative/error tests")
	}
	if runMemoryTests {
		fmt.Println("  - Memory safety tests")
	}
	fmt.Println()

	// Устанавливаем флаг verbose для всех тестов
	if testVerbose {
		testing.Verbose()
	}

	// Запускаем тесты
	result := m.Run()

	if result == 0 {
		fmt.Println("\nAll tests passed!")
	} else {
		fmt.Println("\nSome tests failed")
	}

	os.Exit(result)
}
