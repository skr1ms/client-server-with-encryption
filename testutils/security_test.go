package test_test

import (
	"fmt"
	"os"
	"testing"

	"client-server/testutils"
)

func TestMain(m *testing.M) {
	fmt.Println("Запуск тестов безопасности...")
	results := test.RunSecurityTests()

	fmt.Println("\nСводка результатов тестов безопасности:")
	for _, result := range results {
		status := "ПРОЙДЕН"
		if !result.Success {
			status = "НЕ ПРОЙДЕН"
		}
		fmt.Printf("- %-30s: %s (Шифрование: %d мс, Дешифрование: %d мс)\n",
			result.TestName, status, result.EncryptionTime, result.DecryptionTime)
	}
	os.Exit(m.Run())
}
