package security_tests

import (
	"fmt"
	"os"
	"testing"

	"client-server/tests/utils"
)

func TestMain(m *testing.M) {
	fmt.Println("Запуск тестов безопасности...")
	results := utils.RunSecurityTests()
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
