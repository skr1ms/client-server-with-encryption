package main

import (
	attack "client-server/tests/attack_tests"
	"client-server/tests/benchmark"
	"client-server/tests/utils"
	"fmt"
)

func main() {
	fmt.Println("=== ЗАПУСК ВСЕХ ТЕСТОВ БЕЗОПАСНОСТИ ===")
	fmt.Println()
	// 1. Функциональные тесты безопасности
	fmt.Println("1. Запуск функциональных тестов безопасности...")
	securityResults := utils.RunSecurityTests()

	passedTests := 0
	for _, result := range securityResults {
		status := "✗ FAIL"
		if result.Success {
			status = "✓ PASS"
			passedTests++
		}
		fmt.Printf("   %s %s\n", status, result.TestName)
	}
	fmt.Printf("   Пройдено: %d/%d тестов\n\n", passedTests, len(securityResults))

	// 2. Тесты атак
	fmt.Println("2. Запуск тестов устойчивости к атакам...")
	attackResults := attack.RunAllAttackTests()
	for _, result := range attackResults {
		status := "✗ УЯЗВИМ"
		if result.SecurityLevel == "ОТРАЖЕНО" {
			status = "✓ ЗАЩИЩЕНО"
		}
		fmt.Printf("   %s %s (%s)\n", status, result.AttackType, result.SecurityLevel)
	}
	fmt.Println()

	// 3. Нагрузочные тесты
	fmt.Println("3. Запуск нагрузочных тестов производительности...")
	loadResults := benchmark.RunComprehensiveLoadTests()

	for clientType, result := range loadResults {
		fmt.Printf("   %s: %.0f ops/sec (%.2f%% error rate)\n",
			clientType, result.ThroughputOpsPerSec, result.ErrorRate)
	}

	fmt.Println("\n=== ИТОГОВЫЙ ОТЧЕТ ===")
	fmt.Printf("• Безопасность: %d/%d тестов пройдено\n", passedTests, len(securityResults))
	fmt.Printf("• Атаки: %d/%d типов атак отражено\n",
		countDefendedAttacks(attackResults), len(attackResults))
	fmt.Printf("• Производительность: проверена для %d типов клиентов\n", len(loadResults))
}

func countDefendedAttacks(results []attack.AttackTestResult) int {
	count := 0
	for _, result := range results {
		if result.SecurityLevel == "ОТРАЖЕНО" {
			count++
		}
	}
	return count
}
