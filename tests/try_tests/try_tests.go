package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"client-server/tests/attack_tests"
	"client-server/tests/benchmark"
	"client-server/tests/metrics"
)

func main() {
	fmt.Println("===============================================")
	fmt.Println("  ДЕМОНСТРАЦИЯ КРИПТОГРАФИЧЕСКОЙ СИСТЕМЫ")
	fmt.Println("===============================================")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--attacks":
			runAttackTests()
			return
		case "--load":
			runLoadTests()
			return
		case "--efficiency":
			demonstrateEfficiencyCalculation()
			return
		default:
			printUsage()
			return
		}
	}

	printUsage()
}

func printUsage() {
	fmt.Println("Использование:")
	fmt.Println("  go run try_tests.go --attacks       - Тесты атак")
	fmt.Println("  go run try_tests.go --load          - Нагрузочные тесты")
	fmt.Println("  go run try_tests.go --efficiency    - Демонстрация расчета эффективности")
}

func runAttackTests() {
	fmt.Println("\n=== ТЕСТЫ УСТОЙЧИВОСТИ К АТАКАМ ===")

	results := attack_tests.RunAllAttackTests()
	attack_tests.AnalyzeAttackResults(results)
}

func runLoadTests() {
	fmt.Println("\n=== НАГРУЗОЧНЫЕ ТЕСТЫ ===")

	results := benchmark.RunComprehensiveLoadTests()
	benchmark.CompareClientPerformance(results)

	// Экспорт результатов
	fmt.Println("\nЭкспорт результатов в JSON...")
	if err := benchmark.ExportResults(results, "load_test_results.json"); err != nil {
		fmt.Printf("Ошибка экспорта: %v\n", err)
	} else {
		fmt.Println("✓ Результаты сохранены в load_test_results.json")
	}
}

func demonstrateEfficiencyCalculation() {
	fmt.Println("\n=== ДЕМОНСТРАЦИЯ РАСЧЕТА ЭФФЕКТИВНОСТИ ===")
	fmt.Println("Согласно формуле из Задание.txt:")
	fmt.Println("E = w1⋅T'enc + w2⋅T'dec + w3⋅K' + w4⋅P'attack")

	// Создаем разные сценарии для демонстрации
	scenarios := []struct {
		name        string
		encTime     time.Duration
		decTime     time.Duration
		keyLength   int
		attackProb  float64
		description string
	}{
		{
			name:        "Оптимальный",
			encTime:     10 * time.Millisecond,
			decTime:     15 * time.Millisecond,
			keyLength:   256,
			attackProb:  0.0001,
			description: "Быстрое шифрование, AES-256, низкая вероятность атаки",
		},
		{
			name:        "Медленный",
			encTime:     100 * time.Millisecond,
			decTime:     120 * time.Millisecond,
			keyLength:   256,
			attackProb:  0.0001,
			description: "Медленное шифрование, AES-256, низкая вероятность атаки",
		},
		{
			name:        "Слабый ключ",
			encTime:     10 * time.Millisecond,
			decTime:     15 * time.Millisecond,
			keyLength:   128,
			attackProb:  0.01,
			description: "Быстрое шифрование, AES-128, повышенная вероятность атаки",
		},
		{
			name:        "Максимальный",
			encTime:     5 * time.Millisecond,
			decTime:     7 * time.Millisecond,
			keyLength:   4096,
			attackProb:  0.00001,
			description: "Очень быстрое шифрование, RSA-4096, минимальная вероятность атаки",
		},
	}

	fmt.Printf("\n%-12s %-15s %-15s %-12s %-12s %-12s\n",
		"Сценарий", "Шифрование", "Расшифровка", "Ключ", "Вер.атаки", "Эффективность")
	fmt.Println(strings.Repeat("-", 90))

	for _, scenario := range scenarios {
		stats := metrics.NewSecurityStats()
		stats.RecordEncryptionTime(scenario.encTime)
		stats.RecordDecryptionTime(scenario.decTime)
		stats.SetKeyLength(scenario.keyLength)
		stats.SetAttackProbability(scenario.attackProb)

		efficiency := stats.CalculateEfficiencyScore()

		fmt.Printf("%-12s %-15s %-15s %-12d %-12.6f %-12.4f\n",
			scenario.name,
			scenario.encTime.String(),
			scenario.decTime.String(),
			scenario.keyLength,
			scenario.attackProb,
			efficiency)

		fmt.Printf("    %s\n", scenario.description)
	}

	fmt.Println("\nДетальный расчет для оптимального сценария:")
	stats := metrics.NewSecurityStats()
	stats.RecordEncryptionTime(scenarios[0].encTime)
	stats.RecordDecryptionTime(scenarios[0].decTime)
	stats.SetKeyLength(scenarios[0].keyLength)
	stats.SetAttackProbability(scenarios[0].attackProb)
	stats.PrintDetailedReport()
}
