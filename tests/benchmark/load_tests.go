package benchmark

import (
	"client-server/internal/crypto"
	"client-server/tests/metrics"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ClientType представляет тип клиента
type ClientType string

const (
	MobileClient  ClientType = "Mobile"
	WebClient     ClientType = "Web"
	DesktopClient ClientType = "Desktop"
	ServerClient  ClientType = "Server"
)

// PerformanceProfile определяет профиль производительности для разных типов клиентов
type PerformanceProfile struct {
	ClientType      ClientType
	MessageSize     int
	ConcurrentUsers int
	TestDuration    time.Duration
	Description     string
}

// LoadTestResult представляет результаты нагрузочного теста
type LoadTestResult struct {
	ClientType          ClientType `json:"clientType"`
	ConcurrentUsers     int        `json:"concurrentUsers"`
	TotalOperations     int        `json:"totalOperations"`
	SuccessfulOps       int        `json:"successfulOperations"`
	FailedOps           int        `json:"failedOperations"`
	AvgEncryptionTime   float64    `json:"avgEncryptionTimeMs"`
	AvgDecryptionTime   float64    `json:"avgDecryptionTimeMs"`
	ThroughputOpsPerSec float64    `json:"throughputOpsPerSec"`
	TestDuration        int64      `json:"testDurationMs"`
	MemoryUsageMB       float64    `json:"memoryUsageMB"`
	CPUUsagePercent     float64    `json:"cpuUsagePercent"`
	ErrorRate           float64    `json:"errorRate"`
	EfficiencyScore     float64    `json:"efficiencyScore"`
}

// OperationResult представляет результат одной криптографической операции
type OperationResult struct {
	OperationID    int           `json:"operationId"`
	Success        bool          `json:"success"`
	EncryptionTime time.Duration `json:"encryptionTime"`
	DecryptionTime time.Duration `json:"decryptionTime"`
	Error          error         `json:"error,omitempty"`
	MessageSize    int           `json:"messageSize"`
	Timestamp      time.Time     `json:"timestamp"`
}

// ClientProfile определяет характеристики разных типов клиентов
type ClientProfile struct {
	MaxConcurrency  int
	MessageSize     int
	OperationsCount int
	TestDuration    time.Duration
}

// GetClientProfile возвращает профиль для указанного типа клиента
func GetClientProfile(clientType ClientType) ClientProfile {
	switch clientType {
	case MobileClient:
		return ClientProfile{
			MaxConcurrency:  10,  // Ограниченная мощность
			MessageSize:     512, // Меньшие сообщения
			OperationsCount: 100,
			TestDuration:    30 * time.Second,
		}
	case WebClient:
		return ClientProfile{
			MaxConcurrency:  25,
			MessageSize:     1024,
			OperationsCount: 250,
			TestDuration:    30 * time.Second,
		}
	case DesktopClient:
		return ClientProfile{
			MaxConcurrency:  50,
			MessageSize:     2048,
			OperationsCount: 500,
			TestDuration:    30 * time.Second,
		}
	case ServerClient:
		return ClientProfile{
			MaxConcurrency:  100,
			MessageSize:     4096,
			OperationsCount: 1000,
			TestDuration:    30 * time.Second,
		}
	default:
		return GetClientProfile(DesktopClient)
	}
}

// performCryptoOperation выполняет одну криптографическую операцию
func performCryptoOperation(opID int, messageSize int, sharedSecret []byte, ecdsaPriv, ecdsaPub interface{}, rsaPriv, rsaPub interface{}) OperationResult {

	result := OperationResult{
		OperationID: opID,
		MessageSize: messageSize,
		Timestamp:   time.Now(),
	}

	// Генерируем случайное сообщение
	message := make([]byte, messageSize)
	if _, err := rand.Read(message); err != nil {
		result.Error = fmt.Errorf("failed to generate random message: %v", err)
		result.Success = false
		return result
	}
	// Создаем stats для операций
	stats := metrics.NewSecurityStats()

	// Генерируем IV для AES
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		result.Error = fmt.Errorf("failed to generate IV: %v", err)
		result.Success = false
		return result
	}

	// Замеряем время шифрования
	encStart := time.Now()
	encryptedData := crypto.AESEncrypt(sharedSecret[:32], iv, message, stats)
	result.EncryptionTime = time.Since(encStart)

	// Замеряем время расшифровки
	decStart := time.Now()
	decryptedData, err := crypto.AESDecrypt(sharedSecret[:32], iv, encryptedData, stats)
	result.DecryptionTime = time.Since(decStart)

	if err != nil {
		result.Error = fmt.Errorf("decryption failed: %v", err)
		result.Success = false
		return result
	}

	// Проверяем корректность расшифровки
	if len(decryptedData) != len(message) {
		result.Error = fmt.Errorf("decrypted data length mismatch")
		result.Success = false
		return result
	}
	// Простая проверка целостности (сравнение первых и последних байт)
	if len(message) > 0 && (decryptedData[0] != message[0] ||
		decryptedData[len(decryptedData)-1] != message[len(message)-1]) {
		result.Error = fmt.Errorf("data integrity check failed")
		result.Success = false
		return result
	}
	result.Success = true
	return result
}

// RunLoadTest выполняет нагрузочный тест для указанного типа клиента
func RunLoadTest(clientType ClientType) LoadTestResult {
	profile := GetClientProfile(clientType)
	return runLoadTestWithProfile(clientType, profile.MaxConcurrency, profile.MessageSize, profile.TestDuration)
}

// RunLoadTestWithParams выполняет нагрузочный тест с пользовательскими параметрами
func RunLoadTestWithParams(clientType ClientType, concurrentUsers int, messageSize int, testDuration time.Duration) LoadTestResult {
	return runLoadTestWithProfile(clientType, concurrentUsers, messageSize, testDuration)
}

// runLoadTestWithProfile внутренняя функция для выполнения нагрузочного теста
func runLoadTestWithProfile(clientType ClientType, concurrentUsers int, messageSize int, testDuration time.Duration) LoadTestResult {
	// Вычисляем количество операций на основе длительности теста
	operationsCount := concurrentUsers * 10 // примерно 10 операций на пользователя

	fmt.Printf("Запуск нагрузочного теста для %s клиента...\n", clientType)
	fmt.Printf("Параметры: %d пользователей, %d операций, размер сообщения: %d байт\n",
		concurrentUsers, operationsCount, messageSize)

	// Начальные метрики памяти
	var startMemStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&startMemStats)

	start := time.Now()

	// Каналы для сбора результатов
	results := make(chan OperationResult, operationsCount)

	// Подготавливаем общие данные
	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	// WaitGroup для управления горутинами
	var wg sync.WaitGroup

	// Канал для ограничения количества одновременных операций
	semaphore := make(chan struct{}, concurrentUsers)

	// Запускаем операции
	for i := 0; i < operationsCount; i++ {
		wg.Add(1)
		go func(opID int) {
			defer wg.Done()

			// Получаем разрешение на выполнение
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := performCryptoOperation(opID, messageSize, sharedSecret,
				ecdsaPriv, ecdsaPub, rsaPriv, rsaPub)
			results <- result
		}(i)
	}

	// Ждем завершения всех операций
	go func() {
		wg.Wait()
		close(results)
	}()

	// Собираем результаты
	var (
		successfulOps = 0
		failedOps     = 0
		totalEncTime  = 0.0
		totalDecTime  = 0.0
	)

	for result := range results {
		if result.Success {
			successfulOps++
			totalEncTime += float64(result.EncryptionTime.Milliseconds())
			totalDecTime += float64(result.DecryptionTime.Milliseconds())
		} else {
			failedOps++
			fmt.Printf("Операция %d завершилась с ошибкой: %v\n", result.OperationID, result.Error)
		}
	}

	elapsed := time.Since(start)

	// Финальные метрики памяти
	var endMemStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&endMemStats)

	// Вычисляем метрики
	avgEncTime := 0.0
	avgDecTime := 0.0
	if successfulOps > 0 {
		avgEncTime = totalEncTime / float64(successfulOps)
		avgDecTime = totalDecTime / float64(successfulOps)
	}

	throughput := float64(successfulOps) / elapsed.Seconds()
	errorRate := float64(failedOps) / float64(operationsCount) * 100.0
	memoryUsageMB := float64(endMemStats.Alloc-startMemStats.Alloc) / 1024 / 1024

	// Примерная оценка использования CPU (упрощенная)
	cpuUsage := calculateCPUUsage(elapsed, concurrentUsers)

	result := LoadTestResult{
		ClientType:          clientType,
		ConcurrentUsers:     concurrentUsers,
		TotalOperations:     operationsCount,
		SuccessfulOps:       successfulOps,
		FailedOps:           failedOps,
		AvgEncryptionTime:   avgEncTime,
		AvgDecryptionTime:   avgDecTime,
		ThroughputOpsPerSec: throughput,
		TestDuration:        elapsed.Milliseconds(),
		MemoryUsageMB:       memoryUsageMB,
		CPUUsagePercent:     cpuUsage,
		ErrorRate:           errorRate,
	}
	// Выводим результаты
	printLoadTestResults(result)

	return result
}

// calculateCPUUsage вычисляет примерное использование CPU
func calculateCPUUsage(duration time.Duration, concurrency int) float64 {
	// Упрощенная формула: больше concurrent операций = больше CPU
	// В реальном приложении следует использовать более точные метрики
	baseUsage := 10.0                                       // базовое использование
	concurrencyFactor := float64(concurrency) / 10.0 * 15.0 // масштабирование по concurrency

	if concurrencyFactor > 80.0 {
		concurrencyFactor = 80.0 // ограничиваем максимум
	}

	return baseUsage + concurrencyFactor
}

// printLoadTestResults выводит результаты тестирования в консоль
func printLoadTestResults(result LoadTestResult) {
	fmt.Printf("\n=== Результаты нагрузочного тестирования ===\n")
	fmt.Printf("Тип клиента: %s\n", result.ClientType)
	fmt.Printf("Общее количество операций: %d\n", result.TotalOperations)
	fmt.Printf("Успешных операций: %d\n", result.SuccessfulOps)
	fmt.Printf("Неуспешных операций: %d\n", result.FailedOps)
	fmt.Printf("Процент ошибок: %.2f%%\n", result.ErrorRate)
	fmt.Printf("Среднее время шифрования: %.2f мс\n", result.AvgEncryptionTime)
	fmt.Printf("Среднее время расшифровки: %.2f мс\n", result.AvgDecryptionTime)
	fmt.Printf("Пропускная способность: %.2f оп/сек\n", result.ThroughputOpsPerSec)
	fmt.Printf("Продолжительность теста: %d мс\n", result.TestDuration)
	fmt.Printf("Использование памяти: %.2f МБ\n", result.MemoryUsageMB)
	fmt.Printf("Использование CPU: %.2f%%\n", result.CPUUsagePercent)
	fmt.Printf("Количество concurrent пользователей: %d\n", result.ConcurrentUsers)
	fmt.Printf("============================================\n\n")
}

// RunAllClientLoadTests запускает нагрузочные тесты для всех типов клиентов
func RunAllClientLoadTests() map[ClientType]LoadTestResult {
	clientTypes := []ClientType{MobileClient, WebClient, DesktopClient, ServerClient}
	results := make(map[ClientType]LoadTestResult)

	fmt.Println("Запуск полного набора нагрузочных тестов...")

	for _, clientType := range clientTypes {
		fmt.Printf("\n--- Тестирование %s клиента ---\n", clientType)
		results[clientType] = RunLoadTest(clientType)

		// Небольшая пауза между тестами для стабилизации системы
		time.Sleep(2 * time.Second)
	}

	// Сохраняем агрегированные результаты в файл
	saveResultsToFile(results)

	return results
}

// saveResultsToFile сохраняет результаты тестов в JSON файл
func saveResultsToFile(results map[ClientType]LoadTestResult) {
	fileName := fmt.Sprintf("load_test_results_%d.json", time.Now().Unix())

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Ошибка при сериализации результатов: %v\n", err)
		return
	}

	err = os.WriteFile(fileName, data, 0644)
	if err != nil {
		fmt.Printf("Ошибка при сохранении файла %s: %v\n", fileName, err)
		return
	}

	fmt.Printf("Результаты сохранены в файл: %s\n", fileName)
}

// CompareClientPerformance анализирует и сравнивает производительность разных типов клиентов
func CompareClientPerformance(results map[ClientType]LoadTestResult) {
	fmt.Println("\n=== СРАВНЕНИЕ ПРОИЗВОДИТЕЛЬНОСТИ КЛИЕНТОВ ===")

	// Сортируем результаты по эффективности
	type clientResult struct {
		ClientType ClientType
		Result     LoadTestResult
	}

	var sortedResults []clientResult
	for clientType, result := range results {
		sortedResults = append(sortedResults, clientResult{
			ClientType: clientType,
			Result:     result,
		})
	}

	// Сортировка по убыванию эффективности
	sort.Slice(sortedResults, func(i, j int) bool {
		return sortedResults[i].Result.EfficiencyScore > sortedResults[j].Result.EfficiencyScore
	})

	fmt.Printf("%-15s %-12s %-15s %-12s %-10s %-15s\n",
		"Клиент", "Операций/сек", "Время шифр. (мс)", "Время расшифр.", "Ошибки %", "Эффективность")
	fmt.Println(strings.Repeat("-", 90))

	for i, cr := range sortedResults {
		rank := i + 1
		fmt.Printf("%d. %-12s %-12.2f %-15.2f %-12.2f %-10.2f %-15.4f\n",
			rank,
			cr.ClientType,
			cr.Result.ThroughputOpsPerSec,
			cr.Result.AvgEncryptionTime,
			cr.Result.AvgDecryptionTime,
			cr.Result.ErrorRate,
			cr.Result.EfficiencyScore)
	}

	// Анализ результатов
	if len(sortedResults) > 0 {
		best := sortedResults[0]
		worst := sortedResults[len(sortedResults)-1]

		fmt.Printf("\n🏆 Лучший результат: %s (эффективность: %.4f)\n", best.ClientType, best.Result.EfficiencyScore)
		fmt.Printf("📉 Худший результат: %s (эффективность: %.4f)\n", worst.ClientType, worst.Result.EfficiencyScore)

		if best.Result.EfficiencyScore > 0 && worst.Result.EfficiencyScore > 0 {
			improvement := (best.Result.EfficiencyScore - worst.Result.EfficiencyScore) / worst.Result.EfficiencyScore * 100
			fmt.Printf("📊 Разница в производительности: %.1f%%\n", improvement)
		}
	}

	// Рекомендации
	fmt.Println("\n💡 РЕКОМЕНДАЦИИ:")
	for _, cr := range sortedResults {
		if cr.Result.ErrorRate > 5.0 {
			fmt.Printf("⚠️  %s: высокий уровень ошибок (%.1f%%) - требует оптимизации\n",
				cr.ClientType, cr.Result.ErrorRate)
		}
		if cr.Result.ThroughputOpsPerSec < 10 {
			fmt.Printf("🐌 %s: низкая пропускная способность (%.1f оп/сек) - требует масштабирования\n",
				cr.ClientType, cr.Result.ThroughputOpsPerSec)
		}
	}
}

// GetDefaultProfiles возвращает предустановленные профили для разных типов клиентов
func GetDefaultProfiles() []PerformanceProfile {
	return []PerformanceProfile{
		{
			ClientType:      MobileClient,
			MessageSize:     1024, // 1KB - типично для мобильных устройств
			ConcurrentUsers: 10,   // Меньше пользователей
			TestDuration:    30 * time.Second,
			Description:     "Мобильное устройство: малые сообщения, низкая нагрузка",
		},
		{
			ClientType:      WebClient,
			MessageSize:     4096, // 4KB - веб-формы и JSON
			ConcurrentUsers: 25,   // Средняя нагрузка
			TestDuration:    30 * time.Second,
			Description:     "Веб-клиент: средние сообщения, умеренная нагрузка",
		},
		{
			ClientType:      DesktopClient,
			MessageSize:     8192, // 8KB - файлы и документы
			ConcurrentUsers: 50,   // Высокая нагрузка
			TestDuration:    30 * time.Second,
			Description:     "Десктопное приложение: большие сообщения, высокая нагрузка",
		},
		{
			ClientType:      ServerClient,
			MessageSize:     16384, // 16KB - серверные данные
			ConcurrentUsers: 100,   // Максимальная нагрузка
			TestDuration:    30 * time.Second,
			Description:     "Сервер: крупные сообщения, максимальная нагрузка",
		},
	}
}

// RunComprehensiveLoadTests запускает комплексные нагрузочные тесты
func RunComprehensiveLoadTests() map[ClientType]LoadTestResult {
	profiles := GetDefaultProfiles()
	results := make(map[ClientType]LoadTestResult)

	fmt.Println("=== ЗАПУСК КОМПЛЕКСНЫХ НАГРУЗОЧНЫХ ТЕСТОВ ===")
	fmt.Printf("Будет протестировано %d типов клиентов\n", len(profiles))

	for i, profile := range profiles {
		fmt.Printf("\n[%d/%d] Тестирование %s\n", i+1, len(profiles), profile.ClientType)
		fmt.Printf("Описание: %s\n", profile.Description)
		fmt.Printf("Параметры: %d байт/сообщение, %d пользователей, %v\n",
			profile.MessageSize, profile.ConcurrentUsers, profile.TestDuration)

		result := RunLoadTestWithParams(profile.ClientType, profile.ConcurrentUsers, profile.MessageSize, profile.TestDuration)
		results[profile.ClientType] = result
		// Добавляем расчет показателя эффективности с учетом специфики устройства
		stats := metrics.NewSecurityStats()
		stats.RecordEncryptionTime(time.Duration(result.AvgEncryptionTime * float64(time.Millisecond)))
		stats.RecordDecryptionTime(time.Duration(result.AvgDecryptionTime * float64(time.Millisecond)))

		// Настраиваем параметры в зависимости от типа клиента
		switch profile.ClientType {
		case MobileClient:
			stats.SetKeyLength(128)           // Меньшая длина ключа для мобильных устройств
			stats.SetAttackProbability(0.001) // Немного выше вероятность атаки
		case WebClient:
			stats.SetKeyLength(192)            // Средняя безопасность для веб
			stats.SetAttackProbability(0.0005) // Средняя вероятность атаки
		case DesktopClient:
			stats.SetKeyLength(256)            // Стандартный AES-256
			stats.SetAttackProbability(0.0001) // Низкая вероятность атаки
		case ServerClient:
			stats.SetKeyLength(384)             // Повышенная безопасность для серверов
			stats.SetAttackProbability(0.00001) // Очень низкая вероятность атаки
		default:
			stats.SetKeyLength(256)
			stats.SetAttackProbability(0.0001)
		}

		result.EfficiencyScore = stats.CalculateEfficiencyScore()
		results[profile.ClientType] = result
		fmt.Printf("Результат: %.2f оп/сек, %.2f%% ошибок, эффективность: %.4f\n",
			result.ThroughputOpsPerSec, result.ErrorRate, result.EfficiencyScore)
	}

	// Сохраняем результаты в JSON файл с исправленными значениями efficiencyScore
	filename := fmt.Sprintf("load_test_results_%d.json", time.Now().Unix())
	ExportResults(results, filename)

	return results
}

// ExportResults экспортирует результаты нагрузочных тестов в JSON файл
func ExportResults(results map[ClientType]LoadTestResult, filename string) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %v", err)
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	fmt.Printf("Результаты экспортированы в: %s\n", filename)
	return nil
}
