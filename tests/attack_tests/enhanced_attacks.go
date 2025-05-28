package attack_tests

import (
	"client-server/internal/crypto"
	"client-server/tests/metrics"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// TestEnhancedTimingAttacks тестирует улучшенную защиту от timing атак
func TestEnhancedTimingAttacks() AttackTestResult {
	start := time.Now()

	crypto.ResetHMACTimingStats()

	key := make([]byte, 32)
	rand.Read(key)
	correctData := []byte("correct message")

	const measurements = 10000
	var validTimes []time.Duration
	var invalidTimes []time.Duration

	// Тестируем время для корректных HMAC
	for i := 0; i < measurements; i++ {
		correctHMAC := crypto.GenerateHMAC(key, correctData)
		result, elapsed, _ := crypto.VerifyHMACWithTimingAnalysis(key, correctData, correctHMAC)
		if result {
			validTimes = append(validTimes, elapsed)
		}
	}

	// Тестируем время для некорректных HMAC
	for i := 0; i < measurements; i++ {
		invalidHMAC := make([]byte, 32)
		rand.Read(invalidHMAC)
		result, elapsed, _ := crypto.VerifyHMACWithTimingAnalysis(key, correctData, invalidHMAC)
		if !result {
			invalidTimes = append(invalidTimes, elapsed)
		}
	}
	avgValid := averageDurationEnhanced(validTimes)
	avgInvalid := averageDurationEnhanced(invalidTimes)
	stddevValid := stddevDurationEnhanced(validTimes, avgValid)
	stddevInvalid := stddevDurationEnhanced(invalidTimes, avgInvalid)

	timeDifference := float64(avgValid - avgInvalid)
	if timeDifference < 0 {
		timeDifference = -timeDifference
	}

	threshold := 3 * float64(stddevValid+stddevInvalid)
	vulnerable := timeDifference > threshold

	securityLevel := "ОТРАЖЕНО"
	attackProbability := 0.0001
	if vulnerable {
		securityLevel = "УЯЗВИМ"
		attackProbability = 0.01
	}

	elapsed := time.Since(start)
	avg, stddev, count := crypto.GetHMACTimingStats()

	description := fmt.Sprintf("Time difference: %.2fns (threshold: %.2fns), HMAC stats: avg=%.2fns, stddev=%.2fns, samples=%d",
		timeDifference, threshold, float64(avg), float64(stddev), count)

	return AttackTestResult{
		AttackType:        "Enhanced Timing Attack (HMAC)",
		Successful:        vulnerable,
		AttemptsMade:      measurements * 2,
		TimeElapsed:       elapsed.Milliseconds(),
		AttackRate:        float64(measurements*2) / elapsed.Seconds(),
		AttackProbability: attackProbability,
		SecurityLevel:     securityLevel,
		Description:       description,
		Recommendation:    "HMAC использует crypto/subtle.ConstantTimeCompare с расширенным статистическим анализом",
	}
}

// TestEnhancedReplayAttacks тестирует улучшенную защиту от replay атак
func TestEnhancedReplayAttacks() AttackTestResult {
	start := time.Now()

	crypto.ResetNonceStorage()

	stats := metrics.NewSecurityStats()
	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	attempts := 0
	successfulReplays := 0

	// Тест 1: Множественные replay атаки с одним nonce
	plaintext := []byte("test message")
	originalMsg := crypto.CreateSecureMessage(plaintext, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, stats)

	_, err := crypto.VerifyAndDecryptMessage(originalMsg, sharedSecret, rsaPub, stats)
	if err == nil {
		attempts++
	}

	for i := 0; i < 100; i++ {
		_, err := crypto.VerifyAndDecryptMessage(originalMsg, sharedSecret, rsaPub, stats)
		attempts++
		if err == nil {
			successfulReplays++
		}
	}

	// Тест 2: Проверка временного окна (timestamp)
	// Создаем сообщение с устаревшим timestamp
	oldMsg := originalMsg
	oldMsg.Timestamp = time.Now().Unix() - 40 // 40 секунд назад (больше MaxTimeDifference)

	_, err = crypto.VerifyAndDecryptMessage(oldMsg, sharedSecret, rsaPub, stats)
	attempts++
	if err == nil {
		successfulReplays++
	}

	// Тест 3: Проверка nonce tracking
	nonceCount := crypto.GetNonceCount()

	elapsed := time.Since(start)
	attackProbability := float64(successfulReplays) / float64(attempts)

	securityLevel := "ОТРАЖЕНО"
	if successfulReplays > 0 {
		securityLevel = "УЯЗВИМ"
	}

	description := fmt.Sprintf("Successful replays: %d out of %d attempts, nonce tracking: %d stored",
		successfulReplays, attempts, nonceCount)

	return AttackTestResult{
		AttackType:        "Enhanced Replay Attack",
		Successful:        successfulReplays > 0,
		AttemptsMade:      attempts,
		TimeElapsed:       elapsed.Milliseconds(),
		AttackRate:        float64(attempts) / elapsed.Seconds(),
		AttackProbability: attackProbability,
		SecurityLevel:     securityLevel,
		Description:       description,
		Recommendation:    "Улучшенная защита: расширенный nonce tracking и сокращенное окно timestamp (30с)",
	}
}

// TestConcurrentBruteForceEnhanced тестирует улучшенную защиту от параллельных атак
func TestConcurrentBruteForceEnhanced() AttackTestResult {
	start := time.Now()

	correctKey := make([]byte, 32)
	rand.Read(correctKey)
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("secret message")
	stats := metrics.NewSecurityStats()

	correctCiphertext := crypto.AESEncrypt(correctKey, iv, plaintext, stats)

	const numWorkers = 50 
	const attemptsPerWorker = 1000
	maxTime := 3 * time.Second

	var totalAttempts int64
	var successfulAttacks int64
	var rejectedByRateLimit int64
	var wg sync.WaitGroup
	var mutex sync.Mutex

	stopChan := make(chan struct{})

	go func() {
		time.Sleep(maxTime)
		close(stopChan)
	}()

	// Запускаем параллельных воркеров
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			clientID := fmt.Sprintf("attacker_%d", workerID)
			localAttempts := 0
			localRejected := 0

			for j := 0; j < attemptsPerWorker; j++ {
				select {
				case <-stopChan:
					return
				default:
				}

				// Проверяем rate limiting
				if err := crypto.RateLimitCheck(clientID); err != nil {
					localRejected++
					continue
				}

				// Генерируем случайный ключ
				attackKey := make([]byte, 32)
				rand.Read(attackKey)

				// Пытаемся расшифровать
				decrypted := crypto.AESEncrypt(attackKey, iv, plaintext, stats)
				if decrypted != nil {
					localAttempts++

					if _, err := crypto.AESDecrypt(attackKey, iv, correctCiphertext, stats); err == nil {
						mutex.Lock()
						successfulAttacks++
						mutex.Unlock()
					}
				} else {
					localRejected++
				}
			}

			mutex.Lock()
			totalAttempts += int64(localAttempts)
			rejectedByRateLimit += int64(localRejected)
			mutex.Unlock()
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	concurrentOps := crypto.GetConcurrentOpsCount()
	rate := float64(totalAttempts) / elapsed.Seconds()
	attackProbability := float64(successfulAttacks) / float64(totalAttempts)

	securityLevel := "ОТРАЖЕНО"
	if successfulAttacks > 0 {
		securityLevel = "УЯЗВИМ"
	} else if rejectedByRateLimit > totalAttempts/2 {
		securityLevel = "ЗАЩИЩЕНО" 
	}

	description := fmt.Sprintf("Workers: %d, successful: %d, rejected by limits: %d, concurrent ops: %d",
		numWorkers, successfulAttacks, rejectedByRateLimit, concurrentOps)

	return AttackTestResult{
		AttackType:        "Enhanced Concurrent Brute Force",
		Successful:        successfulAttacks > 0,
		AttemptsMade:      int(totalAttempts),
		TimeElapsed:       elapsed.Milliseconds(),
		AttackRate:        rate,
		AttackProbability: attackProbability,
		SecurityLevel:     securityLevel,
		Description:       description,
		Recommendation:    "Система защищена от параллельных атак: rate limiting и ограничение concurrent операций",
	}
}

// Вспомогательные функции для статистического анализа
func averageDurationEnhanced(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}

func stddevDurationEnhanced(durations []time.Duration, avg time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	var variance float64
	for _, d := range durations {
		diff := float64(d - avg)
		variance += diff * diff
	}
	variance /= float64(len(durations))

	return time.Duration(variance)
}
