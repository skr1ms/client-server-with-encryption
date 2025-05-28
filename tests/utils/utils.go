package utils

import (
	"bytes"
	"client-server/internal/crypto"
	"client-server/tests/metrics"
	"crypto/rand"
	"sync"
	"time"
)

type SecurityTestResult struct {
	TestName          string                 `json:"testName"`
	Success           bool                   `json:"success"`
	Description       string                 `json:"description"`
	MessageSize       int                    `json:"messageSize,omitempty"`
	EncryptionTime    int64                  `json:"encryptionTimeMs,omitempty"`
	DecryptionTime    int64                  `json:"decryptionTimeMs,omitempty"`
	SigningTime       int64                  `json:"signingTimeMs,omitempty"`
	VerificationTime  int64                  `json:"verificationTimeMs,omitempty"`
	EfficiencyScore   float64                `json:"efficiencyScore,omitempty"`
	AttackProbability float64                `json:"attackProbability,omitempty"`
	AttackAttempts    int                    `json:"attackAttempts,omitempty"`
	AttackSuccess     bool                   `json:"attackSuccess,omitempty"`
	AdditionalMetrics map[string]interface{} `json:"additionalMetrics,omitempty"`
}

func RunSecurityTests() []SecurityTestResult {
	var results []SecurityTestResult

	results = append(results, testBasicFunctionality())
	results = append(results, testBruteForceResistance())
	results = append(results, testTimingAttackResistance())
	results = append(results, testReplayAttackPrevention())
	results = append(results, testKeyExchangeSecurity())
	results = append(results, testLargeMessageHandling())
	results = append(results, testConcurrentAccess())
	results = append(results, testMessageIntegrity())
	results = append(results, testDifferentKeySizes())

	return results
}

func testBasicFunctionality() SecurityTestResult {
	stats := metrics.NewSecurityStats()
	stats.SetKeyLength(256)

	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()

	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	testMessage := []byte("This is a test message for security evaluation")
	startTime := time.Now()
	secureMsg := crypto.CreateSecureMessage(testMessage, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, stats)
	encryptionTime := time.Since(startTime)

	startTime = time.Now()
	decrypted, err := crypto.VerifyAndDecryptMessage(secureMsg, sharedSecret, rsaPub, stats)
	decryptionTime := time.Since(startTime)

	success := err == nil && bytes.Equal(decrypted, testMessage)
	return SecurityTestResult{
		TestName:        "Basic Functionality",
		Success:         success,
		Description:     "Tests encryption and decryption correctness",
		MessageSize:     len(testMessage),
		EncryptionTime:  encryptionTime.Milliseconds(),
		DecryptionTime:  decryptionTime.Milliseconds(),
		EfficiencyScore: stats.CalculateEfficiencyScore(),
	}
}

func testBruteForceResistance() SecurityTestResult {
	stats := metrics.NewSecurityStats()
	stats.SetKeyLength(256)

	attempts := 10000 
	successfulAttempts := 0

	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	testMessage := []byte("Secret message")
	secureMsg := crypto.CreateSecureMessage(testMessage, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, stats)

	startTime := time.Now()
	for i := 0; i < attempts; i++ {
		fakeSecret := make([]byte, 64)
		rand.Read(fakeSecret)

		_, err := crypto.VerifyAndDecryptMessage(secureMsg, fakeSecret, rsaPub, stats)
		if err == nil {
			successfulAttempts++
		}
	}
	duration := time.Since(startTime)

	attackProbability := float64(successfulAttempts) / float64(attempts)

	return SecurityTestResult{
		TestName:          "Brute Force Resistance",
		Success:           attackProbability < 0.001, 
		Description:       "Tests resistance to brute force attacks on encryption key",
		AttackAttempts:    attempts,
		AttackProbability: attackProbability,
		AttackSuccess:     successfulAttempts > 0,
		AdditionalMetrics: map[string]interface{}{
			"testDurationMs":     duration.Milliseconds(),
			"attemptsPerSecond":  float64(attempts) / duration.Seconds(),
			"successfulAttempts": successfulAttempts,
		},
	}
}

func testTimingAttackResistance() SecurityTestResult {
	key := make([]byte, 32)
	rand.Read(key)

	correctMAC := crypto.GenerateHMAC(key, []byte("test data"))

	var correctTimes []time.Duration
	for i := 0; i < 1000; i++ {
		start := time.Now()
		crypto.VerifyHMAC(key, []byte("test data"), correctMAC)
		correctTimes = append(correctTimes, time.Since(start))
	}

	wrongMAC := make([]byte, len(correctMAC))
	rand.Read(wrongMAC)

	var wrongTimes []time.Duration
	for i := 0; i < 1000; i++ {
		start := time.Now()
		crypto.VerifyHMAC(key, []byte("test data"), wrongMAC)
		wrongTimes = append(wrongTimes, time.Since(start))
	}

	// Вычисляем среднее время
	avgCorrect := averageDuration(correctTimes)
	avgWrong := averageDuration(wrongTimes)

	timeDifference := absDuration(avgCorrect - avgWrong)

	return SecurityTestResult{
		TestName:    "Timing Attack Resistance",
		Success:     timeDifference < time.Microsecond*100, // Разница менее 100 микросекунд
		Description: "Tests if HMAC verification is resistant to timing attacks",
		AdditionalMetrics: map[string]interface{}{
			"avgCorrectTimeNs": avgCorrect.Nanoseconds(),
			"avgWrongTimeNs":   avgWrong.Nanoseconds(),
			"timeDifferenceNs": timeDifference.Nanoseconds(),
		},
	}
}

func testReplayAttackPrevention() SecurityTestResult {
	stats := metrics.NewSecurityStats()
	stats.SetKeyLength(256)

	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	testMessage := []byte("Test message")

	// Создаем сообщение
	secureMsg := crypto.CreateSecureMessage(testMessage, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, stats)

	// Первая расшифровка должна пройти успешно
	_, err1 := crypto.VerifyAndDecryptMessage(secureMsg, sharedSecret, rsaPub, stats)

	// Ждем достаточно долго чтобы timestamp стал недействительным
	time.Sleep(time.Second * 2)

	// Создаем старое сообщение (с устаревшим timestamp)
	oldMsg := secureMsg
	oldMsg.Timestamp = time.Now().Unix() - 120 // 2 минуты назад

	_, err2 := crypto.VerifyAndDecryptMessage(oldMsg, sharedSecret, rsaPub, stats)

	return SecurityTestResult{
		TestName:    "Replay Attack Prevention",
		Success:     err1 == nil && err2 != nil,
		Description: "Tests prevention of replay attacks using timestamps",
		AdditionalMetrics: map[string]interface{}{
			"firstAttemptSuccess":  err1 == nil,
			"secondAttemptSuccess": err2 == nil,
			"errorMessage": func() string {
				if err2 != nil {
					return err2.Error()
				}
				return ""
			}(),
		},
	}
}

func testKeyExchangeSecurity() SecurityTestResult {
	// Тест безопасности обмена ключами

	// Генерируем ключи для двух сторон
	priv1, pub1 := crypto.GenerateECDHKeys()
	priv2, pub2 := crypto.GenerateECDHKeys()

	// Вычисляем общие секреты
	secret1 := crypto.ComputeSharedSecret(priv1, pub2)
	secret2 := crypto.ComputeSharedSecret(priv2, pub1)

	// Проверяем, что секреты одинаковые
	secretsMatch := bytes.Equal(secret1, secret2)

	// Проверяем, что секрет не пустой и достаточно длинный
	secretValid := len(secret1) >= 32 && !bytes.Equal(secret1, make([]byte, len(secret1)))

	return SecurityTestResult{
		TestName:    "Key Exchange Security",
		Success:     secretsMatch && secretValid,
		Description: "Tests ECDH key exchange security and correctness",
		AdditionalMetrics: map[string]interface{}{
			"secretsMatch": secretsMatch,
			"secretLength": len(secret1),
			"secretValid":  secretValid,
		},
	}
}

func testLargeMessageHandling() SecurityTestResult {
	stats := metrics.NewSecurityStats()
	stats.SetKeyLength(256)

	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	// Тест с большим сообщением (1MB)
	largeMessage := make([]byte, 1024*1024)
	rand.Read(largeMessage)

	startTime := time.Now()
	secureMsg := crypto.CreateSecureMessage(largeMessage, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, stats)
	encryptionTime := time.Since(startTime)

	startTime = time.Now()
	decrypted, err := crypto.VerifyAndDecryptMessage(secureMsg, sharedSecret, rsaPub, stats)
	decryptionTime := time.Since(startTime)

	success := err == nil && bytes.Equal(decrypted, largeMessage)

	return SecurityTestResult{
		TestName:        "Large Message Handling",
		Success:         success,
		Description:     "Tests handling of large messages (1MB)",
		MessageSize:     len(largeMessage),
		EncryptionTime:  encryptionTime.Milliseconds(),
		DecryptionTime:  decryptionTime.Milliseconds(),
		EfficiencyScore: stats.CalculateEfficiencyScore(),
	}
}

func testConcurrentAccess() SecurityTestResult {
	stats := metrics.NewSecurityStats()
	stats.SetKeyLength(256)

	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	const numGoroutines = 100
	const messagesPerGoroutine = 10

	var wg sync.WaitGroup
	results := make(chan bool, numGoroutines*messagesPerGoroutine)

	startTime := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			localStats := metrics.NewSecurityStats()
			localStats.SetKeyLength(256)

			for j := 0; j < messagesPerGoroutine; j++ {
				message := []byte("Concurrent test message")

				secureMsg := crypto.CreateSecureMessage(message, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, localStats)
				decrypted, err := crypto.VerifyAndDecryptMessage(secureMsg, sharedSecret, rsaPub, localStats)

				success := err == nil && bytes.Equal(decrypted, message)
				results <- success
			}
		}(i)
	}

	wg.Wait()
	close(results)

	totalDuration := time.Since(startTime)

	successCount := 0
	totalMessages := 0
	for result := range results {
		totalMessages++
		if result {
			successCount++
		}
	}

	successRate := float64(successCount) / float64(totalMessages)

	return SecurityTestResult{
		TestName:    "Concurrent Access",
		Success:     successRate > 0.99, // 99% успешных операций
		Description: "Tests concurrent encryption/decryption operations",
		AdditionalMetrics: map[string]interface{}{
			"totalMessages":      totalMessages,
			"successfulMessages": successCount,
			"successRate":        successRate,
			"totalDurationMs":    totalDuration.Milliseconds(),
			"messagesPerSecond":  float64(totalMessages) / totalDuration.Seconds(),
		},
	}
}

func testMessageIntegrity() SecurityTestResult {
	stats := metrics.NewSecurityStats()
	stats.SetKeyLength(256)

	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)

	testMessage := []byte("Integrity test message")
	secureMsg := crypto.CreateSecureMessage(testMessage, sharedSecret, ecdsaPriv, ecdsaPub, rsaPriv, stats)

	// Попытка изменить зашифрованные данные
	tamperedMsg := secureMsg
	if len(tamperedMsg.Cipher) > 0 {
		tamperedMsg.Cipher[0] ^= 1 // Изменяем один бит
	}

	_, err := crypto.VerifyAndDecryptMessage(tamperedMsg, sharedSecret, rsaPub, stats)

	// Тест должен обнаружить изменение и вернуть ошибку
	integrityProtected := err != nil

	return SecurityTestResult{
		TestName:    "Message Integrity",
		Success:     integrityProtected,
		Description: "Tests detection of message tampering",
		AdditionalMetrics: map[string]interface{}{
			"tamperingDetected": integrityProtected,
			"errorMessage": func() string {
				if err != nil {
					return err.Error()
				}
				return ""
			}(),
		},
	}
}

func testDifferentKeySizes() SecurityTestResult {
	// Тест с разными размерами ключей (в данном случае RSA)
	stats := metrics.NewSecurityStats()

	keySizes := []int{2048} // В текущей реализации только 2048
	results := make(map[int]bool)
	timings := make(map[int]time.Duration)

	testData := []byte("Key size test data")

	for _, keySize := range keySizes {
		stats.SetKeyLength(keySize)

		startTime := time.Now()
		rsaPriv, rsaPub := crypto.GenerateRSAKeys()

		signature := crypto.SignRSA(rsaPriv, testData, stats)
		verified := crypto.VerifyRSA(rsaPub, testData, signature, stats)

		duration := time.Since(startTime)

		results[keySize] = verified
		timings[keySize] = duration
	}

	allSuccessful := true
	for _, success := range results {
		if !success {
			allSuccessful = false
			break
		}
	}

	return SecurityTestResult{
		TestName:    "Different Key Sizes",
		Success:     allSuccessful,
		Description: "Tests RSA with different key sizes",
		AdditionalMetrics: map[string]interface{}{
			"keySizeResults": results,
			"keySizeTimings": func() map[string]int64 {
				timingResults := make(map[string]int64)
				for size, timing := range timings {
					timingResults[string(rune(size))] = timing.Milliseconds()
				}
				return timingResults
			}(),
		},
	}
}

func averageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
