package test

import (
	"bytes"
	"client-server/internal/crypto"
	"client-server/internal/metrics"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
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

	exportTestResults(results)
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

func exportTestResults(results []SecurityTestResult) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Printf("Ошибка при маршалинге результатов тестов: %v", err)
		return
	}
	os.WriteFile("results/security_test_results.json", data, 0644)
}
