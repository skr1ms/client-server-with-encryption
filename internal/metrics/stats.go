package metrics

import (
	"fmt"
	"time"
)

type SecurityStats struct {
	EncryptionTime   time.Duration
	DecryptionTime   time.Duration
	SigningTime      time.Duration
	VerificationTime time.Duration
	KeyLength        int
	LastCheckTime    time.Time
}

func NewSecurityStats() *SecurityStats {
	return &SecurityStats{
		LastCheckTime: time.Now(),
	}
}

func (stats *SecurityStats) RecordEncryptionTime(duration time.Duration) {
	stats.EncryptionTime = duration
}

func (stats *SecurityStats) RecordDecryptionTime(duration time.Duration) {
	stats.DecryptionTime = duration
}

func (stats *SecurityStats) RecordSigningTime(duration time.Duration) {
	stats.SigningTime = duration
}

func (stats *SecurityStats) RecordVerificationTime(duration time.Duration) {
	stats.VerificationTime = duration
}

func (stats *SecurityStats) SetKeyLength(length int) {
	stats.KeyLength = length
}

func (stats *SecurityStats) PrintStats() {
	fmt.Printf("Статистика безопасности (с момента последней проверки %v):\n", time.Since(stats.LastCheckTime))
	fmt.Printf("  Время шифрования: %d мс\n", stats.EncryptionTime.Milliseconds())
	fmt.Printf("  Время расшифровки: %d мс\n", stats.DecryptionTime.Milliseconds())
	fmt.Printf("  Время подписания: %d мс\n", stats.SigningTime.Milliseconds())
	fmt.Printf("  Время проверки: %d мс\n", stats.VerificationTime.Milliseconds())
	fmt.Printf("  Длина ключа: %d бит\n", stats.KeyLength)
	stats.LastCheckTime = time.Now()
}

func (stats *SecurityStats) CalculateEfficiencyScore() float64 {
	normalizedEncTime := 1.0 - float64(stats.EncryptionTime.Milliseconds())/1000.0
	if normalizedEncTime < 0 {
		normalizedEncTime = 0
	}
	normalizedDecTime := 1.0 - float64(stats.DecryptionTime.Milliseconds())/1000.0
	if normalizedDecTime < 0 {
		normalizedDecTime = 0
	}
	normalizedKeyLength := float64(stats.KeyLength) / 4096.0
	attackProbability := 1.0 / float64(stats.KeyLength)
	normalizedAttackProb := 1.0 - attackProbability

	w1, w2, w3, w4 := 0.25, 0.25, 0.25, 0.25
	return w1*normalizedEncTime + w2*normalizedDecTime + w3*normalizedKeyLength + w4*normalizedAttackProb
}
