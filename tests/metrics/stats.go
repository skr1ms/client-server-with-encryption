package metrics

import (
	"fmt"
	"time"
)

type SecurityStats struct {
	EncryptionTime    time.Duration
	DecryptionTime    time.Duration
	SigningTime       time.Duration
	VerificationTime  time.Duration
	KeyLength         int
	AttackProbability float64
	LastCheckTime     time.Time
}

// Максимальные значения для нормализации согласно заданию
const (
	MaxEncryptionTimeMs  = 10.0   // 10 мс максимум для более чувствительной нормализации
	MaxDecryptionTimeMs  = 10.0   // 10 мс максимум для более чувствительной нормализации
	MaxKeyLength         = 4096.0 // 4096 бит максимум
	MaxAttackProbability = 1.0    // 100% максимальная вероятность атаки
)

func NewSecurityStats() *SecurityStats {
	return &SecurityStats{
		LastCheckTime:     time.Now(),
		KeyLength:         256,    // По умолчанию AES-256
		AttackProbability: 0.0001, // Очень низкая вероятность для AES-256
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

func (stats *SecurityStats) SetAttackProbability(probability float64) {
	stats.AttackProbability = probability
}

func (stats *SecurityStats) PrintStats() {
	fmt.Printf("Статистика безопасности (с момента последней проверки %v):\n", time.Since(stats.LastCheckTime))
	fmt.Printf("  Время шифрования: %d мс\n", stats.EncryptionTime.Milliseconds())
	fmt.Printf("  Время расшифровки: %d мс\n", stats.DecryptionTime.Milliseconds())
	fmt.Printf("  Время подписания: %d мс\n", stats.SigningTime.Milliseconds())
	fmt.Printf("  Время проверки: %d мс\n", stats.VerificationTime.Milliseconds())
	fmt.Printf("  Длина ключа: %d бит\n", stats.KeyLength)
	fmt.Printf("  Вероятность атаки: %.6f\n", stats.AttackProbability)
	fmt.Printf("  Показатель эффективности: %.4f\n", stats.CalculateEfficiencyScore())
	stats.LastCheckTime = time.Now()
}

// CalculateEfficiencyScore рассчитывает интегральный показатель эффективности
// согласно формуле из задания: E = w1⋅T'enc + w2⋅T'dec + w3⋅K' + w4⋅P'attack
func (stats *SecurityStats) CalculateEfficiencyScore() float64 {
	// 1. Нормализованное время шифрования: T'enc = Tenc/max(Tenc)
	normalizedEncTime := float64(stats.EncryptionTime.Milliseconds()) / MaxEncryptionTimeMs
	if normalizedEncTime > 1.0 {
		normalizedEncTime = 1.0
	}

	// 2. Нормализованное время расшифровки: T'dec = Tdec/max(Tdec)
	normalizedDecTime := float64(stats.DecryptionTime.Milliseconds()) / MaxDecryptionTimeMs
	if normalizedDecTime > 1.0 {
		normalizedDecTime = 1.0
	}

	// 3. Нормализованная длина ключа: K' = K/max(K)
	normalizedKeyLength := float64(stats.KeyLength) / MaxKeyLength
	if normalizedKeyLength > 1.0 {
		normalizedKeyLength = 1.0
	}

	// 4. Нормализованная вероятность атаки (обратная): P'attack = 1 − (Pattack/max(Pattack))
	normalizedAttackProb := 1.0 - (stats.AttackProbability / MaxAttackProbability)
	if normalizedAttackProb < 0 {
		normalizedAttackProb = 0
	}

	// Весовые коэффициенты из задания (равные веса)
	w1, w2, w3, w4 := 0.25, 0.25, 0.25, 0.25

	// Интегральная формула эффективности
	// Для времени используем обратные значения (чем меньше время, тем лучше)
	efficiency := w1*(1.0-normalizedEncTime) + w2*(1.0-normalizedDecTime) + w3*normalizedKeyLength + w4*normalizedAttackProb
	return efficiency
}

// PrintDetailedReport выводит детальный отчет по всем компонентам эффективности
func (stats *SecurityStats) PrintDetailedReport() {
	fmt.Println("\n=== ДЕТАЛЬНЫЙ ОТЧЕТ ПО ЭФФЕКТИВНОСТИ ===")

	// Исходные значения
	fmt.Printf("Исходные значения:\n")
	fmt.Printf("  Время шифрования (Tenc): %d мс\n", stats.EncryptionTime.Milliseconds())
	fmt.Printf("  Время расшифровки (Tdec): %d мс\n", stats.DecryptionTime.Milliseconds())
	fmt.Printf("  Длина ключа (K): %d бит\n", stats.KeyLength)
	fmt.Printf("  Вероятность атаки (Pattack): %.6f\n", stats.AttackProbability)

	// Нормализованные значения
	normalizedEncTime := float64(stats.EncryptionTime.Milliseconds()) / MaxEncryptionTimeMs
	if normalizedEncTime > 1.0 {
		normalizedEncTime = 1.0
	}

	normalizedDecTime := float64(stats.DecryptionTime.Milliseconds()) / MaxDecryptionTimeMs
	if normalizedDecTime > 1.0 {
		normalizedDecTime = 1.0
	}

	normalizedKeyLength := float64(stats.KeyLength) / MaxKeyLength
	if normalizedKeyLength > 1.0 {
		normalizedKeyLength = 1.0
	}

	normalizedAttackProb := 1.0 - (stats.AttackProbability / MaxAttackProbability)
	if normalizedAttackProb < 0 {
		normalizedAttackProb = 0
	}

	fmt.Printf("\nНормализованные значения:\n")
	fmt.Printf("  T'enc = %.4f (нормализованное время шифрования)\n", normalizedEncTime)
	fmt.Printf("  T'dec = %.4f (нормализованное время расшифровки)\n", normalizedDecTime)
	fmt.Printf("  K' = %.4f (нормализованная длина ключа)\n", normalizedKeyLength)
	fmt.Printf("  P'attack = %.4f (обратная нормализованная вероятность атаки)\n", normalizedAttackProb)

	// Компоненты эффективности
	w1, w2, w3, w4 := 0.25, 0.25, 0.25, 0.25
	comp1 := w1 * (1.0 - normalizedEncTime)
	comp2 := w2 * (1.0 - normalizedDecTime)
	comp3 := w3 * normalizedKeyLength
	comp4 := w4 * normalizedAttackProb

	fmt.Printf("\nКомпоненты формулы эффективности:\n")
	fmt.Printf("  w1⋅(1-T'enc) = %.2f⋅%.4f = %.4f\n", w1, 1.0-normalizedEncTime, comp1)
	fmt.Printf("  w2⋅(1-T'dec) = %.2f⋅%.4f = %.4f\n", w2, 1.0-normalizedDecTime, comp2)
	fmt.Printf("  w3⋅K' = %.2f⋅%.4f = %.4f\n", w3, normalizedKeyLength, comp3)
	fmt.Printf("  w4⋅P'attack = %.2f⋅%.4f = %.4f\n", w4, normalizedAttackProb, comp4)

	efficiency := comp1 + comp2 + comp3 + comp4
	fmt.Printf("\nИНТЕГРАЛЬНЫЙ ПОКАЗАТЕЛЬ ЭФФЕКТИВНОСТИ: %.4f\n", efficiency)
	fmt.Printf("Диапазон: [0, 1], где 1 - максимальная эффективность\n")
	fmt.Println("==========================================")
}
