package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

// Глобальная статистика времени для анализа timing атак
var hmacTimingStats = NewTimingStats(1000)

// TimingStats для статистического анализа времени HMAC операций
type TimingStats struct {
	measurements []time.Duration
	mutex        sync.RWMutex
	maxSize      int
}

// NewTimingStats создает новый анализатор времени
func NewTimingStats(maxSize int) *TimingStats {
	return &TimingStats{
		measurements: make([]time.Duration, 0, maxSize),
		maxSize:      maxSize,
	}
}

// AddMeasurement добавляет новое измерение времени
func (ts *TimingStats) AddMeasurement(duration time.Duration) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if len(ts.measurements) >= ts.maxSize {
		ts.measurements = ts.measurements[1:]
	}
	ts.measurements = append(ts.measurements, duration)
}

// GetStats возвращает статистику времени
func (ts *TimingStats) GetStats() (avg, stddev time.Duration, count int) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	count = len(ts.measurements)
	if count == 0 {
		return 0, 0, 0
	}

	var sum time.Duration
	for _, d := range ts.measurements {
		sum += d
	}
	avg = sum / time.Duration(count)

	var variance float64
	for _, d := range ts.measurements {
		diff := float64(d - avg)
		variance += diff * diff
	}
	variance /= float64(count)
	stddev = time.Duration(variance)

	return avg, stddev, count
}

// Reset очищает статистику
func (ts *TimingStats) Reset() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.measurements = ts.measurements[:0]
}

// GenerateHMAC вычисляет HMAC-SHA256 данных
func GenerateHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC проверяет HMAC данных с использованием сравнения с постоянным временем
// и статистическим анализом для защиты от timing атак
func VerifyHMAC(key, data, mac []byte) bool {
	start := time.Now()

	expected := GenerateHMAC(key, data)
	result := subtle.ConstantTimeCompare(mac, expected) == 1

	elapsed := time.Since(start)
	hmacTimingStats.AddMeasurement(elapsed)

	return result
}

// VerifyHMACWithTimingAnalysis проверяет HMAC с дополнительным анализом времени
func VerifyHMACWithTimingAnalysis(key, data, mac []byte) (bool, time.Duration, time.Duration) {
	start := time.Now()

	expected := GenerateHMAC(key, data)
	result := subtle.ConstantTimeCompare(mac, expected) == 1

	elapsed := time.Since(start)
	hmacTimingStats.AddMeasurement(elapsed)

	_, stddev, _ := hmacTimingStats.GetStats()

	return result, elapsed, stddev
}

// GetHMACTimingStats возвращает статистику времени HMAC операций
func GetHMACTimingStats() (avg, stddev time.Duration, count int) {
	return hmacTimingStats.GetStats()
}

// ResetHMACTimingStats сбрасывает статистику времени
func ResetHMACTimingStats() {
	hmacTimingStats.Reset()
}
