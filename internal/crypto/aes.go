package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"client-server/tests/metrics"
)

// Защита от параллельных атак
var (
	// Счетчик параллельных операций шифрования
	concurrentOps    int64
	maxConcurrentOps int64 = 100 // Максимальное количество параллельных операций
	rateLimitMutex   sync.RWMutex
	rateLimitMap     = make(map[string]time.Time) // IP -> last operation time
	minOpInterval    = 10 * time.Millisecond      // Минимальный интервал между операциями
)

// RateLimitCheck проверяет ограничения скорости для защиты от DoS атак
func RateLimitCheck(clientID string) error {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	if lastOp, exists := rateLimitMap[clientID]; exists {
		if now.Sub(lastOp) < minOpInterval {
			return errors.New("слишком частые операции - возможная DoS атака")
		}
	}

	rateLimitMap[clientID] = now

	// Очистка старых записей (старше 1 минуты)
	cutoff := now.Add(-time.Minute)
	for id, timestamp := range rateLimitMap {
		if timestamp.Before(cutoff) {
			delete(rateLimitMap, id)
		}
	}

	return nil
}

// ConcurrencyCheck проверяет ограничения параллельности
func ConcurrencyCheck() error {
	current := atomic.LoadInt64(&concurrentOps)
	if current >= maxConcurrentOps {
		return errors.New("превышен лимит параллельных операций - возможная параллельная атака")
	}
	atomic.AddInt64(&concurrentOps, 1)
	return nil
}

// ConcurrencyRelease освобождает слот параллельности
func ConcurrencyRelease() {
	atomic.AddInt64(&concurrentOps, -1)
}

// GetConcurrentOpsCount возвращает текущее количество параллельных операций
func GetConcurrentOpsCount() int64 {
	return atomic.LoadInt64(&concurrentOps)
}

// PKCS7Pad добавляет дополнение PKCS#7 к данным
func PKCS7Pad(data []byte) []byte {
	pad := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(data, padtext...)
}

// PKCS7Unpad удаляет дополнение PKCS#7 из данных
func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("пустые данные")
	}
	pad := int(data[len(data)-1])
	if pad > aes.BlockSize || pad == 0 {
		return nil, errors.New("недопустимое дополнение")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if data[i] != byte(pad) {
			return nil, errors.New("недопустимое дополнение")
		}
	}
	return data[:len(data)-pad], nil
}

// AESEncrypt шифрует данные с использованием AES-256-CBC с защитой от параллельных атак
func AESEncrypt(key, iv, plaintext []byte, stats *metrics.SecurityStats) []byte {
	// Проверка ограничений параллельности
	if err := ConcurrencyCheck(); err != nil {
		// В случае превышения лимита, делаем небольшую задержку
		time.Sleep(time.Millisecond * 50)
		return nil
	}
	defer ConcurrencyRelease()

	startTime := time.Now()
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext = PKCS7Pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	stats.RecordEncryptionTime(time.Since(startTime))
	return ciphertext
}

// AESDecrypt расшифровывает данные, зашифрованные с помощью AES-256-CBC с защитой от параллельных атак
func AESDecrypt(key, iv, ciphertext []byte, stats *metrics.SecurityStats) ([]byte, error) {
	// Проверка ограничений параллельности
	if err := ConcurrencyCheck(); err != nil {
		return nil, err
	}
	defer ConcurrencyRelease()

	startTime := time.Now()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	plaintext, err = PKCS7Unpad(plaintext)
	if err != nil {
		return nil, err
	}
	stats.RecordDecryptionTime(time.Since(startTime))
	return plaintext, nil
}
