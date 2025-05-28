package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"client-server/tests/metrics"
)

const (
	AESKeySize           = 32
	HMACKeySize          = 32
	NonceSize            = 16
	MaxTimeDifference    = 30              // Сокращенное окно timestamp для лучшей безопасности
	NonceCleanupInterval = 5 * time.Minute // Интервал очистки старых nonce
	MaxNonceStorage      = 10000           // Максимальное количество nonce в памяти
)

// Глобальное хранилище использованных nonce для защиты от replay атак
var (
	usedNonces = make(map[string]time.Time)
	nonceMutex sync.RWMutex
)

// NonceTracker для управления nonce с улучшенной защитой
type NonceTracker struct {
	nonces          map[string]time.Time
	mutex           sync.RWMutex
	maxSize         int
	cleanupInterval time.Duration
	stopChan        chan struct{}
}

// NewNonceTracker создает новый трекер nonce с автоматической очисткой
func NewNonceTracker(maxSize int, cleanupInterval time.Duration) *NonceTracker {
	tracker := &NonceTracker{
		nonces:          make(map[string]time.Time),
		maxSize:         maxSize,
		cleanupInterval: cleanupInterval,
		stopChan:        make(chan struct{}),
	}

	// Запускаем автоматическую очистку
	go tracker.startCleanup()

	return tracker
}

// AddNonce добавляет nonce и проверяет на дубликаты
func (nt *NonceTracker) AddNonce(nonce []byte) error {
	nonceStr := string(nonce)
	nt.mutex.Lock()
	defer nt.mutex.Unlock()

	// Проверяем на дубликат
	if _, exists := nt.nonces[nonceStr]; exists {
		return errors.New("nonce уже использован (replay attack обнаружен)")
	}

	// Проверяем размер и очищаем при необходимости
	if len(nt.nonces) >= nt.maxSize {
		nt.cleanupOldNonces()
	}

	nt.nonces[nonceStr] = time.Now()
	return nil
}

// cleanupOldNonces удаляет старые nonce
func (nt *NonceTracker) cleanupOldNonces() {
	cutoff := time.Now().Add(-nt.cleanupInterval)
	for nonce, timestamp := range nt.nonces {
		if timestamp.Before(cutoff) {
			delete(nt.nonces, nonce)
		}
	}
}

// startCleanup запускает периодическую очистку
func (nt *NonceTracker) startCleanup() {
	ticker := time.NewTicker(nt.cleanupInterval / 2) // Очистка в 2 раза чаще
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nt.mutex.Lock()
			nt.cleanupOldNonces()
			nt.mutex.Unlock()
		case <-nt.stopChan:
			return
		}
	}
}

// Stop останавливает автоматическую очистку
func (nt *NonceTracker) Stop() {
	close(nt.stopChan)
}

// GetCount возвращает количество сохраненных nonce
func (nt *NonceTracker) GetCount() int {
	nt.mutex.RLock()
	defer nt.mutex.RUnlock()
	return len(nt.nonces)
}

// Reset очищает все nonce
func (nt *NonceTracker) Reset() {
	nt.mutex.Lock()
	defer nt.mutex.Unlock()
	nt.nonces = make(map[string]time.Time)
}

// Глобальный трекер nonce с улучшенной защитой
var globalNonceTracker = NewNonceTracker(MaxNonceStorage, NonceCleanupInterval)

type Message struct {
	Timestamp int64  // Временная метка
	Nonce     []byte // Одноразовое число
	IV        []byte // Вектор инициализации AES
	Cipher    []byte // Шифротекст
	HMAC      []byte // HMAC для проверки целостности
	Signature []byte // Подпись ECDSA
	PubKey    []byte // Публичный ключ ECDH
	RSASig    []byte // Подпись RSA
}

func CreateSecureMessage(plaintext []byte, sharedSecret []byte, ecdsaPriv *ecdsa.PrivateKey, ecdhPub []byte, rsaPriv *rsa.PrivateKey, stats *metrics.SecurityStats) Message {
	iv := make([]byte, 16)
	rand.Read(iv)
	ciphertext := AESEncrypt(sharedSecret[:AESKeySize], iv, plaintext, stats)
	hmacValue := GenerateHMAC(sharedSecret[AESKeySize:], ciphertext)
	ecdsaSig := SignECDSA(ecdsaPriv, ciphertext, stats)
	rsaSig := SignRSA(rsaPriv, ciphertext, stats)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	timestamp := time.Now().Unix()
	return Message{
		Timestamp: timestamp,
		Nonce:     nonce,
		IV:        iv,
		Cipher:    ciphertext,
		HMAC:      hmacValue,
		Signature: ecdsaSig,
		PubKey:    ecdhPub,
		RSASig:    rsaSig,
	}
}

func VerifyAndDecryptMessage(msg Message, sharedSecret []byte, rsaPubKey []byte, stats *metrics.SecurityStats) ([]byte, error) {
	// 1. Проверка timestamp (сокращенное окно для лучшей безопасности)
	now := time.Now().Unix()
	if now-msg.Timestamp > MaxTimeDifference || now < msg.Timestamp-MaxTimeDifference {
		return nil, errors.New("временная метка вне допустимого диапазона")
	}

	// 2. Улучшенная проверка nonce с использованием глобального трекера
	if err := globalNonceTracker.AddNonce(msg.Nonce); err != nil {
		return nil, err
	}

	// 3. Проверка HMAC (с constant-time сравнением)
	if !VerifyHMAC(sharedSecret[AESKeySize:], msg.Cipher, msg.HMAC) {
		return nil, errors.New("проверка HMAC не удалась")
	}

	// 4. Проверка ECDSA подписи
	if !VerifyECDSA(msg.PubKey, msg.Cipher, msg.Signature, stats) {
		return nil, errors.New("ECDSA-подпись недействительна")
	}

	// 5. Проверка RSA подписи
	if !VerifyRSA(rsaPubKey, msg.Cipher, msg.RSASig, stats) {
		return nil, errors.New("RSA-подпись недействительна")
	}

	// 6. Расшифровка данных
	plaintext, err := AESDecrypt(sharedSecret[:AESKeySize], msg.IV, msg.Cipher, stats)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %v", err)
	}
	return plaintext, nil
}

func ComputeSharedSecret(priv *ecdsa.PrivateKey, peerPubBytes []byte) []byte {
	pubIface, err := x509.ParsePKIXPublicKey(peerPubBytes)
	if err != nil {
		panic(err)
	}
	pub := pubIface.(*ecdsa.PublicKey)
	x, _ := priv.PublicKey.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	hash := sha256.Sum256(x.Bytes())
	return hash[:]
}

// ClearOldNonces очищает устаревшие nonce из памяти
func ClearOldNonces() {
	globalNonceTracker.mutex.Lock()
	defer globalNonceTracker.mutex.Unlock()
	globalNonceTracker.cleanupOldNonces()
}

// GetNonceCount возвращает количество сохраненных nonce (для тестирования)
func GetNonceCount() int {
	return globalNonceTracker.GetCount()
}

// ResetNonceStorage очищает все nonce (для тестирования)
func ResetNonceStorage() {
	globalNonceTracker.Reset()
}
