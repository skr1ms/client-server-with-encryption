package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// GenerateHMAC вычисляет HMAC-SHA256 данных
func GenerateHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC проверяет HMAC данных с использованием сравнения с постоянным временем
func VerifyHMAC(key, data, mac []byte) bool {
	expected := GenerateHMAC(key, data)
	return subtle.ConstantTimeCompare(mac, expected) == 1
}
