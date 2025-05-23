package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"time"

	"client-server/internal/metrics"
)

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

// AESEncrypt шифрует данные с использованием AES-256-CBC
func AESEncrypt(key, iv, plaintext []byte, stats *metrics.SecurityStats) []byte {
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

// AESDecrypt расшифровывает данные, зашифрованные с помощью AES-256-CBC
func AESDecrypt(key, iv, ciphertext []byte, stats *metrics.SecurityStats) ([]byte, error) {
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
