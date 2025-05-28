package benchmark

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"client-server/internal/crypto"
	"client-server/tests/metrics"
)

func BenchmarkAESEncrypt(b *testing.B) {
	stats := metrics.NewSecurityStats()
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.AESEncrypt(key, iv, plaintext, stats)
	}
}

func BenchmarkAESDecrypt(b *testing.B) {
	stats := metrics.NewSecurityStats()
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	ciphertext := crypto.AESEncrypt(key, iv, plaintext, stats)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = crypto.AESDecrypt(key, iv, ciphertext, stats)
	}
}

func BenchmarkHMAC(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.GenerateHMAC(key, data)
	}
}

func BenchmarkECDSASign(b *testing.B) {
	stats := metrics.NewSecurityStats()
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.SignECDSA(privKey, data, stats)
	}
}

func BenchmarkECDSAVerify(b *testing.B) {
	stats := metrics.NewSecurityStats()
	privKey, pubKey := crypto.GenerateECDHKeys()
	data := make([]byte, 1024)
	rand.Read(data)
	sig := crypto.SignECDSA(privKey, data, stats)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifyECDSA(pubKey, data, sig, stats)
	}
}

func BenchmarkRSASign(b *testing.B) {
	stats := metrics.NewSecurityStats()
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.SignRSA(privKey, data, stats)
	}
}

func BenchmarkRSAVerify(b *testing.B) {
	stats := metrics.NewSecurityStats()
	privKey, pubKey := crypto.GenerateRSAKeys()
	data := make([]byte, 1024)
	rand.Read(data)
	sig := crypto.SignRSA(privKey, data, stats)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifyRSA(pubKey, data, sig, stats)
	}
}

func BenchmarkCreateSecureMessage(b *testing.B) {
	stats := metrics.NewSecurityStats()
	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, _ := crypto.GenerateRSAKeys()
	secret := make([]byte, 64)
	rand.Read(secret)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.CreateSecureMessage(plaintext, secret, ecdsaPriv, ecdsaPub, rsaPriv, stats)
	}
}

func BenchmarkVerifyAndDecryptMessage(b *testing.B) {
	stats := metrics.NewSecurityStats()
	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	secret := make([]byte, 64)
	rand.Read(secret)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	msg := crypto.CreateSecureMessage(plaintext, secret, ecdsaPriv, ecdsaPub, rsaPriv, stats)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = crypto.VerifyAndDecryptMessage(msg, secret, rsaPub, stats)
	}
}

func BenchmarkDifferentMessageSizes(b *testing.B) {
	stats := metrics.NewSecurityStats()
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	sizes := []int{64, 256, 1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Encrypt-%dB", size), func(b *testing.B) {
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				crypto.AESEncrypt(key, iv, plaintext, stats)
			}
		})

		b.Run(fmt.Sprintf("Decrypt-%dB", size), func(b *testing.B) {
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			ciphertext := crypto.AESEncrypt(key, iv, plaintext, stats)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = crypto.AESDecrypt(key, iv, ciphertext, stats)
			}
		})
	}
}
