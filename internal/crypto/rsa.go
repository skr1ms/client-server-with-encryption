package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"log"
	"time"

	"client-server/tests/metrics"
)

const RSAKeySize = 2048

// SignRSA создает подпись RSA для данных
func SignRSA(priv *rsa.PrivateKey, data []byte, stats *metrics.SecurityStats) []byte {
	startTime := time.Now()
	h := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		log.Fatal(err)
	}
	stats.RecordSigningTime(time.Since(startTime))
	return signature
}

// VerifyRSA проверяет подпись RSA
func VerifyRSA(pubBytes, data, sig []byte, stats *metrics.SecurityStats) bool {
	startTime := time.Now()
	pubIface, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		log.Println("Ошибка при разборе открытого ключа RSA:", err)
		return false
	}
	pub, ok := pubIface.(*rsa.PublicKey)
	if !ok {
		log.Println("Не является открытым ключом RSA")
		return false
	}
	h := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	stats.RecordVerificationTime(time.Since(startTime))
	return err == nil
}

// GenerateRSAKeys генерирует пару ключей RSA
func GenerateRSAKeys() (*rsa.PrivateKey, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		log.Fatal(err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return priv, pubBytes
}
