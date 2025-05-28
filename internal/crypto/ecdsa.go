package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"log"
	"math/big"
	"time"

	"client-server/tests/metrics"
)

// SignECDSA создает подпись ECDSA для данных
func SignECDSA(priv *ecdsa.PrivateKey, data []byte, stats *metrics.SecurityStats) []byte {
	startTime := time.Now()
	h := sha512.Sum512(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		log.Fatal(err)
	}
	signature := struct{ R, S *big.Int }{r, s}
	signatureBytes, err := json.Marshal(signature)
	if err != nil {
		log.Fatal(err)
	}
	stats.RecordSigningTime(time.Since(startTime))
	return signatureBytes
}

// VerifyECDSA проверяет подпись ECDSA
func VerifyECDSA(pubBytes, data, sig []byte, stats *metrics.SecurityStats) bool {
	startTime := time.Now()
	pubIface, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		log.Println("Ошибка при разборе открытого ключа:", err)
		return false
	}
	pub, ok := pubIface.(*ecdsa.PublicKey)
	if !ok {
		log.Println("Не является открытым ключом ECDSA")
		return false
	}
	var signature struct{ R, S *big.Int }
	if err := json.Unmarshal(sig, &signature); err != nil {
		log.Println("Ошибка при десериализации подписи:", err)
		return false
	}
	h := sha512.Sum512(data)
	valid := ecdsa.Verify(pub, h[:], signature.R, signature.S)
	stats.RecordVerificationTime(time.Since(startTime))
	return valid
}

// GenerateECDHKeys генерирует пару ключей ECDSA для обмена ключами ECDH
func GenerateECDHKeys() (*ecdsa.PrivateKey, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return priv, pubBytes
}
