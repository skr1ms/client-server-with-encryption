package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"client-server/internal/metrics"
)

const (
	AESKeySize        = 32
	HMACKeySize       = 32
	NonceSize         = 16
	MaxTimeDifference = 60
)

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
	now := time.Now().Unix()
	if now-msg.Timestamp > MaxTimeDifference || now < msg.Timestamp {
		return nil, errors.New("временная метка вне допустимого диапазона")
	}
	if !VerifyHMAC(sharedSecret[AESKeySize:], msg.Cipher, msg.HMAC) {
		return nil, errors.New("проверка HMAC не удалась")
	}
	if !VerifyECDSA(msg.PubKey, msg.Cipher, msg.Signature, stats) {
		return nil, errors.New("ECDSA-подпись недействительна")
	}
	if !VerifyRSA(rsaPubKey, msg.Cipher, msg.RSASig, stats) {
		return nil, errors.New("RSA-подпись недействительна")
	}
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
