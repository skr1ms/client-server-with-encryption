package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa"
	"crypto/sha256"
	"crypto"
	"math/big"
	"errors"
	"fmt"
)

// DHParams представляет параметры Диффи-Хеллмана
type DHParams struct {
	P *big.Int // Простое число
	G *big.Int // Генератор
}

// DHKeyPair представляет пару ключей DH
type DHKeyPair struct {
	Private *big.Int
	Public  *big.Int
	Params  *DHParams
}

// GenerateStandardDHParams генерирует стандартные параметры DH (RFC 3526, группа 14)
func GenerateStandardDHParams() *DHParams {
	pHex := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	
	p, _ := new(big.Int).SetString(pHex, 16)
	g := big.NewInt(2)
	
	return &DHParams{P: p, G: g}
}

// GenerateDHKeyPair генерирует пару ключей DH
func GenerateDHKeyPair(params *DHParams) (*DHKeyPair, error) {
	// Генерируем приватный ключ (случайное число от 1 до p-1)
	private, err := rand.Int(rand.Reader, new(big.Int).Sub(params.P, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	private.Add(private, big.NewInt(1)) // Убеждаемся что >= 1
	
	// Вычисляем публичный ключ: g^private mod p
	public := new(big.Int).Exp(params.G, private, params.P)
	
	return &DHKeyPair{
		Private: private,
		Public:  public,
		Params:  params,
	}, nil
}

// ComputeDHSharedSecret вычисляет общий секрет DH
func ComputeDHSharedSecret(privateKey *big.Int, peerPublicKey *big.Int, params *DHParams) []byte {
	// Вычисляем общий секрет: peerPublic^private mod p
	sharedSecret := new(big.Int).Exp(peerPublicKey, privateKey, params.P)
	
	// Хешируем результат для получения ключа фиксированной длины
	hash := sha256.Sum256(sharedSecret.Bytes())
	return hash[:]
}

// RSASignDHPublicKey подписывает публичный ключ DH с помощью RSA
func RSASignDHPublicKey(rsaPrivate *rsa.PrivateKey, dhPublic *big.Int) ([]byte, error) {
	// Хешируем публичный ключ DH
	hash := sha256.Sum256(dhPublic.Bytes())
	
	// Подписываем хеш
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivate, crypto.SHA256, hash[:])
	return signature, err
}

// RSAVerifyDHPublicKey проверяет подпись публичного ключа DH
func RSAVerifyDHPublicKey(rsaPublic *rsa.PublicKey, dhPublic *big.Int, signature []byte) error {
	// Хешируем публичный ключ DH
	hash := sha256.Sum256(dhPublic.Bytes())
	
	// Проверяем подпись
	return rsa.VerifyPKCS1v15(rsaPublic, crypto.SHA256, hash[:], signature)
}

// DHKeyExchange представляет полный обмен ключами DH с RSA аутентификацией
type DHKeyExchange struct {
	DHKeyPair     *DHKeyPair
	DHSignature   []byte
	RSAPublicKey  []byte
}

// PerformDHKeyExchange выполняет полный обмен ключами DH с RSA аутентификацией
func PerformDHKeyExchange(rsaPrivate *rsa.PrivateKey) (*DHKeyExchange, error) {
	// Генерируем параметры и ключевую пару DH
	params := GenerateStandardDHParams()
	dhKeyPair, err := GenerateDHKeyPair(params)
	if err != nil {
		return nil, err
	}
	
	// Подписываем наш публичный ключ DH с помощью RSA
	signature, err := RSASignDHPublicKey(rsaPrivate, dhKeyPair.Public)
	if err != nil {
		return nil, err
	}
	
	// Получаем наш RSA публичный ключ в формате DER
	rsaPubBytes, err := x509.MarshalPKIXPublicKey(&rsaPrivate.PublicKey)
	if err != nil {
		return nil, err
	}
	
	return &DHKeyExchange{
		DHKeyPair:    dhKeyPair,
		DHSignature:  signature,
		RSAPublicKey: rsaPubBytes,
	}, nil
}

// VerifyAndComputeSharedSecret проверяет подпись пира и вычисляет общий секрет
func VerifyAndComputeSharedSecret(
	ourDHPrivate *big.Int,
	ourDHParams *DHParams,
	peerExchange *DHKeyExchange,
) ([]byte, error) {
	// Парсим RSA публичный ключ пира
	rsaPubInterface, err := x509.ParsePKIXPublicKey(peerExchange.RSAPublicKey)
	if err != nil {
		return nil, err
	}
	
	rsaPub, ok := rsaPubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("не является RSA публичным ключом")
	}
	
	// Проверяем подпись пира
	err = RSAVerifyDHPublicKey(rsaPub, peerExchange.DHKeyPair.Public, peerExchange.DHSignature)
	if err != nil {
		return nil, fmt.Errorf("проверка RSA подписи не удалась: %v", err)
	}
	
	// Вычисляем общий секрет
	sharedSecret := ComputeDHSharedSecret(ourDHPrivate, peerExchange.DHKeyPair.Public, ourDHParams)
	
	return sharedSecret, nil
}