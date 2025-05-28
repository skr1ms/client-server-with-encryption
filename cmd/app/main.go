package main

import (
	"bufio"
	"client-server/internal/crypto"
	"client-server/tests/metrics"
	test "client-server/tests/utils"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

var (
	globalStats = metrics.NewSecurityStats()
	statsMutex  sync.Mutex
)

type ConnectionInfo struct {
	ECDSAPrivate *ecdsa.PrivateKey
	ECDSAPublic  []byte
	RSAPrivate   *rsa.PrivateKey
	RSAPublic    []byte
	PeerECDSA    []byte
	PeerRSA      []byte
	SharedSecret []byte
	Stats        *metrics.SecurityStats
	NonceTracker map[string]bool
	StatsTimer   *time.Timer
}

func NewConnectionInfo() *ConnectionInfo {
	ecdsaPriv, ecdsaPub := crypto.GenerateECDHKeys()
	rsaPriv, rsaPub := crypto.GenerateRSAKeys()
	globalStats.SetKeyLength(256)

	return &ConnectionInfo{
		ECDSAPrivate: ecdsaPriv,
		ECDSAPublic:  ecdsaPub,
		RSAPrivate:   rsaPriv,
		RSAPublic:    rsaPub,
		Stats:        globalStats,
		NonceTracker: make(map[string]bool),
	}
}

func printStats() {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	fmt.Println("=== Метрики производительности безопасности ===")
	globalStats.PrintStats()
	efficiencyScore := globalStats.CalculateEfficiencyScore()
	fmt.Printf("Итоговый показатель эффективности: %.4f\n", efficiencyScore)
	fmt.Println("===============================================")
}

func exchangeKeys(conn net.Conn, info *ConnectionInfo) error {
	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)
	keyData := struct {
		ECDSA []byte
		RSA   []byte
	}{info.ECDSAPublic, info.RSAPublic}
	if err := encoder.Encode(keyData); err != nil {
		return err
	}
	var peerKeyData struct {
		ECDSA []byte
		RSA   []byte
	}
	if err := decoder.Decode(&peerKeyData); err != nil {
		return err
	}
	info.PeerECDSA = peerKeyData.ECDSA
	info.PeerRSA = peerKeyData.RSA
	info.SharedSecret = crypto.ComputeSharedSecret(info.ECDSAPrivate, info.PeerECDSA)
	return nil
}

func sendMessages(conn net.Conn, info *ConnectionInfo) {
	encoder := gob.NewEncoder(conn)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Вы: ")
		if !scanner.Scan() {
			break
		}
		text := scanner.Text()
		if text == "/stats" {
			printStats()
			continue
		}
		if text == "/test" {
			results := test.RunSecurityTests()
			jsonResults, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println("=== Результаты теста безопасности ===")
			fmt.Println(string(jsonResults))
			fmt.Println("=====================================")
			continue
		}
		msg := crypto.CreateSecureMessage(
			[]byte(text),
			info.SharedSecret,
			info.ECDSAPrivate,
			info.ECDSAPublic,
			info.RSAPrivate,
			info.Stats,
		)
		if err := encoder.Encode(msg); err != nil {
			fmt.Println("Ошибка отправки:", err)
			break
		}
	}
}

func receiveMessages(conn net.Conn, info *ConnectionInfo) {
	decoder := gob.NewDecoder(conn)
	for {
		var msg crypto.Message
		if err := decoder.Decode(&msg); err != nil {
			if err != io.EOF {
				fmt.Println("\nОшибка получения:", err)
			}
			break
		}
		nonceStr := string(msg.Nonce)
		if _, seen := info.NonceTracker[nonceStr]; seen {
			fmt.Println("\nАтака повторного воспроизведения! Сообщение отклонено.")
			continue
		}
		info.NonceTracker[nonceStr] = true
		if len(info.NonceTracker) > 1000 {
			info.NonceTracker = make(map[string]bool)
		}
		plain, err := crypto.VerifyAndDecryptMessage(msg, info.SharedSecret, info.PeerRSA, info.Stats)
		if err != nil {
			fmt.Println("\nОшибка проверки сообщения:", err)
			continue
		}
		fmt.Print("\r\033[2K")
		fmt.Println("Собеседник:", string(plain))
		fmt.Print("Вы: ")
	}
}

func runServer(address string) {
	info := NewConnectionInfo()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Println("Ожидание клиента на", address)
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	if err := exchangeKeys(conn, info); err != nil {
		log.Fatal("Ошибка обмена ключами:", err)
	}
	fmt.Println("Соединение установлено. Введите сообщение:")
	go receiveMessages(conn, info)
	sendMessages(conn, info)
}

func runClient(address string) {
	info := NewConnectionInfo()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		log.Fatal("Ошибка подключения:", err)
	}
	defer conn.Close()
	if err := exchangeKeys(conn, info); err != nil {
		log.Fatal("Ошибка обмена ключами:", err)
	}
	fmt.Println("Соединение установлено. Введите сообщение:")
	go receiveMessages(conn, info)
	sendMessages(conn, info)
}

func main() {
	serverMode := flag.Bool("server", false, "Запустить в режиме сервера")
	clientMode := flag.Bool("client", false, "Запустить в режиме клиента")
	address := flag.String("addr", "localhost:8080", "Адрес для подключения/прослушивания")
	flag.Parse()
	if *serverMode {
		runServer(*address)
	} else if *clientMode {
		runClient(*address)
	} else {
		fmt.Println("Укажите --server или --client")
	}
}
