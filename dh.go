
package main

import (
		"bufio"
		"bytes"
		"crypto"
		"crypto/sha256"
		"crypto/rand"
		"crypto/rsa"
		"crypto/x509"
		"encoding/hex"
		"encoding/pem"
		"flag"
		"io"
		"io/ioutil"
    "fmt"
		"math/big"
		"net"
		"os"
		"regexp"
		"time"
)

// Prime and generator for DH Group 14 NOTE: The Group 15 prime is too large for RSA to handle (when sending partial keys)
const (
	generator = 2
	prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
var g *big.Int
var p *big.Int

var publicKey *rsa.PublicKey
var privateKey *rsa.PrivateKey

var nonce []byte
var secretExp big.Int
var sessionKey []byte

var mode = flag.String("m", "server", "Mode to run in, must be server or client")
var port = flag.Int("p", 8989, "Port to listen on/connect to")
var host = flag.String("h", "localhost", "Host address to connect to (only needed in client mode)")
var pubKeyFile = flag.String("k", "BAD", "File containing the 3072-bit RSA public key of the target peer (pem format)")
var privKeyFile = flag.String("s", "BAD", "File containing your 3072-bit RSA private key (pem format)")
var debug = flag.Bool("v", false, "True for verbose/debug mode")

func validateArgs() {
	if *mode != "server" && *mode != "client" {
		fmt.Println("Bad mode.")
		os.Exit(2)
	}

	// validate host format
	numRange := "[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]"
	var matched, _ = regexp.MatchString(fmt.Sprintf("^(%[1]s)\\.(%[1]s)\\.(%[1]s)\\.(%[1]s)$", numRange), *host)
	if *host != "localhost" && !matched {
		fmt.Println("Bad host address.")
		os.Exit(2)
	}

	// validate key files
	var err error
	_, err = os.Stat(*pubKeyFile)
	if err != nil {
		fmt.Printf("Bad public key file.\n")
		os.Exit(2)
	}

	_, err = os.Stat(*privKeyFile)
	if err != nil {
		fmt.Printf("Bad private key file.\n")
		os.Exit(2)
	}

	// TODO: validate port number
}

func listenRead(conn net.Conn) {
	for {
		var message = make([]byte, 768)
    receiveIncoming(conn, &message)
		decrypted := verifyAndDecrypt(&message)
		fmt.Print("Received: ", string(decrypted))
	}
}

func listenWrite(conn net.Conn) {
	for {
		// read in input from stdin
		reader := bufio.NewReader(os.Stdin)
		message, err := reader.ReadString('\n')

		if message == "END\n" {
			conn.Close()
			os.Exit(0)
		}

		if err != nil {
			fmt.Println("Error reading outgoing message: ", err.Error())
		}

		outgoing := []byte(message)
		sendOutgoing(conn, encryptAndSign(&outgoing))
	}
}

func receiveIncoming(conn net.Conn, message *[]byte) {
	reader := bufio.NewReader(conn)
	_, err := reader.Read(*message)

	if err == io.EOF {
		fmt.Println("Connection terminated by peer.")
		conn.Close()
		os.Exit(0)
	}

	if e, ok := err.(net.Error); ok && e.Timeout() {
		fmt.Println("Alright people, we've had a timeout.")
		// TODO: intitate key update?
		conn.SetDeadline(time.Now().Local().Add(time.Second * time.Duration(5)))
	}

	if err != nil {
		fmt.Println("Error reading incoming message: ", err.Error())
	}
}

func sendOutgoing(conn net.Conn, message []byte) {
	_, err := conn.Write(message)
	if err != nil {
		fmt.Println("Error writing outgoing message: ", err.Error())
	}
}

func encryptAndSign(plaintext *[]byte) []byte {
	// NOTE: if an RSA key size of less than 3072 is used, message may be too large to encrypt/sign
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, *plaintext, []byte("auth"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		os.Exit(1)
	}

	hashed := sha256.Sum256(ciphertext)
	signature, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		os.Exit(1)
	}

	return append(ciphertext[:], signature[:]...)
}

func verifyAndDecrypt(message *[]byte) []byte {
	rng := rand.Reader

	// first 384 bytes is message then 384 bytes signature
	ciphertext := (*message)[:384]
	signature := (*message)[384:]

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, ciphertext, []byte("auth"))
	if err != nil {
	        fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
	}

	hashed := sha256.Sum256(ciphertext)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
  	fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
	}

	return plaintext
}

func checkNonce(received []byte) {
	if !bytes.Equal(received, nonce) {
		panic("Nonce in response was not as expected!")
	}
}

func parseDhMessage(message *[]byte) {
	plaintext := verifyAndDecrypt(message)

	nonceResponse := plaintext[:32]
	checkNonce(nonceResponse)

	peerPartialKey := plaintext[32:]
	peerPartialKeyInt := new(big.Int)
	peerPartialKeyInt.SetBytes(peerPartialKey)

	computeSessionKey(peerPartialKeyInt)
}

func mutualAuth(conn net.Conn) {
	if *mode == "server" {
		// Step 1: Receive nonce challenge from peer
		var nonceChallenge = make([]byte, 32)
		receiveIncoming(conn, &nonceChallenge)

		// Step 2: Send peer nonce challenge and our partial key
		partialKey := computePartialKey()
		message := append(nonceChallenge[:], partialKey[:]...)
		encrypted := encryptAndSign(&message)

		nonce = generateNonce()
		nonceAndEncrypted := append(nonce[:], encrypted[:]...)
		sendOutgoing(conn, nonceAndEncrypted)

		// Step 3: Receive nonce to check and peer partial key
		var response = make([]byte, 768)
		receiveIncoming(conn, &response)
		parseDhMessage(&response)

	} else { // client mode
		// Step 1: Generate and send a nonce challenge
		nonce = generateNonce()
		sendOutgoing(conn, nonce)

		// Step 2: Receive challenge + nonce to check and peer partial key
		var response = make([]byte, 800)
		receiveIncoming(conn, &response)
		nonceChallenge := response[:32]
		ciphertext := response[32:]

		partialKey := computePartialKey()
		parseDhMessage(&ciphertext)

		// Step 3: Send peer challenge and own partial key encrypted and signed
		message := append(nonceChallenge[:], partialKey[:]...)
		encrypted := encryptAndSign(&message)
		sendOutgoing(conn, encrypted)
	}

	if *debug {
		fmt.Printf("SESSION KEY: %x ", sessionKey)
	}
}

func generateNonce() []byte {
	// according to RFC 2409 length should be between 8 and 256 bytes
	nonce := make([]byte, 32)

	_, err := rand.Read(nonce)
	if err != nil {
		fmt.Println("Problem generating nonce!")
	}

	return nonce
}

func generateExponent() big.Int {
	// 512 bit number should give 256-bit security NOTE: this may be wasted effort given we're using Group 14?
	bytes := make([]byte, 64)

	_, err := rand.Read(bytes)
	if err != nil {
		fmt.Println("Problem generating random bytes for exponent!")
	}

	exponent := new(big.Int)
	exponent.SetBytes(bytes)
	return *exponent
}

func computeSessionKey(peerPartialKey *big.Int) {
	key := new(big.Int)
	key.Exp(peerPartialKey, &secretExp, p)
	sessionKey = key.Bytes()
}

func computePartialKey() []byte {
	secretExp = generateExponent()
	key := new(big.Int)
	key.Exp(g, &secretExp, p)
	return key.Bytes()
}

func prepForBigMath() {
	// convert prime and generator to big Ints
	g = big.NewInt(generator)
	bytes, _ := hex.DecodeString(prime)
	p = new(big.Int)
	p.SetBytes(bytes)
}

func parseKeyFile(keyFile string) []byte{
	data, err := ioutil.ReadFile(keyFile)

	if err != nil {
		fmt.Println("Error readin key file.")
		os.Exit(1)
	}

	if len(data) == 0 {
		fmt.Println("Error parsing key file.")
		os.Exit(1)
	}

	keyBlock, _ := pem.Decode(data)
	// TODO: handle case where decode fails because it's not in pem format
	return keyBlock.Bytes
}

func initValues() {
	prepForBigMath()

	var err error

	privBytes := parseKeyFile(*privKeyFile)
	privateKey, err = x509.ParsePKCS1PrivateKey(privBytes)

	if err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	pubBytes := parseKeyFile(*pubKeyFile)
	parsed, err := x509.ParsePKIXPublicKey(pubBytes)

	if err != nil {
		panic("Failed to parse public key: " + err.Error())
	}

	var typeOK bool
	publicKey, typeOK = parsed.(*rsa.PublicKey)

	if !typeOK {
		panic("Public key is of wrong type. Please make sure you use RSA keys.")
	}
}

func main() {
	flag.Parse()
	validateArgs()
	initValues()

	var conn net.Conn
	var err error

	if *mode == "server" {
		// server mode
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Println("Error trying to listen on port.")
			os.Exit(1)
		}

		// only accepting one connection
		conn, err = ln.Accept()
		ln.Close()

		if err != nil {
			fmt.Println("Error accepting connection.")
		}

	} else {
		// client mode
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Println("Could not connect.")
			os.Exit(1)
		}
	}

	// conn.SetDeadline(time.Now().Local().Add(time.Second * time.Duration(5)))

	mutualAuth(conn)

	go listenRead(conn)
	go listenWrite(conn)

	for {} // TODO: instead, make main wait for the routines to be done
}
