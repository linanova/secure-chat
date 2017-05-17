package main

import (
  "bytes"
  "crypto"
  "crypto/sha256"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/hex"
  "encoding/pem"
  "io/ioutil"
  "fmt"
  "math/big"
  "net"
  "os"
)

const (
	dhNonceLen = 32 // according to RFC 2409 nonce should be between 8 and 256 bytes
	rsaLen = 384 // Length of RSA encrptions and signatures assuming 3072-bit key
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

func prepDHValues() {
  // 1. parse prime and generator into big Ints
  g = big.NewInt(generator)

  bytes, _ := hex.DecodeString(prime)
  p = new(big.Int)
  p.SetBytes(bytes)

  // 2. Parse public and private key files into RSA key format
  var err error

	privBytes := parseKeyFile(*privKeyFile)
	privateKey, err = x509.ParsePKCS1PrivateKey(privBytes)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse private key: " + err.Error())
		os.Exit(1)
	}

	if privateKey.N.BitLen() != 3072 {
		fmt.Fprintln(os.Stderr, "Private key provided is not 3072-bit.")
		os.Exit(1)
	}

	pubBytes := parseKeyFile(*pubKeyFile)
	parsed, err := x509.ParsePKIXPublicKey(pubBytes)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse public key: " + err.Error())
		os.Exit(1)
	}

	var typeOK bool
	publicKey, typeOK = parsed.(*rsa.PublicKey)

	if !typeOK {
		fmt.Fprintln(os.Stderr, "Public key is of wrong type. Please make sure you use RSA keys.")
		os.Exit(1)
	}

	if publicKey.N.BitLen() != 3072 {
		fmt.Fprintln(os.Stderr, "Public key provided is not 3072-bit.")
		os.Exit(1)
	}
}

// computeSessionKey computes (g^bmodp)^amodp and saves the result in the
// global variable sessionKey.
func computeSessionKey(peerPartialKey *big.Int) {
	key := new(big.Int)
	key.Exp(peerPartialKey, &secretExp, p)
	sessionKey = key.Bytes()
}

// computePartialKey computes g^amodp and returns the result as a byte slice.
func computePartialKey() []byte {
	secretExp = generateExponent()
	key := new(big.Int)
	key.Exp(g, &secretExp, p)
	return key.Bytes()
}

// parseKeyFile reads the content of the specified file and attempts to
// decode it into a PEM block.
func parseKeyFile(keyFile string) []byte {
	data, err := ioutil.ReadFile(keyFile)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading key file: " + err.Error())
		os.Exit(1)
	}

	if len(data) == 0 {
		fmt.Fprintln(os.Stderr, "Key file is empty.")
		os.Exit(1)
	}

	// TODO: pem block may be encrypted with a passcode! check for it
	keyBlock, _ := pem.Decode(data)
	if keyBlock == nil {
		fmt.Fprintln(os.Stderr, "Key file is not in PEM format.")
		os.Exit(1)
	}

	return keyBlock.Bytes
}

// generateExponent generates a random secret exponent to be used in the diffie
// hellman key exchange.
func generateExponent() big.Int {
	// 512 bit number should give 256-bit security NOTE: this may be wasted effort given we're using Group 14?
	bytes := make([]byte, 64)

	_, err := rand.Read(bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Problem generating random bytes for exponent!")
		os.Exit(1)
	}

	exponent := new(big.Int)
	exponent.SetBytes(bytes)
	return *exponent
}

func checkNonce(received []byte) {
	if !bytes.Equal(received, nonce) {
		fmt.Fprintln(os.Stderr, "Challenge response was incorrect!")
		os.Exit(1)
	}
}

// parseDhMessage takes a cipertext message and extracts the nonce response
// and partial key. Then, it checks that the nonce response matches the one
// that was sent, and uses the partial key to compute the session key.
func parseDhMessage(message *[]byte) {
	plaintext := verifyAndDecrypt(message)

	nonceResponse := plaintext[:dhNonceLen]
	checkNonce(nonceResponse)

	peerPartialKey := plaintext[dhNonceLen:]
	peerPartialKeyInt := new(big.Int)
	peerPartialKeyInt.SetBytes(peerPartialKey)

	computeSessionKey(peerPartialKeyInt)
}

// encryptAndSign uses the peer's public key to encrypt using RSA-OAEP and our
// private key to sign using RSASSA-PKCS1-V1_5-SIGN. It returns the appended
// ciphertext and signature.
func encryptAndSign(plaintext *[]byte) []byte {
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

// verifyAndDecrypt splits the given message into cipertext and signature. It
// verifies the signature and if all is good, returns the decrypted message.
func verifyAndDecrypt(message *[]byte) []byte {
	rng := rand.Reader

	// first half is the message second half is the signature
	ciphertext := (*message)[:rsaLen]
	signature := (*message)[rsaLen:]

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, ciphertext, []byte("auth"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		os.Exit(1)
	}

	hashed := sha256.Sum256(ciphertext)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
  	fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		os.Exit(1)
	}

	return plaintext
}

// mutualAuth prompts an exchange of messages as defined by the diffie
// hellman algorithm. Both sides are authenticated to each other, and
// they establish a shared secret symmetric key to use for future communication
func mutualAuth(conn net.Conn) {
	if *mode == "server" {
		// Step 1: Receive nonce challenge from peer
		var nonceChallenge = make([]byte, dhNonceLen)
		receiveIncoming(conn, &nonceChallenge)

		// Step 2: Send peer nonce challenge and our partial key
		partialKey := computePartialKey()
		message := append(nonceChallenge[:], partialKey[:]...)
		encrypted := encryptAndSign(&message)

		nonce = generateNonce(dhNonceLen)
		nonceAndEncrypted := append(nonce[:], encrypted[:]...)
		sendOutgoing(conn, nonceAndEncrypted)

		// Step 3: Receive nonce to check and peer partial key
		var response = make([]byte, 768)
		receiveIncoming(conn, &response)
		parseDhMessage(&response)

	} else { // client mode
		// Step 1: Generate and send a nonce challenge
		nonce = generateNonce(dhNonceLen)
		sendOutgoing(conn, nonce)

		// Step 2: Receive challenge + nonce to check and peer partial key
		var response = make([]byte, 800)
		receiveIncoming(conn, &response)
		nonceChallenge := response[:dhNonceLen]
		ciphertext := response[dhNonceLen:]

		partialKey := computePartialKey()
		parseDhMessage(&ciphertext)

		// Step 3: Send peer challenge and own partial key encrypted and signed
		message := append(nonceChallenge[:], partialKey[:]...)
		encrypted := encryptAndSign(&message)
		sendOutgoing(conn, encrypted)
	}

	if *debug {
		fmt.Printf("SESSION KEY: %x", sessionKey)
	}
}
