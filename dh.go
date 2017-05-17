// Package provides a simple secure communication channel. It implements
// Diffie Hellman for mutual authentication and key establishment.
// The benefit of using DH instead of just RSA is that it provides PFS.
package main

import (
		"bufio"
		"crypto/aes"
		"crypto/cipher"
		"crypto/rand"
		"crypto/sha256"
		"flag"
		"io"
    "fmt"
		"net"
		"os"
		"regexp"
		"time"
)

// Use 96-bit IV as recommended by NIST
// IV needs to be unique but not necessarily random. If we do use a random IV,
// there's a 50% chance of a duplicate after 2^48 messages. We could make sure
// the key is refreshed before that happens!
const IVLen = 12

var mode = flag.String("m", "server", "Mode to run in, must be server or client")
var port = flag.Int("p", 8989, "Port to listen on/connect to")
var host = flag.String("h", "localhost", "Host address to connect to (only needed in client mode)")
var pubKeyFile = flag.String("k", "BAD", "File containing the 3072-bit RSA public key of the target peer (PEM format)")
var privKeyFile = flag.String("s", "BAD", "File containing your 3072-bit RSA private key (PEM format)")
var debug = flag.Bool("v", false, "True for verbose/debug mode")

func validateArgs() {
	if *mode != "server" && *mode != "client" {
		fmt.Fprintln(os.Stderr, "Invalid mode. Must be 'client' or 'server'.")
		os.Exit(2)
	}

	// validate host format as either 'localhost' or x.x.x.x where x is 0-255
	numRange := "[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]"
	var matched, _ = regexp.MatchString(fmt.Sprintf("^(%[1]s)\\.(%[1]s)\\.(%[1]s)\\.(%[1]s)$", numRange), *host)
	if *host != "localhost" && !matched {
		fmt.Fprintln(os.Stderr, "Invalid host address format.")
		os.Exit(2)
	}

	// validate key files exist
	var err error
	_, err = os.Stat(*pubKeyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Public key file does not exist.")
		os.Exit(2)
	}

	_, err = os.Stat(*privKeyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Private key file does not exist.")
		os.Exit(2)
	}
}

func listenRead(conn net.Conn) {
	for {
		var maxLen int = 1024 // TODO: this is totally arbitrary - figure out better way
		var message = make([]byte, maxLen)
    messageLen := receiveIncoming(conn, &message)

		IV := message[:IVLen]
		ciphertext := message[IVLen:messageLen]
		plaintext := decrypt(ciphertext, IV)
		fmt.Printf("Received: %s", string(plaintext))
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

		outgoing := encrypt([]byte(message))
		sendOutgoing(conn, outgoing)
	}
}

// Technically generateNonce simply gives a random value of the requested length
// whether it's actually used as a nonce is up to the function caller
func generateNonce(len int) []byte {
	nonce := make([]byte, len)

	_, err := rand.Read(nonce)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Problem generating nonce!")
		os.Exit(1)
	}

	return nonce
}

func encrypt(plaintext []byte) []byte {
	IV := generateNonce(IVLen)

  // key needs to be 256-bit, use sha256 TODO: probably don't need to do this EVERY time?
	key := sha256.Sum256(sessionKey)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error with AES encryption: " + err.Error())
		os.Exit(1)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error with AES encryption: " + err.Error())
		os.Exit(1)
	}

	ciphertext := aesgcm.Seal(nil, IV, plaintext, nil)
	// fmt.Printf("Sending IV: %x\nSending Ciphertext: %x\n", IV, ciphertext)
	return append(IV[:], ciphertext[:]...)
}

func decrypt(ciphertext []byte, IV []byte) []byte {
	// key needs to be 256-bit, use sha256 TODO: probably don't need to do this EVERY time?
	key := sha256.Sum256(sessionKey)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error with AES decryption: " + err.Error())
		os.Exit(1)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error with AES decryption: " + err.Error())
		os.Exit(1)
	}

	plaintext, err := aesgcm.Open(nil, IV, ciphertext, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error with AES decryption: " + err.Error())
		os.Exit(1)
	}

	return plaintext
}

func receiveIncoming(conn net.Conn, message *[]byte) int {
	reader := bufio.NewReader(conn)
	numRead, err := reader.Read(*message)

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

	return numRead
}

func sendOutgoing(conn net.Conn, message []byte) {
	_, err := conn.Write(message)
	if err != nil {
		fmt.Println("Error writing outgoing message: ", err.Error())
		os.Exit(1)
	}
}

func init() {
  flag.Parse()
  validateArgs()
	prepDHValues()
}

func main() {
	var conn net.Conn
	var err error

	if *mode == "server" {
		// server mode
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error trying to listen on %s:%d.\n", *host, *port)
			os.Exit(1)
		}

		// only accept one connection, then close the listener
		conn, err = ln.Accept()
		ln.Close()

		if err != nil {
			fmt.Fprintln(os.Stderr, "Error accepting connection.")
			os.Exit(1)
		}

	} else {
		// client mode
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not connect to %s:%d.\n", *host, *port)
			os.Exit(1)
		}
	}

	// conn.SetDeadline(time.Now().Local().Add(time.Second * time.Duration(5)))
	mutualAuth(conn)

	go listenRead(conn)
	go listenWrite(conn)

	for {} // TODO: instead, make main wait for the routines to be done
}
