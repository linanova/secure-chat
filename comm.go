// Simple secure communication channel.
// AES-GCM for symmetric encryption/decryption.
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
)

// Use 96-bit IV as recommended by NIST
// IV needs to be unique but not necessarily random. If we do use a random IV,
// make sure the key is refreshed FAR before 2^32 exchanges happen. IV dupes in
// GCM are seriously bad.
const ivLen = 12

var aead cipher.AEAD

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

// listenRead listens for incoming messages on the connection, decrypts, and prints out
func listenRead(conn net.Conn, done chan bool) {
    reader := bufio.NewReader(conn)

    for {
        maxLen := 1024 // TODO: this is arbitrary - message header with len would be better
        message := make([]byte, maxLen)
        messageLen, err := receiveIncoming(reader, &message)

        if err == io.EOF {
            fmt.Println("Connection terminated by peer.")
            conn.Close()
            os.Exit(0)
            done <- true
        }

        IV := message[:ivLen]
        ciphertext := message[ivLen:messageLen]
        plaintext := decrypt(ciphertext, IV)
        fmt.Printf("Received: %s", string(plaintext))
    }
}

// listenWrite listens for stdin input, encrypts, and wrties out to the connection
func listenWrite(conn net.Conn, done chan bool) {
    readerStdin := bufio.NewReader(os.Stdin)

    for {
        // read in input from stdin
        message, err := readerStdin.ReadString('\n')

        // treat "END" as a keyword used by the user to terminate the connection
        if message == "END\n" {
            conn.Close()
            os.Exit(0)
            done <- true
        }

        if err != nil {
            fmt.Println("Error reading outgoing message: ", err.Error())
        }

        outgoing := encrypt([]byte(message))
        sendOutgoing(conn, outgoing)
    }
}

// genRandomBytes returns a random byte slice of the requested length
func genRandomBytes(len int) []byte {
    random := make([]byte, len)

    _, err := rand.Read(random)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Problem generating random value: ", err.Error())
        os.Exit(1)
    }

    return random
}

// computeSessionCipher uses the session key to set up a new GCM cipher.
func computeSessionCipher() {
    hashedKey := sha256.Sum256(sessionKey)

    block, err := aes.NewCipher(hashedKey[:])
    if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
        os.Exit(1)
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
        os.Exit(1)
    }

    aead = aesgcm
}

// encrypt encrypts and authenticates (seals) the given message with our aead
func encrypt(plaintext []byte) []byte {
    IV := genRandomBytes(ivLen)
    ciphertext := aead.Seal(nil, IV, plaintext, nil)

    return append(IV[:], ciphertext[:]...)
}

// decrypt decrypts and authenticates (opens) the given message with our aead
func decrypt(ciphertext []byte, IV []byte) []byte {
    plaintext, err := aead.Open(nil, IV, ciphertext, nil)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error with AES decryption: " + err.Error())
        os.Exit(1)
    }

    return plaintext
}

// receiveIncoming reads into the specified slice. Number of bytes read will be
// up to a max of the slice length. The actual number read is returned along with
// any error.
func receiveIncoming(reader *bufio.Reader, message *[]byte) (int, error) {
    numRead, err := reader.Read(*message)

    if err != nil {
        fmt.Println("Error reading incoming message: ", err.Error())
    }

    return numRead, err
}

// sendOutgoing writes out the given message to the connection
func sendOutgoing(conn net.Conn, message []byte) {
    numWritten, err := conn.Write(message)

    if err != nil {
        fmt.Println("Error writing outgoing message: ", err.Error())
        os.Exit(1)
    }

    if numWritten != len(message) {
        fmt.Println("Could not write out the full message.")
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

    // Note this is not a server in the traditional sense, as it only takes in
    // one connection. The roles are needed simply to establish who initiates
    // the connection
    if *mode == "server" {
        // server mode
        ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error trying to listen on %s:%d.\n", *host, *port)
            os.Exit(1)
        }

        // accept one connection, then close the listener
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

    // initiate Diffie Hellman exchange
    keyExchange(conn)
    computeSessionCipher()

    // now that a session key is established, spin up routines to listen
    // for incoming and outgoing messages
    done := make(chan bool)
    go listenRead(conn, done)
    go listenWrite(conn, done)

    <-done
}
