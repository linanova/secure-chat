
package main

import (
		"bufio"
		"flag"
		"io"
    "fmt"
		"net"
		"os"
		"regexp"
)

// Prime and generator for DH Group 14
const (
	g = 2
	p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

var mode = flag.String("m", "server", "Mode to run in, must be server or client")
var port = flag.Int("p", 8989, "Port to listen on/connect to")
var host = flag.String("h", "localhost", "Host address to connect to (only needed in client mode)")
var keyFile = flag.String("k", "BAD", "File containing the public key of the target you want to talk to")

func validateArgs() {
	if *mode != "server" && *mode != "client" {
		fmt.Printf("Bad mode.\n")
		os.Exit(2)
	}

	// validate host format
	numRange := "[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]"
	var matched, _ = regexp.MatchString(fmt.Sprintf("^(%[1]s)\\.(%[1]s)\\.(%[1]s)\\.(%[1]s)$", numRange), *host)
	if *host != "localhost" && !matched {
		fmt.Printf("Bad host address.\n")
		os.Exit(2)
	}

	// validate key file
	_, err := os.Stat(*keyFile)
	if err != nil {
		fmt.Printf("Bad key file.\n")
		os.Exit(2)
	}

	// TODO: validate port number
}

func listenRead(conn net.Conn) {
	for {
    message, err := bufio.NewReader(conn).ReadString('\n')

		if err == io.EOF {
			fmt.Println("Connection terminated by peer.")
			conn.Close()
			os.Exit(0)
		}

		if err != nil {
			fmt.Println("Error reading incoming message: ", err.Error())
		}

    fmt.Print("Received:", string(message))
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

		_, err = conn.Write([]byte(message + "\n"))
		if err != nil {
			fmt.Println("Error writing outgoing message: ", err.Error())
		}
	}
}

func main() {
	flag.Parse()
	validateArgs()

	var conn net.Conn
	var err error

	if *mode == "server" {
		// server mode
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Printf("Error trying to listen on port.\n")
			os.Exit(1)
		}

		// only accepting one connection
		conn, err = ln.Accept()
		ln.Close()

		if err != nil {
			fmt.Printf("Error accepting connection.\n")
		}

	} else {
		// client mode
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Printf("Could not connect.\n")
			os.Exit(1)
		}
	}

	go listenRead(conn)
	go listenWrite(conn)

	for {} // TODO: instead, make main wait for the routines to be done
}
