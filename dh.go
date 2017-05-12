
package main

import (
		"flag"
    "fmt"
		"net"
		"os"
		"regexp"
)

var mode = flag.String("m", "server", "Mode to run in, must be server or client")
var port = flag.Int("p", 8989, "Port to listen on/connect to")
var host = flag.String("h", "localhost", "Host address to connect to (only needed in client mode)")

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

	// validate port number
}

func main() {
	flag.Parse()
	validateArgs()

	if *mode == "server" {
		// server code
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Printf("Error trying to listen on port.\n")
			os.Exit(1)
		}

		for {
			_, err := ln.Accept()
			if err != nil {
				fmt.Printf("Error accepting connection.\n")
				os.Exit(1)
			}
			// handle connection
		}

	} else {
		// client code
		_, err := net.Dial("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Printf("Could not connect.\n")
			os.Exit(1)
		}
	}

}
