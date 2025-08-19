package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ChriZzn/sslx/sslx"
)

var host = "86.106.182.135:587"

func main() {

	// Example Net Connection
	conn, _ := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})

	// Pick any tls.ConnectionState for Fingerprinting (tls.Dial / smtp.StartTLS / ...)
	state := conn.ConnectionState()

	// Results are Calculated from the ConnectionState struct
	result, _ := sslx.GatherSSLInfo(&state)
	output, _ := json.MarshalIndent(result, "", " ")
	fmt.Println(string(output))

}
