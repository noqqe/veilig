package veilig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

var versions = map[uint16]string{
	tls.VersionSSL30: "SSL",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// Does TLS Handshake
func connect(host string) *tls.Conn {
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		fmt.Println("Could not connect to", os.Args[1])
		fmt.Println("Did you specify the port correctly?")
		os.Exit(1)
	}
	return conn
}

func LoadCertificateFromTLS(host string) ([]*x509.Certificate, error) {

	// Check if argument is host:port
	conn := connect(host)
	defer conn.Close()
	state := conn.ConnectionState()

	fmt.Printf("%sConnection: %s via %s using %s%s\n\n", Comment, conn.RemoteAddr(), versions[state.Version], tls.CipherSuiteName(state.CipherSuite), Reset)

	for _, cert := range conn.ConnectionState().VerifiedChains[0] {
		chain = append(chain, cert)
	}
	return chain, nil
}
