package veilig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

var versions = map[uint16]string{
	tls.VersionSSL30: "SSL",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

var dialer = net.Dialer{
	Timeout: time.Second * 2,
}

// Does TLS Handshake
func connect(host string) (*tls.Conn, error) {
	conn, err := tls.DialWithDialer(&dialer, "tcp", host, nil)
	if err != nil {
		return nil, fmt.Errorf("could not connect to \"%s\"", host)
	}
	return conn, nil
}

func LoadCertificateFromTLS(host string) ([]*x509.Certificate, string, error) {

	// Check if argument is host:port
	conn, err := connect(host)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	state := conn.ConnectionState()

	fmt.Printf("%sConnection: %s via %s using %s%s\n\n", Comment, conn.RemoteAddr(), versions[state.Version], tls.CipherSuiteName(state.CipherSuite), Reset)

	for _, cert := range conn.ConnectionState().VerifiedChains[0] {
		chain = append(chain, cert)
	}
	return chain, strings.Split(host, ":")[0], nil
}
