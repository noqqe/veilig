package veilig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/fatih/color"
	"github.com/goware/urlx"
)

var versions = map[uint16]string{
	tls.VersionSSL30: "SSL",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

func LoadCertificateFromURL(url string) ([]*x509.Certificate, string, error) {

	u, err := urlx.Parse(url)
	if err != nil {
		return nil, "", err
	}
	host, port, err := urlx.SplitHostPort(u)
	if err != nil {
		return nil, "", err
	}

	if port == "" {
		port = "443"
	}

	return LoadCertificateFromTLS(host, port)
}

func LoadCertificateFromTLS(host, port string) ([]*x509.Certificate, string, error) {

	config := &tls.Config{
		MinVersion:         tls.VersionSSL30,
		InsecureSkipVerify: true,
	}

	dialer := net.Dialer{
		Timeout: time.Second * 2,
	}

	conn, err := tls.DialWithDialer(&dialer, "tcp", host+":"+port, config)
	if err != nil {
		return chain, host, fmt.Errorf("could not connect to %s: %v", host+":"+port, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()

	color.HiBlack("Connection: %s via %s using %s\n\n", conn.RemoteAddr(), versions[state.Version], tls.CipherSuiteName(state.CipherSuite))

	if len(conn.ConnectionState().PeerCertificates) > 0 {
		chain = append(chain, conn.ConnectionState().PeerCertificates...)
	}
	return chain, host, nil
}
