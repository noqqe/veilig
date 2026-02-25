package veilig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

var versions = map[uint16]string{
	tls.VersionSSL30: "SSL",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

func isValidPortSuffix(s string) bool {
	// Regular expression to match a string ending with ":port" where port is digits
	re := regexp.MustCompile(`:(\d+)$`)

	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		return false
	}

	portStr := matches[1]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}

	return true
}

func LoadCertificateFromURL(ur string) ([]*x509.Certificate, string, error) {

	if !strings.HasPrefix(ur, "https://") {
		ur = "https://" + ur
	}
	u, err := url.Parse(ur)

	fmt.Printf("Parsing URL %s...\n", u)
	fmt.Printf("Host: %s\n", u.Host)
	fmt.Printf("Scheme: %s\n", u.Scheme)
	fmt.Printf("Port: %s\n", u.Port())

	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Connecting to %s...\n", u)
	return LoadCertificateFromTLS(u)

}

func LoadCertificateFromTLS(url *url.URL) ([]*x509.Certificate, string, error) {

	config := &tls.Config{
		MinVersion:         tls.VersionSSL30,
		InsecureSkipVerify: true,
	}

	dialer := net.Dialer{
		Timeout: time.Second * 2,
	}

	host := url.Host
	if !isValidPortSuffix(url.Host) {
		host = host + ":443"
	}

	conn, err := tls.DialWithDialer(&dialer, "tcp", host, config)
	if err != nil {
		return chain, url.Host, fmt.Errorf("could not connect to %s: %v", host, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()

	color.HiBlack("Connection: %s via %s using %s\n\n", conn.RemoteAddr(), versions[state.Version], tls.CipherSuiteName(state.CipherSuite))

	if len(conn.ConnectionState().PeerCertificates) > 0 {
		chain = append(chain, conn.ConnectionState().PeerCertificates...)
	}
	return chain, url.Host, nil
}
