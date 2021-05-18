package veilig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

var (
	Reset       = "\033[0m"
	Background  = "\033[38;5;59m"
	CurrentLine = "\033[38;5;60m"
	Foreground  = "\033[38;5;231m"
	Comment     = "\033[38;5;103m"
	Cyan        = "\033[38;5;159m"
	Green       = "\033[38;5;120m"
	Orange      = "\033[38;5;222m"
	Pink        = "\033[38;5;212m"
	Purple      = "\033[38;5;183m"
	Red         = "\033[38;5;210m"
	Yellow      = "\033[38;5;229m"
)

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

// Takes certificate struct and prints values
func printCertificate(cert *x509.Certificate) bool {

	fmt.Printf("Subject:%s\t%s%s\n", Green, cert.Subject, Reset)
	fmt.Printf("Valid from:%s\t%s%s\n", Yellow, cert.NotBefore, Reset)
	fmt.Printf("Valid until:%s\t%s%s\n", Yellow, cert.NotAfter, Reset)
	fmt.Printf("Is CA?:%s\t\t%t%s\n", Pink, cert.IsCA, Reset)
	fmt.Printf("Algorithm:%s\t%s%s\n", Pink, cert.SignatureAlgorithm, Reset)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:%s\t%s%s\n", Purple, cert.DNSNames, Reset)
	}
	if len(cert.OCSPServer) > 0 {
		fmt.Printf("OCSP Server:%s\t%s%s\n", Comment, cert.OCSPServer, Reset)
	}
	return true
}

func root(args []string) {

	conn := connect(os.Args[1])
	defer conn.Close()

	for n, cert := range conn.ConnectionState().VerifiedChains[0] {
		// Formatting
		if n > 0 {
			fmt.Println()
		}
		// Print Cert
		fmt.Printf("%s%d. Certificate%s\n", Comment, n+1, Reset)
		printCertificate(cert)
	}
}
