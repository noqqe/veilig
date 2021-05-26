package veilig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
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

// Takes certificate struct and prints values
func printCertificate(cert *x509.Certificate) bool {

	fmt.Printf("Subject:%s\t%s%s\n", Green, cert.Subject, Reset)
	fmt.Printf("Valid from:%s\t%s%s\n", Yellow, cert.NotBefore, Reset)
	fmt.Printf("Valid until:%s\t%s%s\n", Yellow, cert.NotAfter, Reset)
	fmt.Printf("Issuer:%s\t\t%s%s\n", Cyan, cert.Issuer.Organization[0], Reset)
	fmt.Printf("Is CA?:%s\t\t%t%s\n", Pink, cert.IsCA, Reset)
	fmt.Printf("Algorithm:%s\t%s%s\n", Pink, cert.SignatureAlgorithm, Reset)

	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:%s\t%s%s\n", Purple, strings.Join(cert.DNSNames, ", "), Reset)
	}

	if len(cert.OCSPServer) > 0 {
		fmt.Printf("OCSP Server:%s\t%s%s\n", Comment, strings.Join(cert.OCSPServer, ", "), Reset)
	}

	return true
}

func verifyCertificate(cert *x509.Certificate, host string) {
	if cert.IsCA == false {
		err := cert.VerifyHostname(host)
		if err == nil {
			fmt.Printf("Name Valid:%s\ttrue%s\n", Green, Reset)
		} else {
			fmt.Printf("Name Valid:%s\t\t%s%s\n", Red, cert.VerifyHostname(host), Reset)
		}
	}
}

func Root(args []string) {

	// Option Parser
	app := &cli.App{
		Name:     "veilig",
		Version:  "0.0.5",
		Compiled: time.Now(),
		Description: `
		veilig heise.de:443

or

veilig cert.pem
		`,
		Usage: "x509 Certificate Viewer",
		Action: func(c *cli.Context) error {

			// Check if argument is given
			if c.NArg() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			// Check if argument is file
			_, err := os.Stat(c.Args().Get(0))
			if !os.IsNotExist(err) {
				log.Fatal("File does exist.")
			}

			// Check if argument is host:port
			conn := connect(c.Args().Get(0))
			defer conn.Close()
			state := conn.ConnectionState()
			fmt.Printf("%sConnection: %s via %s using %s%s\n\n", Comment, conn.RemoteAddr(), versions[state.Version], tls.CipherSuiteName(state.CipherSuite), Reset)

			for n, cert := range conn.ConnectionState().VerifiedChains[0] {
				// Formatting
				if n > 0 {
					fmt.Println()
				}
				// Print Cert
				fmt.Printf("%s%d. Certificate%s\n", Comment, n+1, Reset)
				printCertificate(cert)
				verifyCertificate(cert, strings.Split(os.Args[1], ":")[0])
			}
			return nil
		},
	}

	app.Run(os.Args)

}
