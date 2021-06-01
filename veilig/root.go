package veilig

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
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
	chain       []*x509.Certificate
	dnsname     string
)

// Takes certificate struct and prints values
func printCertificate(cert *x509.Certificate) bool {

	bits := cert.PublicKey.(*rsa.PublicKey)

	fmt.Printf("Subject:%s\t%s%s\n", Green, cert.Subject, Reset)
	fmt.Printf("Valid from:%s\t%s%s\n", Yellow, cert.NotBefore, Reset)
	fmt.Printf("Valid until:%s\t%s%s\n", Yellow, cert.NotAfter, Reset)
	fmt.Printf("Issuer:%s\t\t%s%s\n", Cyan, cert.Issuer.Organization[0], Reset)
	fmt.Printf("Is CA:%s\t\t%t%s\n", Pink, cert.IsCA, Reset)
	fmt.Printf("Signature:%s\t%s%s\n", Pink, cert.SignatureAlgorithm, Reset)
	fmt.Printf("PublicKey:%s\t%s (%d bits)%s\n", Pink, cert.PublicKeyAlgorithm, bits.Size()*8, Reset)

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
		Version:  "1.1.0",
		Compiled: time.Now(),
		Description: `
veilig heise.de:443
veilig /tmp/cert.pem
veilig cert.pem
veilig https://lobste.rs
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
				chain, err = LoadCertificateFromFile(c.Args().Get(0))
				if err != nil {
					fmt.Println(err)
					return nil
				}
			} else {
				if strings.Contains(c.Args().Get(0), "://") {
					chain, dnsname, err = LoadCertificateFromURL(c.Args().Get(0))
				} else {
					chain, dnsname, err = LoadCertificateFromTLS(c.Args().Get(0))
				}
			}

			// Print infos
			for n, cert := range chain {
				if n > 0 {
					fmt.Println()
				}
				fmt.Printf("%s%d. Certificate%s\n", Comment, n+1, Reset)
				printCertificate(cert)
				if len(dnsname) > 0 {
					verifyCertificate(cert, dnsname)
				}
			}
			return nil

		},
	}

	app.Run(os.Args)

}
