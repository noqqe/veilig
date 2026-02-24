// Package veilig is a toy ssl tls cert viewer
package veilig

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	color "github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

var (
	chain   []*x509.Certificate
	Version = "unknown"
)

// Takes certificate struct and prints values
func printCertificate(cert *x509.Certificate) bool {

	color.Green("Subject:\t%s\n", cert.Subject)
	color.Yellow("Valid from:\t%s\n", cert.NotBefore)
	color.Yellow("Valid until:\t%s\n", cert.NotAfter)

	if len(cert.Issuer.Organization) > 0 {
		color.Cyan("Issuer:\t\t%s\n", cert.Issuer.Organization[0])
	}

	color.HiCyan("Is CA:\t\t%t\n", cert.IsCA)
	color.HiMagenta("Signature:\t%s\n", cert.SignatureAlgorithm)

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := cert.PublicKey.(*rsa.PublicKey)
		color.HiMagenta("PublicKey:\t%s (%d bits)\n", cert.PublicKeyAlgorithm, bits.Size()*8)
	case *ecdsa.PublicKey:
		curve := cert.PublicKey.(*ecdsa.PublicKey)
		params := curve.Params()
		color.HiMagenta("PublicKey:\t%s %v (%d bits)\n", cert.PublicKeyAlgorithm, params.Name, params.BitSize)
	default:
		color.HiMagenta("PublicKey:%s\t%s%s\n", cert.PublicKeyAlgorithm)
	}

	if len(cert.DNSNames) > 0 {
		color.HiCyan("DNS Names:\t%s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.OCSPServer) > 0 {
		color.HiBlue("OCSP Server:\t%s\n", strings.Join(cert.OCSPServer, ", "))
	}

	return true
}

func verifyCertificate(cert *x509.Certificate, host string) {
	if !cert.IsCA {
		err := cert.VerifyHostname(host)
		if err == nil {
			color.Green("Name Valid:\t%s\n", "true")
		} else {
			color.Red("Name Valid:\t%s%s\n", "false: ", cert.VerifyHostname(host))
		}
	}
}

// Check if the argument is a file
func isFile(arg string) bool {
	_, err := os.Stat(arg)
	return !os.IsNotExist(err)
}

// Check if the argument is a valid URL
func isURL(arg string) bool {
	_, err := url.ParseRequestURI(arg)
	return err == nil
}

// Check if the argument is in host:port format
func isHostPort(arg string) bool {
	hostPort := strings.Split(arg, ":")
	if len(hostPort) != 2 {
		return false
	}
	host := hostPort[0]
	port := hostPort[1]

	// Validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return false
	}

	// Check if the host can be resolved
	_, err = net.LookupHost(host)
	return err == nil
}

func Root(args []string) {

	// Option Parser
	app := &cli.App{
		Name:     "veilig",
		Version:  Version,
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

			// initialize variables
			arg := c.Args().Get(0)
			var chain []*x509.Certificate
			var dnsname string
			var err error

			switch {
			case isFile(arg):
				chain, err = LoadCertificateFromFile(arg)
				if err != nil {
					fmt.Println("Error loading certificate from file:", err)
				}
			case isHostPort(arg):
				chain, dnsname, err = LoadCertificateFromTLS(arg)
				if err != nil {
					fmt.Println("Error loading certificate from TLS:", err)
				}
			case isURL(arg):
				chain, dnsname, err = LoadCertificateFromURL(arg)
				if err != nil {
					fmt.Println("Error loading certificate from URL:", err)
				}
			default:
				fmt.Println("Invalid argument format:", arg)
				cli.ShowAppHelp(c)
			}

			// Print infos
			for n, cert := range chain {
				if n > 0 {
					fmt.Println()
				}
				color.White("%d. Certificate\n", n+1)
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
