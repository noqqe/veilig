package veilig

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/fatih/color"
)

var (
	Cyan    = color.New(color.FgCyan).SprintFunc()
	Green   = color.New(color.FgGreen).SprintFunc()
	Red     = color.New(color.FgRed).SprintFunc()
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
	Pink    = color.New(color.FgHiMagenta).SprintFunc()
	Black   = color.New(color.FgHiBlack).SprintFunc()
)

// Takes certificate struct and prints values
func printCertificate(cert *x509.Certificate) bool {

	fmt.Printf("Subject:\t%s\n", Green(cert.Subject))
	fmt.Printf("Valid from:\t%s\n", Yellow(cert.NotBefore))
	fmt.Printf("Valid until:\t%s\n", Yellow(cert.NotAfter))

	if len(cert.Issuer.Organization) > 0 {
		fmt.Printf("Issuer:\t\t%s\n", Cyan(cert.Issuer.Organization[0]))
	}

	fmt.Printf("Is CA:\t\t%s\n", Cyan(cert.IsCA))
	fmt.Printf("Signature:\t%s\n", Magenta(cert.SignatureAlgorithm))

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := cert.PublicKey.(*rsa.PublicKey)
		fmt.Printf("PublicKey:\t%s (%d bits)\n", Magenta(cert.PublicKeyAlgorithm), bits.Size()*8)
	case *ecdsa.PublicKey:
		curve := cert.PublicKey.(*ecdsa.PublicKey)
		params := curve.Params()
		fmt.Printf("PublicKey:\t%s %v (%d bits)\n", Magenta(cert.PublicKeyAlgorithm), params.Name, params.BitSize)
	default:
		fmt.Printf("PublicKey:%s\t%s%s\n", Magenta(cert.PublicKeyAlgorithm))
	}

	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:\t%s\n", Cyan(strings.Join(cert.DNSNames, ", ")))
	}

	if len(cert.OCSPServer) > 0 {
		fmt.Printf("OCSP Server:\t%s\n", Cyan(strings.Join(cert.OCSPServer, ", ")))
	}

	return true
}

// Verifies if the cert name matches the given domain name
func verifyCertificate(cert *x509.Certificate, host string) {
	if !cert.IsCA {
		err := cert.VerifyHostname(host)
		if err == nil {
			fmt.Printf("Name Valid:\t%s\n", Green("true"))
		} else {
			fmt.Printf("Name Valid:\t%s%s\n", "false: ", Red(cert.VerifyHostname(host)))
		}
	}
}
