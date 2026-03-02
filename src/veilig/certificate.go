package veilig

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"strings"

	"github.com/fatih/color"
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

// Verifies if the cert name matches the given domain name
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
