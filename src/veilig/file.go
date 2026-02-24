package veilig

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fatih/color"
)

// LoadCertificateFromFile reads the cert from file
// Source: https://gist.github.com/ukautz/cd118e298bbd8f0a88fc
func LoadCertificateFromFile(path string) ([]*x509.Certificate, error) {

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fi, _ := os.Stat(path)
	size := fi.Size()

	var chain []*x509.Certificate
	var cert *x509.Certificate
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("could not parse certificate in \"%s\": %v", path, err)
			}
			chain = append(chain, cert)
		}
		raw = rest
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificate found in \"%s\"", path)
	}

	color.HiBlack("File: %s (%d bytes) with %d certificate(s)\n\n", path, size, len(chain))

	return chain, nil
}
