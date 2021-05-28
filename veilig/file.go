package veilig

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// Source: https://gist.github.com/ukautz/cd118e298bbd8f0a88fc
func LoadCertificateFromFile(path string) ([]*x509.Certificate, error) {

	raw, err := ioutil.ReadFile(path)
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
			chain = append(chain, cert)
		}
		raw = rest
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("No certificate found in \"%s\"", path)
	}

	fmt.Printf("%sFile: %s (%d bytes) with %d certificate(s)%s\n\n", Comment, path, size, len(chain), Reset)

	return chain, nil
}
