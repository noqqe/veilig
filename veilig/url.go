package veilig

import (
	"crypto/x509"
	"fmt"
	"net/url"
)

func LoadCertificateFromURL(ur string) ([]*x509.Certificate, string, error) {

	u, err := url.Parse(ur)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme == "https" {
		return LoadCertificateFromTLS(u.Host + ":443")
	} else {
		return nil, "", fmt.Errorf("URL schema \"%s\" not supported", u.Scheme)
	}

}
