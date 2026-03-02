// Package veilig is a toy ssl tls cert viewer
package veilig

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/goware/urlx"
	"github.com/urfave/cli/v2"
)

var (
	chain   []*x509.Certificate
	Version = "unknown"
)

// Check if the argument is a file
func isFile(arg string) bool {
	_, err := os.Stat(arg)
	return !os.IsNotExist(err)
}

// Check if the argument is a valid URL
func isNetwork(arg string) bool {
	_, err := urlx.Parse(arg)
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
					os.Exit(1)
				}
			case isNetwork(arg):
				chain, dnsname, err = LoadCertificateFromURL(arg)
				if err != nil {
					fmt.Println("Error loading certificate from TLS:", err)
					os.Exit(1)
				}
			default:
				fmt.Println("Invalid argument format:", arg)
				cli.ShowAppHelp(c)
				os.Exit(1)
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
