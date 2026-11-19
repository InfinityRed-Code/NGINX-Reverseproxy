// nrp ist Dienst (nrp serve) und CLI in einem Binary.
package main

import (
	"os"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/cli"
)

// version wird beim Build gesetzt: -ldflags "-X main.version=v3.0.0".
var version = "dev"

func main() {
	os.Exit(cli.Execute(version))
}
