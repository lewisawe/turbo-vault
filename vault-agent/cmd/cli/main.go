package main

import (
	"os"

	"github.com/keyvault/agent/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}