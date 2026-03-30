// go-gdetect is a command-line client for the GLIMPS Malware Detect API.
// It provides commands to submit files, retrieve analysis results, search by
// SHA256, export reports, and query profile status.
package main

import (
	"os"

	"github.com/glimps-re/go-gdetect/cmd/cli"
)

func main() {
	err := cli.Execute()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
