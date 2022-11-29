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
