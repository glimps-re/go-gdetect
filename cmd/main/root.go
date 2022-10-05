// Package gogdetect implements multiple commands to interact with GLIMPS
// Malware detect API. To manipulate directly detect's API, use package
// [pkg/gdetect/gdetect].
//
// Usage:
// gogdetect [command]
//
// Available Commands:
//
//	completion  Generate the autocompletion script for the specified shell
//	get         Get a file by its uuid
//	help        Help about any command
//	search      Search a previous analysis
//	submit      Submit a file to gdetect api
//	waitfor     Submit a file to gdetect api and wait for results
//
// Flags:
//
//	-h, --help           help for gogdetect
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gogdetect",
	Short: "gogdetect - interact with GLIMPS malware detect API",
}

func Execute() (err error) {
	// Check if cmd is well recognized
	cmd, _, errCmdNotFound := rootCmd.Find(os.Args[1:])
	if errCmdNotFound != nil || cmd == nil {
		// Not found: we launch default command (submit)
		args := append([]string{"gogdetect", "submit"}, os.Args[1:]...)
		os.Args = args
	}

	err = rootCmd.Execute()
	return
}

func init() {
	// Flag to bypass HTTPS check, should be false except in case of testing
	rootCmd.PersistentFlags().Bool("insecure", false, "bypass HTTPS check")

	// Load env variables (API_URL and API_TOKEN)
	var envApiToken = os.Getenv("API_TOKEN")
	var envApiURL = os.Getenv("API_URL")

	// Create token and url flags
	rootCmd.PersistentFlags().String("token", envApiToken, "token to API")
	rootCmd.PersistentFlags().String("url", envApiURL, "url to API")

	// If token is not set as an env variable it should be specified as an argument
	if envApiToken == "" {
		rootCmd.MarkPersistentFlagRequired("token")
	}

	// If url is not set as an env variable it should be specified as an argument
	if envApiURL == "" {
		rootCmd.MarkPersistentFlagRequired("url")
	}
}
