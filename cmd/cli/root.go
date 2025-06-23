// Package go-gdetect implements multiple commands to interact with GLIMPS
// Malware detect API. To manipulate directly detect's API, use package
// [pkg/gdetect/gdetect].
//
// Usage:
// go-gdetect [command]
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
//	-h, --help           help for go-gdetect
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "go-gdetect",
	Short: "go-gdetect - interact with GLIMPS malware detect API",
}

func Execute() (err error) {
	// Check if cmd is well recognized
	cmd, _, errCmdNotFound := rootCmd.Find(os.Args[1:])
	if errCmdNotFound != nil || cmd == nil {
		// Not found: we launch default command (submit)
		args := append([]string{"go-gdetect", "submit"}, os.Args[1:]...)
		os.Args = args
	}

	err = rootCmd.Execute()
	return
}

func init() {
	// Flag to bypass HTTPS check, should be false except in case of testing
	rootCmd.PersistentFlags().Bool("insecure", false, "bypass HTTPS check")

	// Flag to use syndetect instead of detect API
	rootCmd.PersistentFlags().Bool("syndetect", false, "use syndetect API (warning: it's subset of detect capabilities)")

	// Load env variables (API_URL and API_TOKEN)
	envAPIToken := os.Getenv("API_TOKEN")
	envAPIURL := os.Getenv("API_URL")

	// Create token and url flags
	rootCmd.PersistentFlags().String("token", envAPIToken, "token to API")
	rootCmd.PersistentFlags().String("url", envAPIURL, "url to API")

	// If token is not set as an env variable it should be specified as an argument
	if envAPIToken == "" {
		if e := rootCmd.MarkPersistentFlagRequired("token"); e != nil {
			rootCmd.PrintErr(e)
		}
	}

	// If url is not set as an env variable it should be specified as an argument
	if envAPIURL == "" {
		if e := rootCmd.MarkPersistentFlagRequired("url"); e != nil {
			rootCmd.PrintErr(e)
		}
	}
}
