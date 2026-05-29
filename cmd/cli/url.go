package cli

import (
	"context"
	"fmt"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// ScanURLCmd is a CLI sub command to scan a URL with the Detect API.
// It prints out the resulting verdict.
//
// Usage:
//
//	go-gdetect url <url>
//
// Flags:
//
//	-h, --help   help for url
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var ScanURLCmd = &cobra.Command{
	Use:   "url <url>",
	Short: "Scan a URL with detect API",
	Long:  `scan a URL with detect API and print out the resulting verdict.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		apiToken, err := cmd.Flags().GetString("token")
		if err != nil {
			return
		}

		apiEndpoint, err := cmd.Flags().GetString("url")
		if err != nil {
			return
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return
		}

		client, err := gdetect.NewClientFromConfig(gdetect.ClientConfig{
			Endpoint: apiEndpoint,
			Token:    apiToken,
			Insecure: insecure,
		})
		if err != nil {
			return
		}

		syndetect, err := cmd.Flags().GetBool("syndetect")
		if err != nil {
			return
		}
		if syndetect {
			client.SetSyndetect()
		}

		result, err := client.ScanURL(context.Background(), args[0])
		if err != nil {
			return
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), result.Verdict)
		if err != nil {
			return
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(ScanURLCmd)
}
