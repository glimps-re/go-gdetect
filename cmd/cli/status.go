package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// StatusCmd is a CLI sub command to get profile status.
// It print out profile status.
//
// Usage:
//
//	go-gdetect status [flags]
//
// Flags:
//
//	-h, --help            help for status
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get profile status",
	Long:  `Get profile status.`,
	Args:  cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		apiToken, err := cmd.Flags().GetString("token")
		if err != nil {
			return
		}

		apiEndpoint, err := cmd.Flags().GetString("url")
		if err != nil {
			return
		}

		disableSSLChecking, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return
		}

		client, err := gdetect.NewClient(apiEndpoint, apiToken, disableSSLChecking, nil)
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

		result, err := client.GetProfileStatus(context.Background())
		if err != nil {
			return
		}

		bytes, err := json.Marshal(result)
		if err != nil {
			return
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(bytes))
		if err != nil {
			return
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(StatusCmd)
}
