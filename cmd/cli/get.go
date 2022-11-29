package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// # GetCmd
//
// GetCmd is a CLI sub command to get an analysis giving its UUID.
// It prints out analysis' result.
//
// Usage:
//
//	go-gdetect get <file_uuid> [flags]
//
// Flags:
//
//	-h, --help            help for get
//	    --retrieve-urls   Retrieve expert and token view URL
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var GetCmd = &cobra.Command{
	Use:   "get <file_uuid>",
	Short: "Get result by its uuid",
	Long: `Retrieves a result given its UUID. It prints out analysis results 
and eventually URL to access Token view and Expert analysis view.`,
	Args: cobra.ExactArgs(1),
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

		client, err := gdetect.NewClient(apiEndpoint, apiToken, disableSSLChecking)
		if err != nil {
			return
		}

		result, err := client.GetResultByUUID(context.Background(), args[0])
		if err != nil {
			return
		}

		bytes, err := json.Marshal(result)
		if err != nil {
			return
		}

		fmt.Fprintln(cmd.OutOrStdout(), string(bytes))

		retrieveURL, err := cmd.Flags().GetBool("retrieve-urls")
		if err != nil {
			return
		}
		if retrieveURL {
			expertURL, errExpertViewURL := client.ExtractExpertViewURL(&result)
			if errExpertViewURL != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error extracting expert view url: %s\n", errExpertViewURL)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Expert view url: %s\n", expertURL)
			}

			tokenViewURL, errTokenViewURL := client.ExtractTokenViewURL(&result)
			if errTokenViewURL != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error extracting token view url: %s\n", errTokenViewURL)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Token view url: %s\n", tokenViewURL)
			}
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(GetCmd)
	GetCmd.Flags().Bool("retrieve-urls", false, "Retrieve expert and token view URL")
}
