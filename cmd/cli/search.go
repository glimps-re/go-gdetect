package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// # SearchCmd
//
// SearchCmd is a CLI sub command to search for an analysis giving a file's SHA256.
// It print out analysis' result.
//
// Usage:
//
//	go-gdetect search <sha256> [flags]
//
// Flags:
//
//	-h, --help            help for search
//	    --retrieve-urls   Retrieve expert and token view URL
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var SearchCmd = &cobra.Command{
	Use:   "search <sha256>",
	Short: "Search a previous analysis by SHA256",
	Long: `search retrieves a result given a SHA256. It prints out analysis 
results and eventually URL to access Token view and Expert 
analysis view.`,
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

		client, err := gdetect.NewClient(apiEndpoint, apiToken, disableSSLChecking, nil)
		if err != nil {
			return
		}

		result, err := client.GetResultBySHA256(context.Background(), args[0])
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
		return nil
	},
}

func init() {
	rootCmd.AddCommand(SearchCmd)
	SearchCmd.Flags().Bool("retrieve-urls", false, "Retrieve expert and token view URL")
}
