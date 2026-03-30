package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

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
//	    --wait int        Server-side wait: hold the connection for up to N seconds until analysis is complete (0–59)
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

		waitSeconds, err := cmd.Flags().GetInt("wait")
		if err != nil {
			return
		}

		var result gdetect.Result
		result, err = client.GetResultByUUIDWithWait(context.Background(), args[0], waitSeconds)
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

		retrieveURL, err := cmd.Flags().GetBool("retrieve-urls")
		if err != nil {
			return
		}
		if retrieveURL {
			expertURL, errExpertViewURL := client.ExtractExpertViewURL(&result)
			if errExpertViewURL != nil {
				_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Error extracting expert view url: %s\n", errExpertViewURL)
				if err != nil {
					return
				}
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Expert view url: %s\n", expertURL)
				if err != nil {
					return
				}
			}

			tokenViewURL, errTokenViewURL := client.ExtractTokenViewURL(&result)
			if errTokenViewURL != nil {
				_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Error extracting token view url: %s\n", errTokenViewURL)
				if err != nil {
					return
				}
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Token view url: %s\n", tokenViewURL)
				if err != nil {
					return
				}
			}
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(GetCmd)
	GetCmd.Flags().Bool("retrieve-urls", false, "Retrieve expert and token view URL")
	GetCmd.Flags().Int("wait", 0, "Server-side wait: instruct the server to hold the connection for up to N seconds until the analysis is complete (0–59)")
}
