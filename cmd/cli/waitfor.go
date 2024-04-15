package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// WaitForCmd is a CLI sub command to submit a file for analysis to Detect API.
// It print out analysis' result.
//
// Usage:
//
//	go-gdetect waitfor <filepath> [flags]
//
// Flags:
//
//	-d, --description string   Description for the file
//	-h, --help                 help for waitfor
//	    --no-cache             Submit file even if a result already exists
//	    --pull-time int        Set time to wait between each request trying get result, in seconds (default 2)
//	    --retrieve-urls        Retrieve expert and token view URL
//	-t, --tag strings          Tags to assign to the file
//	    --timeout int          Set a timeout in seconds (default 180)
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var WaitForCmd = &cobra.Command{
	Use:   "waitfor <filepath>",
	Short: "Submit a file to detect api and wait for results",
	Long: `submit a file to detect API giving its path, and perform regular 
check to API to retrieve result giving analysis UUID retrieved 
from submit. Will print out results to terminal, and eventually 
URL to token view and expert analysis view.`,
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

		tags, err := cmd.Flags().GetStringSlice("tag")
		if err != nil {
			return
		}

		description, err := cmd.Flags().GetString("description")
		if err != nil {
			return
		}

		bypassCache, err := cmd.Flags().GetBool("no-cache")
		if err != nil {
			return
		}

		timeout, err := cmd.Flags().GetInt("timeout")
		if err != nil {
			return
		}

		pullTime, err := cmd.Flags().GetInt("pull-time")
		if err != nil {
			return
		}

		client, err := gdetect.NewClient(apiEndpoint, apiToken, disableSSLChecking, nil)
		if err != nil {
			return
		}

		password, err := cmd.Flags().GetString("password")
		if err != nil {
			return
		}

		waitForOptions := gdetect.WaitForOptions{
			Tags:            tags,
			Description:     description,
			Timeout:         time.Duration(timeout) * time.Second,
			BypassCache:     bypassCache,
			PullTime:        time.Duration(pullTime) * time.Second,
			ArchivePassword: password,
		}

		result, err := client.WaitForFile(context.Background(), args[0], waitForOptions)
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
			expertURL, errExpertURL := client.ExtractExpertViewURL(&result)
			if errExpertURL != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error extracting expert view url: %v\n", errExpertURL)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Expert view url: %s\n", expertURL)
			}

			tokenViewURL, errTokenViewURL := client.ExtractTokenViewURL(&result)
			if errTokenViewURL != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error extracting token view url: %v\n", errTokenViewURL)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Token view url: %s\n", tokenViewURL)
			}
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(WaitForCmd)

	// Optional flags
	WaitForCmd.Flags().Bool("no-cache", false, "Submit file even if a result already exists")
	WaitForCmd.Flags().StringSliceP("tag", "t", nil, "Tags to assign to the file")
	WaitForCmd.Flags().StringP("description", "d", "", "Description for the file")
	WaitForCmd.Flags().Int("timeout", 180, "Set a timeout in seconds")
	WaitForCmd.Flags().Bool("retrieve-urls", false, "Retrieve expert and token view URL")
	WaitForCmd.Flags().Int("pull-time", 2, "Set time to wait between each request trying get result, in seconds")
	WaitForCmd.Flags().StringP("password", "p", "", "Password used to extract archive")
}
