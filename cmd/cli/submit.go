package cli

import (
	"context"
	"fmt"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// SubmitCmd is a CLI sub command to submit a file for analysis to Detect API.
// It print out analysis' UUID.
//
// Usage:
//
//	go-gdetect submit <filepath>
//
// Flags:
//
//	-d, --description string   Description for the file
//	-h, --help                 help for submit
//	--no-cache                 Submit file even if a result already exists
//	-t, --tag strings          Tag list
//	-p, --password string      Password used to extract archive
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var SubmitCmd = &cobra.Command{
	Use:   "submit <filepath>",
	Short: "Submit a file to detect API",
	Long: `submit a file to detect API giving its path. It will also retrieve
analysis UUID and print it out.`,
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

		password, err := cmd.Flags().GetString("password")
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

		submitOptions := gdetect.SubmitOptions{
			Description:     description,
			Tags:            tags,
			BypassCache:     bypassCache,
			ArchivePassword: password,
		}

		uuid, err := client.SubmitFile(context.Background(), args[0], submitOptions)
		if err != nil {
			return
		}
		if _, err = fmt.Fprintln(cmd.OutOrStdout(), uuid); err != nil {
			return
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(SubmitCmd)

	// Optional flags
	SubmitCmd.Flags().Bool("no-cache", false, "Submit file even if a result already exists")
	SubmitCmd.Flags().StringSliceP("tag", "t", nil, "Tag list")
	SubmitCmd.Flags().StringP("description", "d", "", "Description for the file")
	SubmitCmd.Flags().StringP("password", "p", "", "Password used to extract archive")
}
