package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/spf13/cobra"
)

// ExportCmd is a CLI sub command to export an analysis result by UUID.
// It exports the result in the specified format and saves it to a file.
//
// Usage:
//
//	go-gdetect export <file_uuid> [flags]
//
// Flags:
//
//	-h, --help              help for export
//	    --format string     Export format: misp, stix, json, pdf, markdown, csv (required)
//	    --layout string     Report language layout: fr or en (required)
//	    --full              Export full analysis instead of summarized
//	    --output string     Output file path (if not specified, prints to stdout)
//
// Global Flags:
//
//	--insecure       bypass HTTPS check
//	--token string   token to API
//	--url string     url to API
var ExportCmd = &cobra.Command{
	Use:   "export <file_uuid>",
	Short: "Export result by its uuid",
	Long: `Exports a result given its UUID in the specified format.
Supported formats: misp, stix, json, pdf, markdown, csv.
The export can be full analysis or summarized.`,
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

		syndetect, err := cmd.Flags().GetBool("syndetect")
		if err != nil {
			return
		}
		if syndetect {
			client.SetSyndetect()
		}

		format, err := cmd.Flags().GetString("format")
		if err != nil {
			return
		}
		if format == "" {
			return fmt.Errorf("format is required")
		}

		layout, err := cmd.Flags().GetString("layout")
		if err != nil {
			return
		}
		if layout == "" {
			return fmt.Errorf("layout is required")
		}

		full, err := cmd.Flags().GetBool("full")
		if err != nil {
			return
		}

		exportOptions := gdetect.ExportOptions{
			Format: gdetect.ExportFormat(format),
			Layout: gdetect.ExportLayout(layout),
			Full:   full,
		}

		data, err := client.ExportResult(context.Background(), args[0], exportOptions)
		if err != nil {
			return
		}

		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return
		}

		if output != "" {
			// Write to file
			err = os.WriteFile(output, data, 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Export saved to: %s\n", output)
		} else {
			// Write to stdout
			_, err = cmd.OutOrStdout().Write(data)
			if err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		}

		return
	},
}

func init() {
	rootCmd.AddCommand(ExportCmd)
	ExportCmd.Flags().String("format", "", "Export format: misp, stix, json, pdf, markdown, csv (required)")
	ExportCmd.Flags().String("layout", "", "Report language layout: fr or en (required)")
	ExportCmd.Flags().Bool("full", false, "Export full analysis instead of summarized")
	ExportCmd.Flags().String("output", "", "Output file path (if not specified, prints to stdout)")
	ExportCmd.MarkFlagRequired("format")
	ExportCmd.MarkFlagRequired("layout")
}
