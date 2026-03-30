package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Test UUID constants in valid API format (5 groups of 8 hex chars).
const (
	exportUUIDPDF        = "ab000001-0000-0000-0000-00000000000a"
	exportUUIDJSON       = "ab000001-0000-0000-0000-00000000000b"
	exportUUIDMISP       = "ab000001-0000-0000-0000-00000000000c"
	exportUUIDSTIX       = "ab000001-0000-0000-0000-00000000000d"
	exportUUIDMarkdown   = "ab000001-0000-0000-0000-00000000000e"
	exportUUIDCSV        = "ab000001-0000-0000-0000-00000000000f"
	exportUUIDNotFound   = "ab000001-0000-0000-0000-000000000004"
	exportUUIDForbidden  = "ab000001-0000-0000-0000-000000000007"
	exportUUIDBadRequest = "ab000001-0000-0000-0000-000000000010"
	exportUUIDGeneric    = "ab000001-0000-0000-0000-000000000001"
)

func TestExportCmd(t *testing.T) {
	token := "abcdef01-23456789-abcdef01-23456789-abcdef01"

	type fields struct {
		args  string
		flags []string
	}

	tests := []struct {
		name    string
		fields  fields
		wantOut string
		wantErr bool
	}{
		{
			name: "VALID PDF EXPORT",
			fields: fields{
				args: exportUUIDPDF,
				flags: []string{
					"--token", token,
					"--format", "pdf",
					"--layout", "en",
				},
			},
			wantOut: "%PDF-1.3",
			wantErr: false,
		},
		{
			name: "VALID JSON EXPORT FULL",
			fields: fields{
				args: exportUUIDJSON,
				flags: []string{
					"--token", token,
					"--format", "json",
					"--layout", "fr",
					"--full",
				},
			},
			wantOut: `"verdict"`,
			wantErr: false,
		},
		{
			name: "VALID MISP EXPORT",
			fields: fields{
				args: exportUUIDMISP,
				flags: []string{
					"--token", token,
					"--format", "misp",
					"--layout", "en",
				},
			},
			wantOut: `{"Event"`,
			wantErr: false,
		},
		{
			name: "VALID STIX EXPORT",
			fields: fields{
				args: exportUUIDSTIX,
				flags: []string{
					"--token", token,
					"--format", "stix",
					"--layout", "en",
				},
			},
			wantOut: `{"type":"bundle"}`,
			wantErr: false,
		},
		{
			name: "VALID MARKDOWN EXPORT",
			fields: fields{
				args: exportUUIDMarkdown,
				flags: []string{
					"--token", token,
					"--format", "markdown",
					"--layout", "en",
				},
			},
			wantOut: "# GMalware",
			wantErr: false,
		},
		{
			name: "VALID CSV EXPORT",
			fields: fields{
				args: exportUUIDCSV,
				flags: []string{
					"--token", token,
					"--format", "csv",
					"--layout", "en",
				},
			},
			wantOut: "name,sha256",
			wantErr: false,
		},
		{
			name: "MISSING FORMAT FLAG",
			fields: fields{
				args: exportUUIDGeneric,
				flags: []string{
					"--token", token,
					"--layout", "en",
				},
			},
			wantErr: true,
		},
		{
			name: "MISSING LAYOUT FLAG",
			fields: fields{
				args: exportUUIDGeneric,
				flags: []string{
					"--token", token,
					"--format", "json",
				},
			},
			wantErr: true,
		},
		{
			name: "NOT FOUND",
			fields: fields{
				args: exportUUIDNotFound,
				flags: []string{
					"--token", token,
					"--format", "json",
					"--layout", "en",
				},
			},
			wantErr: true,
		},
		{
			name: "FORBIDDEN",
			fields: fields{
				args: exportUUIDForbidden,
				flags: []string{
					"--token", token,
					"--format", "json",
					"--layout", "en",
				},
			},
			wantErr: true,
		},
		{
			name: "BAD REQUEST",
			fields: fields{
				args: exportUUIDBadRequest,
				flags: []string{
					"--token", token,
					"--format", "json",
					"--layout", "en",
				},
			},
			wantErr: true,
		},
		{
			name: "MISSING UUID ARGUMENT",
			fields: fields{
				flags: []string{
					"--token", token,
					"--format", "json",
					"--layout", "en",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s := httptest.NewServer(
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				if req.Header.Get("X-Auth-Token") != token {
					t.Errorf("handler.ExportResult() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
				}

				// Parse query parameters
				query := req.URL.Query()
				format := query.Get("format")
				layout := query.Get("layout")

				switch {
				case strings.Contains(req.URL.Path, exportUUIDPDF):
					if format != "pdf" || layout != "en" {
						t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
					}
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte("%PDF-1.3\n"))
				case strings.Contains(req.URL.Path, exportUUIDJSON):
					if format != "json" || layout != "fr" {
						t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
					}
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte(`{"verdict":"malicious","score":2800}`))
				case strings.Contains(req.URL.Path, exportUUIDMISP):
					if format != "misp" || layout != "en" {
						t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
					}
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte(`{"Event":{"uuid":"test"}}`))
				case strings.Contains(req.URL.Path, exportUUIDSTIX):
					if format != "stix" {
						t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
					}
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte(`{"type":"bundle"}`))
				case strings.Contains(req.URL.Path, exportUUIDMarkdown):
					if format != "markdown" {
						t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
					}
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte("# GMalware submission report\n"))
				case strings.Contains(req.URL.Path, exportUUIDCSV):
					if format != "csv" {
						t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
					}
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte("name,sha256,size\n"))
				case strings.Contains(req.URL.Path, exportUUIDNotFound):
					rw.WriteHeader(http.StatusNotFound)
					_, _ = rw.Write([]byte(`{"status":false,"error":"not found"}`))
				case strings.Contains(req.URL.Path, exportUUIDForbidden):
					rw.WriteHeader(http.StatusForbidden)
					_, _ = rw.Write([]byte(`{"status":false,"error":"forbidden"}`))
				case strings.Contains(req.URL.Path, exportUUIDBadRequest):
					rw.WriteHeader(http.StatusBadRequest)
					_, _ = rw.Write([]byte(`{"status":false,"error":"bad request"}`))
				default:
					// Don't error for requests we don't handle - they might be validation errors
					rw.WriteHeader(http.StatusBadRequest)
					_, _ = rw.Write([]byte(`{"status":false,"error":"unexpected request"}`))
				}
			}),
		)
		defer s.Close()

		t.Run(tt.name, func(t *testing.T) {
			cmd := rootCmd

			bufOut := bytes.NewBufferString("")
			bufErr := bytes.NewBufferString("")
			cmd.SetOut(bufOut)
			cmd.SetErr(bufErr)

			args := []string{"go-gdetect", "export"}
			if tt.fields.args != "" {
				args = append(args, tt.fields.args)
			}
			args = append(args, tt.fields.flags...)
			args = append(args, []string{"--url", s.URL}...)

			os.Args = args
			err := Execute()

			// Check if there's an error in stderr or error return
			hasError := err != nil || bufErr.String() != ""
			if hasError != tt.wantErr {
				t.Errorf("Export command error = %v, stderr = %v, wantErr %v", err, bufErr.String(), tt.wantErr)
			}

			if !tt.wantErr && !strings.Contains(bufOut.String(), tt.wantOut) {
				t.Errorf("Export command output = %v, want to contain %v", bufOut.String(), tt.wantOut)
			}
		})
	}
}

func TestExportCmdWithOutputFile(t *testing.T) {
	token := "abcdef01-23456789-abcdef01-23456789-abcdef01"

	// Create a temporary file for output
	tmpDir := t.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "export_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	s := httptest.NewServer(
		http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.Header.Get("X-Auth-Token") != token {
				t.Errorf("unexpected TOKEN: %v", req.Header.Get("X-Auth-Token"))
			}
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(`{"verdict":"malicious","score":2800}`))
		}),
	)
	defer s.Close()

	cmd := rootCmd

	bufOut := bytes.NewBufferString("")
	bufErr := bytes.NewBufferString("")
	cmd.SetOut(bufOut)
	cmd.SetErr(bufErr)

	args := []string{
		"go-gdetect", "export", exportUUIDJSON,
		"--token", token,
		"--format", "json",
		"--layout", "en",
		"--output", tmpFile.Name(),
		"--url", s.URL,
	}

	os.Args = args
	err = Execute()
	if err != nil {
		t.Errorf("Export command with output file error = %v, stderr: %v", err, bufErr.String())
	}

	// Check if the file was written
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	expectedContent := `{"verdict":"malicious","score":2800}`
	if string(content) != expectedContent {
		t.Errorf("Output file content = %v, want %v", string(content), expectedContent)
	}

	// Check stdout message
	if !strings.Contains(bufOut.String(), "Export saved to:") {
		t.Errorf("Expected success message in output, got: %v", bufOut.String())
	}
}
