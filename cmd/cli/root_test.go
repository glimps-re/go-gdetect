package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Test UUID and SHA256 constants in standard UUID format (8-4-4-4-12).
const (
	rootUUIDValid     = "ab000001-0000-0000-0000-000000000001"
	rootUUIDNeverDone = "ab000001-0000-0000-0000-000000000008"
	rootUUIDTokenSID  = "ab000001-0000-0000-0000-000000000002"
	rootUUIDToken     = "ab000001-0000-0000-0000-000000000003"
	// SHA256 strings (64 hex chars) for search command tests.
	rootSHA256Valid    = "ab00000100000000000000000000000000000000000000000000000000000001"
	rootSHA256TokenSID = "ab00000100000000000000000000000000000000000000000000000000000002"
)

func TestExecute(t *testing.T) {
	token := "abcdef01-23456789-abcdef01-23456789-abcdef01"

	type fields struct {
		command string
		args    string
		flags   []string
	}

	tests := []struct {
		name    string
		fields  fields
		wantOut string
		wantErr bool
	}{
		{
			name: "INVALID COMMAND",
			fields: fields{
				command: "invalid",
				args:    "command",
				flags: []string{
					"--token", token,
				},
			},
			wantErr: true,
		},
		{
			name: "VALID SUBMIT",
			fields: fields{
				command: "submit",
				args:    "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
				},
			},
			wantOut: rootUUIDValid,
			wantErr: false,
		},
		{
			name: "VALID SUBMIT WITH PARAMS",
			fields: fields{
				command: "submit",
				args:    "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
					"--description", "this is a description",
					"--tag", "tag1",
					"-t", "tag2",
					"-p", "password1",
					"--no-cache",
				},
			},
			wantOut: rootUUIDValid,
			wantErr: false,
		},
		{
			name: "VALID SUBMIT DEFAULT COMMAND",
			fields: fields{
				args: "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
				},
			},
			wantOut: rootUUIDValid,
			wantErr: false,
		},
		{
			name: "INVALID SUBMIT",
			fields: fields{
				args: "/not/existing/file",
				flags: []string{
					"--token", token,
				},
			},
			wantErr: true,
		},
		{
			name: "VALID GET",
			fields: fields{
				command: "get",
				args:    rootUUIDValid,
				flags: []string{
					"--token", token,
				},
			},
			wantOut: `{"uuid":"` + rootUUIDValid + `","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"file_count":0,"duration":0,"special_status_code":0}`,
			wantErr: false,
		},
		{
			name: "INVALID GET URLS NO SID",
			fields: fields{
				command: "get",
				args:    rootUUIDToken,
				flags: []string{
					"--token", token,
					"--retrieve-urls",
				},
			},
			wantErr: true,
		},
		{
			name: "VALID SEARCH",
			fields: fields{
				command: "search",
				args:    rootSHA256Valid,
				flags: []string{
					"--token", token,
				},
			},
			wantOut: `{"uuid":"` + rootUUIDValid + `","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"file_count":0,"duration":0,"special_status_code":0}`,
			wantErr: false,
		},
		{
			name: "VALID SEARCH URLS",
			fields: fields{
				command: "search",
				args:    rootSHA256TokenSID,
				flags: []string{
					"--token", token,
					"--retrieve-urls",
				},
			},
			wantOut: `{"uuid":"` + rootUUIDTokenSID + `","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"sid":"` + rootUUIDTokenSID + `","file_count":0,"duration":0,"token":"` + rootUUIDTokenSID + `","special_status_code":0}`,
			wantErr: false,
		},
		{
			name: "VALID WAITFOR",
			fields: fields{
				command: "waitfor",
				args:    "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
					"--pull-time", "1",
					"--no-cache",
				},
			},
			wantOut: `{"uuid":"` + rootUUIDValid + `","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"file_count":0,"duration":0,"special_status_code":0}`,
			wantErr: false,
		},
		{
			name: "VALID WAITFOR WITH PARAMS",
			fields: fields{
				command: "waitfor",
				args:    "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
					"--description", "with token and sid",
					"--tag", "tag1",
					"-t", "tag2",
					"--no-cache",
					"-p", "password1",
					"--retrieve-urls",
					"--pull-time", "1",
					"--no-cache",
				},
			},
			wantOut: `{"uuid":"` + rootUUIDTokenSID + `","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"sid":"` + rootUUIDTokenSID + `","file_count":0,"duration":0,"token":"` + rootUUIDTokenSID + `","special_status_code":0}`,
			wantErr: false,
		},
		{
			name: "INVALID WAITFOR BAD FLAGS",
			fields: fields{
				command: "waitfor",
				args:    "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
					"--description",
					"--pull-time", "1",
				},
			},
			wantErr: true,
		},
		{
			name: "INVALID WAITFOR TIMEOUT",
			fields: fields{
				command: "waitfor",
				args:    "../../tests/samples/false_mirai",
				flags: []string{
					"--token", token,
					"--description", "never done",
					"--timeout", "2",
					"--pull-time", "1",
				},
			},
			wantErr: true,
		},
		{
			name: "VALID STATUS",
			fields: fields{
				command: "status",
				flags: []string{
					"--token", token,
				},
			},
			wantOut: `{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202,"malware_threshold":1000}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		s := httptest.NewServer(
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				if req.Header.Get("X-Auth-Token") != token {
					t.Errorf("handler.GetResultByUUID() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
				}
				switch strings.TrimSpace(req.URL.Path) {
				case "/api/lite/v2/results/" + rootUUIDValid:
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDValid + `", "status": true, "done": true}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				case "/api/lite/v2/results/" + rootUUIDNeverDone:
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDValid + `", "status": true, "done": false}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				case "/api/lite/v2/submit":
					rw.WriteHeader(http.StatusOK)
					req.Body = http.MaxBytesReader(rw, req.Body, 10*1024*1024)
					switch strings.TrimSpace(req.FormValue("description")) {
					case "valid test":
						_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDValid + `", "status": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "never done":
						_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDNeverDone + `", "status": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "with token and sid":
						_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDTokenSID + `", "status": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					default:
						_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDValid + `", "status": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					}
				case "/api/lite/v2/results/" + rootUUIDToken:
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDTokenSID + `", "status": true, "done": true, "token":"` + rootUUIDTokenSID + `"}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				case "/api/lite/v2/results/" + rootUUIDTokenSID:
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDTokenSID + `", "status": true, "done": true, "sid":"` + rootUUIDTokenSID + `", "token":"` + rootUUIDTokenSID + `"}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				case "/api/lite/v2/search/" + rootSHA256TokenSID:
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDTokenSID + `", "status": true, "done": true, "sid":"` + rootUUIDTokenSID + `", "token":"` + rootUUIDTokenSID + `"}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				case "/api/lite/v2/search/" + rootSHA256Valid:
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"uuid":"` + rootUUIDValid + `", "status": true, "done": true}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				case "/api/lite/v2/status":
					rw.WriteHeader(http.StatusOK)
					_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202,"malware_threshold":1000}`))
					if err != nil {
						t.Fatalf("cannot write test response: %s", err)
					}
				default:
					t.Errorf("handler.GetResultByUUID() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
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

			args := []string{"go-gdetect"}
			if tt.fields.command != "" {
				args = append(args, tt.fields.command)
			}
			if tt.fields.args != "" {
				args = append(args, tt.fields.args)
			}
			args = append(args, tt.fields.flags...)

			args = append(args, []string{"--url", s.URL}...)

			os.Args = args
			err := Execute()

			if (bufErr.String() != "") != tt.wantErr && (err != nil) == tt.wantErr {
				t.Errorf("%s command failed, StdErr = %v, wantErr %v", tt.fields.command, bufErr.String(), tt.wantErr)
			}

			if !strings.Contains(bufOut.String(), tt.wantOut) {
				t.Errorf("%s command failed, result = %v, want %v, stderr: %v", tt.fields.command, bufOut.String(), tt.wantOut, bufErr.String())
			}
		})
	}
}
