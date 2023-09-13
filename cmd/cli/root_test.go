package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
			wantOut: `1234`,
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
					"--no-cache",
				},
			},
			wantOut: `1234`,
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
			wantOut: `1234`,
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
				args:    "1234",
				flags: []string{
					"--token", token,
				},
			},
			wantOut: `{"uuid":"1234","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"file_count":0,"duration":0}`,
			wantErr: false,
		},
		{
			name: "INVALID GET URLS NO SID",
			fields: fields{
				command: "get",
				args:    "1234_token",
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
				args:    "1234",
				flags: []string{
					"--token", token,
				},
			},
			wantOut: `{"uuid":"1234","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"file_count":0,"duration":0}`,
			wantErr: false,
		},
		{
			name: "VALID SEARCH URLS",
			fields: fields{
				command: "search",
				args:    "1234_token_sid",
				flags: []string{
					"--token", token,
					"--retrieve-urls",
				},
			},
			wantOut: `{"uuid":"1234_token_sid","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"sid":"1234_token_sid","file_count":0,"duration":0,"token":"1234_token_sid"}`,
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
				},
			},
			wantOut: `{"uuid":"1234","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"file_count":0,"duration":0}`,
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
					"--retrieve-urls",
					"--pull-time", "1",
				},
			},
			wantOut: `{"uuid":"1234_token_sid","sha256":"","sha1":"","md5":"","ssdeep":"","is_malware":false,"score":0,"done":true,"timestamp":0,"filetype":"","size":0,"sid":"1234_token_sid","file_count":0,"duration":0,"token":"1234_token_sid"}`,
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
			wantOut: `{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`,
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
				case "/api/lite/v2/results/1234":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`))
				case "/api/lite/v2/results/1234_never_done":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"uuid":"1234", "status": true, "done": false}`))
				case "/api/lite/v2/submit":
					rw.WriteHeader(http.StatusOK)
					switch strings.TrimSpace(req.FormValue("description")) {
					case "valid test":
						rw.Write([]byte(`{"uuid":"1234", "status": true}`))
					case "never done":
						rw.Write([]byte(`{"uuid":"1234_never_done", "status": true}`))
					case "with token and sid":
						rw.Write([]byte(`{"uuid":"1234_token_sid", "status": true}`))
					default:
						rw.Write([]byte(`{"uuid":"1234", "status": true}`))
					}
				case "/api/lite/v2/results/1234_token":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"uuid":"1234_token_sid", "status": true, "done": true, "token":"1234_token_sid"}`))
				case "/api/lite/v2/results/1234_token_sid":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"uuid":"1234_token_sid", "status": true, "done": true, "sid":"1234_token_sid", "token":"1234_token_sid"}`))
				case "/api/lite/v2/search/1234_token_sid":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"uuid":"1234_token_sid", "status": true, "done": true, "sid":"1234_token_sid", "token":"1234_token_sid"}`))
				case "/api/lite/v2/search/1234":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`))
				case "/api/lite/v2/status":
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`))
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
