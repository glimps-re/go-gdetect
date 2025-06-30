package gdetect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func createTestFile(t *testing.T) (f *os.File) {
	f, err := os.CreateTemp(t.TempDir(), "file")
	if err != nil {
		t.Fatalf("could not create temp file for test, error: %v", err)
	}
	defer func() {
		if err = f.Close(); err != nil {
			t.Fatalf("could not write to temp file for test, error: %v", err)
		}
	}()
	if _, err = f.WriteString("content"); err != nil {
		t.Fatalf("could not write to temp file for test, error: %v", err)
	}
	return
}

func compareClients(c1 *Client, c2 *Client) (equal bool) {
	equal = c1.Endpoint == c2.Endpoint && c1.Token == c2.Token
	return
}

var token = "abcdef01-23456789-abcdef01-23456789-abcdef01"

func TestNewClient(t *testing.T) {
	type args struct {
		endpoint   string
		token      string
		insecure   bool
		httpClient *http.Client
	}
	tests := []struct {
		name       string
		args       args
		wantClient *Client
		wantErr    bool
	}{
		{
			name: "valid",
			args: args{
				endpoint:   "http://glimps/detect",
				token:      token,
				insecure:   false,
				httpClient: nil,
			},
			wantErr: false,
			wantClient: &Client{
				Endpoint: "http://glimps/detect",
				Token:    token,
			},
		},
		{
			name: "empty token",
			args: args{
				endpoint:   "http://glimps/detect",
				token:      "",
				insecure:   false,
				httpClient: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid char in token",
			args: args{
				endpoint:   "http://glimps/detect",
				token:      "tbcdef01-23456789-abcdef01-23456789-abcdef01",
				insecure:   false,
				httpClient: nil,
			},
			wantErr: true,
		},
		{
			name: "too little token",
			args: args{
				endpoint:   "http://glimps/detect",
				token:      "abcdef01",
				insecure:   false,
				httpClient: nil,
			},
			wantErr: true,
		},
		{
			name: "valid default http client",
			args: args{
				endpoint:   "http://glimps/detect",
				token:      token,
				insecure:   false,
				httpClient: http.DefaultClient,
			},
			wantErr: false,
			wantClient: &Client{
				Endpoint:   "http://glimps/detect",
				Token:      token,
				HttpClient: http.DefaultClient,
			},
		},
		{
			name: "valid custom http client",
			args: args{
				endpoint:   "http://glimps/detect",
				token:      token,
				insecure:   false,
				httpClient: &http.Client{Timeout: 2 * time.Second},
			},
			wantErr: false,
			wantClient: &Client{
				Endpoint:   "http://glimps/detect",
				Token:      token,
				HttpClient: &http.Client{Timeout: 2 * time.Second},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClient, err := NewClient(tt.args.endpoint, tt.args.token, tt.args.insecure, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantClient != nil {
				if !compareClients(gotClient, tt.wantClient) {
					t.Errorf("NewClient() = %v, want %v", gotClient, tt.wantClient)
				}
			}
		})
	}
}

func TestClient_SubmitFile(t *testing.T) {
	type args struct {
		tags             []string
		description      string
		bypassCache      bool
		archive_password string
		filename         string
	}
	type fields struct {
		notExistingFile           bool
		respBadJSON               bool
		respBadRequest            bool
		respSubmissionStatusFalse bool
		respTimeout               bool
	}
	tests := []struct {
		name     string
		args     args
		fields   fields
		timeout  time.Duration
		wantUUID string
		wantErr  bool
	}{
		{
			name: "ok",
			args: args{
				description: "valid test",
			},
			wantErr:  false,
			wantUUID: "1234",
		},
		{
			name: "ok filename",
			args: args{
				description: "valid test",
				filename:    "test.exe",
			},
			wantErr:  false,
			wantUUID: "1234",
		},
		{
			name: "error invalid file",
			fields: fields{
				notExistingFile: true,
			},
			wantErr: true,
		},
		{
			name: "error bad request",
			fields: fields{
				respBadRequest: true,
			},
			wantErr: true,
		},
		{
			name: "ok params",
			args: args{
				filename:         "mirai",
				description:      "file params",
				tags:             []string{"tag1", "tag2"},
				bypassCache:      true,
				archive_password: "test",
			},
			wantErr:  false,
			wantUUID: "1234",
		},
		{
			name: "error submission status",
			fields: fields{
				respSubmissionStatusFalse: true,
			},
			wantErr: true,
		},
		{
			name: "error bad json",
			fields: fields{
				respBadJSON: true,
			},
			wantErr: true,
		},
		{
			name: "error timeout",
			fields: fields{
				respTimeout: true,
			},
			wantErr: true,
			timeout: time.Millisecond * 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := "/bad/testfile"
			if !tt.fields.notExistingFile {
				f, err := os.CreateTemp(t.TempDir(), "file")
				if err != nil {
					t.Fatalf("could not create test file, err: %v", err)
				}
				if _, err := f.WriteString("file content"); err != nil {
					t.Fatalf("could not write content to test file, err: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("could not close test file, err: %v", err)
				}
				filename = f.Name()
			}

			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.SubmitFile() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					if req.Method != http.MethodPost {
						t.Errorf("handler.SubmitFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}
					if strings.TrimSpace(req.URL.Path) != "/api/lite/v2/submit" {
						t.Errorf("handler.SubmitFile() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}

					switch {
					case tt.fields.respBadJSON:
						if _, e := rw.Write([]byte(`{"uuid":"1234", "status": false`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.fields.respBadRequest:
						rw.WriteHeader(http.StatusBadRequest)
					case tt.fields.respSubmissionStatusFalse:
						if _, e := rw.Write([]byte(`{"uuid":"1234", "status": false}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.fields.respTimeout:
						time.Sleep(time.Millisecond * 15)
						if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					default:
						if err := req.ParseMultipartForm(4096); err != nil {
							return
						}

						// check bypassCache
						bypassCache, err := strconv.ParseBool(req.FormValue("bypass-cache"))
						if err != nil {
							bypassCache = false
						}
						if bypassCache != tt.args.bypassCache {
							t.Errorf("got bypass-cache %v, want %v", bypassCache, tt.args.bypassCache)
							return
						}

						// check tags
						tags := []string{}
						rawTags := req.FormValue("tags")
						if rawTags != "" {
							tags = strings.Split(rawTags, ",")
						}
						for i, tag := range tags {
							if i >= len(tag) {
								t.Errorf("got tags %v, want %v", tags, tt.args.tags)
								return
							}
							if tt.args.tags[i] != tag {
								t.Errorf("got tags %v, want %v", tags, tt.args.tags)
								return
							}
						}

						// check extract password
						extractPassword := req.FormValue("archive_password")
						if extractPassword != tt.args.archive_password {
							t.Errorf("got archive-password %s, want %s", extractPassword, tt.args.archive_password)
							return
						}

						// check desc
						description := req.FormValue("description")
						if description != tt.args.description {
							t.Errorf("got description %s, want %s", description, tt.args.description)
							return
						}

						f, h, err := req.FormFile("file")
						if err != nil {
							t.Errorf("could not retrieve file from form, err: %v", err)
							return
						}
						defer func() {
							if e := f.Close(); e != nil {
								t.Fatalf("could not close file properly, err: %v", e)
							}
						}()

						wantFilename := filepath.Base(filename)
						if tt.args.filename != "" {
							wantFilename = tt.args.filename
						}

						if h.Filename != wantFilename {
							t.Errorf("got filename %s, want %s", h.Filename, wantFilename)
							return
						}

						if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(ctx, tt.timeout)
				defer cancel()
				ctx = tCtx
			}

			submitOptions := SubmitOptions{
				Description:     tt.args.description,
				Tags:            tt.args.tags,
				BypassCache:     tt.args.bypassCache,
				Filename:        tt.args.filename,
				ArchivePassword: tt.args.archive_password,
			}

			gotUUID, err := client.SubmitFile(ctx, filename, submitOptions)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.SubmitFile() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if gotUUID != tt.wantUUID {
				t.Errorf("Client.SubmitFile() = %v, want %v", gotUUID, tt.wantUUID)
			}
		})
	}
}

func TestClient_GetResultByUUID(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name       string
		args       args
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
		{
			name: "VALID",
			args: args{
				uuid: "1234_valid_test",
			},
			wantErr:    false,
			wantResult: Result{UUID: "1234_valid_test", Done: true},
		},
		{
			name: "TIMEOUT",
			args: args{
				uuid: "1234_timeout",
			},
			wantErr: true,
			timeout: 5 * time.Millisecond,
		},
		{
			name: "NOT FOUND",
			args: args{
				uuid: "1234_not_found",
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				uuid: "1234_server_error",
			},
			wantErr: true,
		},
		{
			name: "BAD JSON",
			args: args{
				uuid: "1234_bad_json",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.GetResultByUUID() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					if req.Method != http.MethodGet {
						t.Errorf("handler.GetResultByUUID() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}
					switch strings.TrimSpace(req.URL.Path) {
					case "/api/lite/v2/results/1234_valid_test":
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_valid_test", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_timeout":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_not_found":
						rw.WriteHeader(http.StatusNotFound)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_server_error":
						rw.WriteHeader(http.StatusInternalServerError)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_bad_json":
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true "done": true`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					default:
						t.Errorf("handler.GetResultByUUID() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}

			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}
			gotResult, err := client.GetResultByUUID(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetResultByUUID() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.GetResultByUUID() got = %+v, want = %+v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestClient_GetResultBySHA256(t *testing.T) {
	type args struct {
		sha256 string
	}

	tests := []struct {
		name       string
		args       args
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
		{
			name: "VALID",
			args: args{
				sha256: "1234_valid_test",
			},
			wantErr:    false,
			wantResult: Result{UUID: "1234_valid_test", Done: true},
		},
		{
			name: "NOT FOUND",
			args: args{
				sha256: "1234_not_found",
			},
			wantErr: true,
		},
		{
			name: "FORBIDDEN",
			args: args{
				sha256: "1234_forbidden",
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				sha256: "1234_server_error",
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			args: args{
				sha256: "1234_timeout",
			},
			wantErr: true,
			timeout: time.Millisecond * 5,
		},
		{
			name: "BAD JSON",
			args: args{
				sha256: "1234_bad_json",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.GetResultBySHA256() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					if req.Method != http.MethodGet {
						t.Errorf("handler.GetResultBySHA256() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}
					switch strings.TrimSpace(req.URL.Path) {
					case "/api/lite/v2/search/1234_valid_test":
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_valid_test", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/search/1234_timeout":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/search/1234_not_found":
						rw.WriteHeader(http.StatusNotFound)
						if _, e := rw.Write([]byte(`{"uuid":"1234_not_found", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/search/1234_server_error":
						rw.WriteHeader(http.StatusInternalServerError)
						if _, e := rw.Write([]byte(`{"uuid":"1234_server_error", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/search/1234_bad_json":
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_bad_json", "status": true, "done": true`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/search/1234_forbidden":
						rw.WriteHeader(http.StatusForbidden)
						if _, e := rw.Write([]byte(`{"uuid":"1234_forbidden", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					default:
						t.Errorf("handler.GetResultBySHA256() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}
				}),
			)
			defer s.Close()

			c, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}
			gotResult, err := c.GetResultBySHA256(ctx, tt.args.sha256)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetResultBySHA256() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.GetResultBySHA256() = %+v, want %+v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestClient_WaitForFile(t *testing.T) {
	type fields struct {
		analysisNeverDone bool
		searchNotDone     bool
		searchNotFound    bool
	}
	type args struct {
		tags        []string
		description string
		bypassCache bool
		timeout     time.Duration
		params      []int
		pullTime    time.Duration
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
		{
			name: "ok",
			args: args{
				params:      []int{1},
				timeout:     180 * time.Second,
				pullTime:    15 * time.Millisecond,
				bypassCache: true,
			},
			wantResult: Result{UUID: "1234", Done: true},
		},
		{
			name: "ok preget",
			args: args{
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234", Done: true},
		},
		{
			name: "ok preget not done",
			fields: fields{
				searchNotDone: true,
			},
			args: args{
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234", Done: true},
		},
		{
			name: "ok preget not found",
			fields: fields{
				searchNotFound: true,
			},
			args: args{
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234", Done: true},
		},
		{
			name: "error timeout",
			fields: fields{
				analysisNeverDone: true,
			},
			args: args{
				params:      []int{1},
				timeout:     time.Millisecond * 15,
				bypassCache: true,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.WaitForFile() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					switch strings.TrimSpace(req.URL.Path) {
					case "/api/lite/v2/submit":
						if req.Method != http.MethodPost {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						switch {
						case tt.fields.analysisNeverDone:
							if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": false}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						default:
							if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						}
					case "/api/lite/v2/search/ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						switch {
						case tt.fields.searchNotFound:
							rw.WriteHeader(http.StatusNotFound)
							return
						case tt.fields.searchNotDone:
							if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": false}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						default:
							if _, e := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						}
					default:
						t.Errorf("handler.WaitForFile() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}

			waitForOptions := WaitForOptions{
				Tags:        tt.args.tags,
				Description: tt.args.description,
				BypassCache: tt.args.bypassCache,
				Timeout:     tt.args.timeout,
				PullTime:    tt.args.pullTime,
			}
			f := createTestFile(t)
			gotResult, err := client.WaitForFile(ctx, f.Name(), waitForOptions)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.WaitForFile() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.WaitForFile() = %+v, want %+v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestClient_WaitForFile_Syndetect(t *testing.T) {
	type fields struct {
		analysisNeverDone bool
		searchNotDone     bool
		searchNotFound    bool
	}
	type args struct {
		tags        []string
		description string
		bypassCache bool
		timeout     time.Duration
		params      []int
		pullTime    time.Duration
	}
	tests := []struct {
		name       string
		args       args
		fields     fields
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
		// {
		// 	name: "ok",
		// 	args: args{
		// 		params:      []int{1},
		// 		timeout:     180 * time.Second,
		// 		pullTime:    15 * time.Millisecond,
		// 		bypassCache: true,
		// 	},
		// 	wantResult: Result{UUID: "1234", Done: true},
		// },
		{
			name: "ok with cache",
			args: args{
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234", Done: true},
		},
		// {
		// 	name: "error timeout",
		// 	args: args{
		// 		params:      []int{1},
		// 		timeout:     time.Millisecond * 15,
		// 		bypassCache: true,
		// 	},
		// 	wantErr: true,
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.WaitForFile() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					switch strings.TrimSpace(req.URL.Path) {
					case "/api/v1/submit":
						if req.Method != http.MethodPost {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						if _, e := rw.Write([]byte(`{"id":"1234", "status": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/v1/results/1234":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						switch {
						case tt.fields.analysisNeverDone:
							if _, e := rw.Write([]byte(`{"id":"1234", "status": true, "done": false}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						default:
							if _, e := rw.Write([]byte(`{"id":"1234", "status": true, "done": true}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						}
					case "/api/v1/results/ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						switch {
						case tt.fields.searchNotFound:
							rw.WriteHeader(http.StatusNotFound)
							return
						case tt.fields.searchNotDone:
							if _, e := rw.Write([]byte(`{"id":"1234", "status": true, "done": false}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						default:
							if _, e := rw.Write([]byte(`{"id":"1234", "status": true, "done": true}`)); e != nil {
								t.Fatalf("could not write response body, err: %v", e)
							}
						}
					default:
						t.Errorf("handler.WaitForFile() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			client.SetSyndetect()
			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}

			waitForOptions := WaitForOptions{
				Tags:        tt.args.tags,
				Description: tt.args.description,
				BypassCache: tt.args.bypassCache,
				Timeout:     tt.args.timeout,
				PullTime:    tt.args.pullTime,
			}
			f := createTestFile(t)
			gotResult, err := client.WaitForFile(ctx, f.Name(), waitForOptions)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.WaitForFile() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.WaitForFile() = %+v, want %+v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestClient_ExtractTokenViewURL(t *testing.T) {
	type fields struct {
		Endpoint string
		Token    string
		insecure bool
	}
	type args struct {
		result *Result
	}
	tests := []struct {
		name             string
		fields           fields
		args             args
		wantURLTokenView string
		wantErr          bool
	}{
		{
			name: "VALID",
			fields: fields{
				Endpoint: "http://gdetect/api",
				Token:    token,
				insecure: false,
			},
			args: args{
				result: &Result{
					UUID:  "1234",
					Token: "5678",
				},
			},
			wantErr:          false,
			wantURLTokenView: "http://gdetect/api/expert/en/analysis-redirect/5678",
		},
		{
			name: "NO TOKEN",
			fields: fields{
				Endpoint: "http://gdetect/api",
				Token:    token,
				insecure: false,
			},
			args: args{
				result: &Result{
					UUID: "1234",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				Endpoint: tt.fields.Endpoint,
				Token:    tt.fields.Token,
			}
			gotURLTokenView, err := c.ExtractTokenViewURL(tt.args.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.ExtractTokenViewURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotURLTokenView != tt.wantURLTokenView {
				t.Errorf("Client.ExtractTokenViewURL() = %v, want %v", gotURLTokenView, tt.wantURLTokenView)
			}
		})
	}
}

func TestClient_ExtractExpertViewURL(t *testing.T) {
	type fields struct {
		Endpoint string
		Token    string
		insecure bool
	}
	type args struct {
		result *Result
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		wantURLExpertView string
		wantErr           bool
	}{
		{
			name: "VALID",
			fields: fields{
				Endpoint: "http://gdetect/api",
				Token:    token,
				insecure: false,
			},
			args: args{
				result: &Result{
					UUID: "1234",
					SID:  "5678",
				},
			},
			wantErr:           false,
			wantURLExpertView: "http://gdetect/api/expert/en/analysis/advanced/5678",
		},
		{
			name: "NO TOKEN",
			fields: fields{
				Endpoint: "http://gdetect/api",
				Token:    token,
				insecure: false,
			},
			args: args{
				result: &Result{
					UUID: "1234",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				Endpoint: tt.fields.Endpoint,
				Token:    tt.fields.Token,
			}
			gotURLExpertView, err := c.ExtractExpertViewURL(tt.args.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.ExtractExpertViewURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotURLExpertView != tt.wantURLExpertView {
				t.Errorf("Client.ExtractExpertViewURL() = %v, want %v", gotURLExpertView, tt.wantURLExpertView)
			}
		})
	}
}

func ExampleClient_SubmitFile() {
	// example mock up
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Add("Content-Type", "application/json")
		if _, e := w.Write([]byte(`{"status":false,"error":"unauthorized"}`)); e != nil {
			fmt.Println(e)
		}
	}))

	defer srv.Close()

	client, err := NewClient(srv.URL, "2b886d5f-aa81d629-4299e60b-41b728ba-9bcbbc00", false, nil)
	if err != nil {
		fmt.Println(err)
	}

	result, err := client.SubmitFile(context.Background(), "/bin/sh", SubmitOptions{
		Tags:        []string{"test"},
		Description: "test submission",
		BypassCache: false,
	})
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(result)
	}
	// Output:
	// invalid response from endpoint, 401 Unauthorized: {"status":false,"error":"unauthorized"}
}

func TestClient_GetFullSubmissionByUUID(t *testing.T) {
	type fields struct {
		setSyndetect bool
	}
	type args struct {
		uuid string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantResult interface{}
		wantErr    bool
		timeout    time.Duration
	}{
		{
			name: "ERROR SYNDETECT",
			fields: fields{
				setSyndetect: true,
			},
			args: args{
				uuid: "1234_syndetect",
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			args: args{
				uuid: "1234_timeout",
			},
			wantErr: true,
			timeout: 5 * time.Millisecond,
		},
		{
			name: "NOT FOUND",
			args: args{
				uuid: "1234_not_found",
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				uuid: "1234_server_error",
			},
			wantErr: true,
		},
		{
			name: "BAD JSON",
			args: args{
				uuid: "1234_bad_json",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.GetResultByUUID() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					if req.Method != http.MethodGet {
						t.Errorf("handler.GetResultByUUID() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}
					switch strings.TrimSpace(req.URL.Path) {
					case "/api/lite/v2/results/1234_valid_test/full":
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_valid_test", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_timeout/full":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_not_found/full":
						rw.WriteHeader(http.StatusNotFound)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_server_error/full":
						rw.WriteHeader(http.StatusInternalServerError)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case "/api/lite/v2/results/1234_bad_json/full":
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true "done": true`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					default:
						t.Errorf("handler.GetResultByUUID() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}

			if tt.fields.setSyndetect {
				client.SetSyndetect()
			}

			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}

			gotResult, err := client.GetFullSubmissionByUUID(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetFullSubmissionByUUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.GetFullSubmissionByUUID() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestClient_GetProfileStatus(t *testing.T) {
	type fields struct {
		setSyndetectClient bool
		setBadStatus       bool
		setBadBody         bool
		setTimeout         bool
		setNotFound        bool
	}
	type args struct{}
	tests := []struct {
		name       string
		wantResult ProfileStatus
		wantErr    bool
		timeout    time.Duration
		args       args
		fields     fields
	}{
		{
			name: "ERROR SYNDETECT",
			args: args{},
			fields: fields{
				setSyndetectClient: true,
			},
			wantErr: true,
		},
		{
			name:    "VALID",
			args:    args{},
			wantErr: false,
			wantResult: ProfileStatus{
				MalwareThreshold:          1000,
				DailyQuota:                1000,
				AvailableDailyQuota:       997,
				Cache:                     true,
				EstimatedAnalysisDuration: 202,
			},
		},
		{
			name: "ERROR HTTP STATUS",
			args: args{},
			fields: fields{
				setBadStatus: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR INVALID BODY",
			args: args{},
			fields: fields{
				setBadBody: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR TIMEOUT",
			args: args{},
			fields: fields{
				setTimeout: true,
			},
			timeout: 5 * time.Millisecond,
			wantErr: true,
		},
		{
			name: "ERROR FEATURE NOT AVAILABLE",
			args: args{},
			fields: fields{
				setNotFound: true,
			},
			timeout: 5 * time.Millisecond,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.GetProfileStatus() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					if req.Method != http.MethodGet {
						t.Errorf("handler.GetProfileStatus() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}
					switch {
					case req.URL.Path == "/api/versions":
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						if _, e := rw.Write([]byte(`{"/api/expert/v2":"2.6.1","/api/lite/v1":"1.0.2","/api/lite/v2":"2.5.0"}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.fields.setTimeout:
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.fields.setBadStatus:
						rw.WriteHeader(http.StatusTeapot)
						if _, e := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.fields.setBadBody:
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"dai`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.fields.setNotFound:
						rw.WriteHeader(http.StatusNotFound)
						rw.Header().Add("Content-Type", "application/json")
						if _, e := rw.Write([]byte(`{"status":false,"error":"not found"}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					default:
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202,"malware_threshold":1000}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			if tt.fields.setSyndetectClient {
				client.SetSyndetect()
			}
			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}

			gotResult, err := client.GetProfileStatus(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetProfileStatus() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.GetProfileStatus() got = %+v, want = %+v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestClient_GetAPIVersion(t *testing.T) {
	type args struct {
		setBadStatus bool
		setBadBody   bool
		setTimeout   bool
		setNotFound  bool
	}
	tests := []struct {
		name        string
		wantVersion string
		wantErr     bool
		timeout     time.Duration
		args        args
	}{
		{
			name:        "VALID",
			args:        args{},
			wantErr:     false,
			wantVersion: "2.5.0",
		},
		{
			name: "ERROR HTTP STATUS",
			args: args{
				setBadStatus: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR INVALID BODY",
			args: args{
				setBadBody: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR TIMEOUT",
			args: args{
				setTimeout: true,
			},
			timeout: 5 * time.Millisecond,
			wantErr: true,
		},
		{
			name: "ERROR NO VERSION FOUND",
			args: args{
				setNotFound: true,
			},
			timeout:     5 * time.Millisecond,
			wantErr:     true,
			wantVersion: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Method != http.MethodGet {
						t.Errorf("handler.GetAPIVersion() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}
					switch {
					case tt.args.setTimeout:
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.args.setBadStatus:
						rw.WriteHeader(http.StatusTeapot)
						if _, e := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.args.setBadBody:
						rw.WriteHeader(http.StatusOK)
						if _, e := rw.Write([]byte(`{"dai`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					case tt.args.setNotFound:
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						if _, e := rw.Write([]byte(`{"/api/expert/v2":"2.6.1","/api/lite/v1":"1.0.2"}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					default:
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						if _, e := rw.Write([]byte(`{"/api/expert/v2":"2.6.1","/api/lite/v1":"1.0.2","/api/lite/v2":"2.5.0"}`)); e != nil {
							t.Fatalf("could not write response body, err: %v", e)
						}
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			ctx := t.Context()
			if tt.timeout != 0 {
				tCtx, cancel := context.WithTimeout(t.Context(), tt.timeout)
				defer cancel()
				ctx = tCtx
			}

			gotResult, err := client.GetAPIVersion(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetAPIVersion() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantVersion) {
				t.Errorf("Client.GetAPIVersion() got = %+v, want = %+v", gotResult, tt.wantVersion)
			}
		})
	}
}
