package gdetect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
		ctx              context.Context
		filepath         string
		tags             []string
		description      string
		bypassCache      bool
		archive_password string
		filename         string
	}

	filepath := "../../tests/samples/false_mirai"

	tests := []struct {
		name     string
		args     args
		timeout  time.Duration
		wantUUID string
		wantErr  bool
	}{
		{
			name: "VALID",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "valid test",
			},
			wantErr:  false,
			wantUUID: "1234",
		},
		{
			name: "VALID WITH FILENAME",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "valid test",
				filename:    "test.exe",
			},
			wantErr:  false,
			wantUUID: "1234",
		},
		{
			name: "INVALID FILE",
			args: args{
				ctx:      context.Background(),
				filepath: "not/a/file",
			},
			wantErr: true,
		},
		{
			name: "BAD REQUEST",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "invalid file",
			},
			wantErr: true,
		},
		{
			name: "PARAMS USE",
			args: args{
				ctx:              context.Background(),
				filepath:         filepath,
				description:      "file params",
				tags:             []string{"tag1", "tag2"},
				bypassCache:      true,
				archive_password: "test",
			},
			wantErr:  false,
			wantUUID: "12345",
		},
		{
			name: "SUBMISSION STATUS FALSE",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "submission status false",
			},
			wantErr: true,
		},
		{
			name: "BAD JSON RESPONSE",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "bad json",
			},
			wantErr:  true,
			wantUUID: "",
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "timeout",
			},
			wantErr: true,
			timeout: time.Millisecond * 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
					switch strings.TrimSpace(req.FormValue("description")) {
					case "valid test":
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "invalid file":
						rw.WriteHeader(http.StatusBadRequest)
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "submission status false":
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "bad json":
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": false`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "timeout":
						time.Sleep(time.Millisecond * 15)
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "file params":
						if err := req.ParseMultipartForm(4096); err != nil {
							return
						}
						switch {
						case req.FormValue("bypass-cache") != "true", req.FormValue("description") != "file params", req.FormValue("tags") != "tag1,tag2", req.FormValue("archive_password") != "test":
							return
						}
						f, h, err := req.FormFile("file")

						switch {
						case err != nil:
							return
						case h.Filename != "false_mirai":
							return
						}
						buf := new(bytes.Buffer)
						if _, err := io.Copy(buf, f); err != nil {
							return
						}
						data := buf.String()
						if data != "test content" {
							return
						}
						_, err = rw.Write([]byte(`{"status": true, "uuid": "12345"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
						return
					default:
						t.Errorf("handler.SubmitFile() %v error = unexpected file description: %v", tt.name, strings.TrimSpace(req.FormValue("description")))
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}

			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			submitOptions := SubmitOptions{
				Description:     tt.args.description,
				Tags:            tt.args.tags,
				BypassCache:     tt.args.bypassCache,
				Filename:        tt.args.filename,
				ArchivePassword: tt.args.archive_password,
			}

			gotUUID, err := client.SubmitFile(tt.args.ctx, tt.args.filepath, submitOptions)

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
		ctx  context.Context
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
				ctx:  context.Background(),
				uuid: "1234_valid_test",
			},
			wantErr:    false,
			wantResult: Result{UUID: "1234_valid_test", Done: true},
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:  context.Background(),
				uuid: "1234_timeout",
			},
			wantErr: true,
			timeout: 5 * time.Millisecond,
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:  context.Background(),
				uuid: "1234_not_found",
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				ctx:  context.Background(),
				uuid: "1234_server_error",
			},
			wantErr: true,
		},
		{
			name: "BAD JSON",
			args: args{
				ctx:  context.Background(),
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
						_, err := rw.Write([]byte(`{"uuid":"1234_valid_test", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_timeout":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_not_found":
						rw.WriteHeader(http.StatusNotFound)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_server_error":
						rw.WriteHeader(http.StatusInternalServerError)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_bad_json":
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true "done": true`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
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

			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			gotResult, err := client.GetResultByUUID(tt.args.ctx, tt.args.uuid)
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
		ctx    context.Context
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
				ctx:    context.Background(),
				sha256: "1234_valid_test",
			},
			wantErr:    false,
			wantResult: Result{UUID: "1234_valid_test", Done: true},
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:    context.Background(),
				sha256: "1234_not_found",
			},
			wantErr: true,
		},
		{
			name: "FORBIDDEN",
			args: args{
				ctx:    context.Background(),
				sha256: "1234_forbidden",
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				ctx:    context.Background(),
				sha256: "1234_server_error",
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:    context.Background(),
				sha256: "1234_timeout",
			},
			wantErr: true,
			timeout: time.Millisecond * 5,
		},
		{
			name: "BAD JSON",
			args: args{
				ctx:    context.Background(),
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
						_, err := rw.Write([]byte(`{"uuid":"1234_valid_test", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/1234_timeout":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/1234_not_found":
						rw.WriteHeader(http.StatusNotFound)
						_, err := rw.Write([]byte(`{"uuid":"1234_not_found", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/1234_server_error":
						rw.WriteHeader(http.StatusInternalServerError)
						_, err := rw.Write([]byte(`{"uuid":"1234_server_error", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/1234_bad_json":
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"1234_bad_json", "status": true, "done": true`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/1234_forbidden":
						rw.WriteHeader(http.StatusForbidden)
						_, err := rw.Write([]byte(`{"uuid":"1234_forbidden", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
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

			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}
			gotResult, err := c.GetResultBySHA256(tt.args.ctx, tt.args.sha256)
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
	type args struct {
		ctx         context.Context
		filepath    string
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
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
		{
			name: "VALID",
			args: args{
				ctx:         context.Background(),
				filepath:    "../../tests/samples/false_mirai",
				params:      []int{1},
				timeout:     180 * time.Second,
				pullTime:    15 * time.Millisecond,
				bypassCache: true,
			},
			wantResult: Result{UUID: "1234", Done: true},
			wantErr:    false,
		},
		{
			name: "VALID WITH PREGET",
			args: args{
				ctx:      context.Background(),
				filepath: "../../tests/samples/false_cryptolocker",
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234_waiting_one_polling", Done: true},
			wantErr:    false,
		},
		{
			name: "VALID PREGET NOT FOUND",
			args: args{
				ctx:      context.Background(),
				filepath: "../../tests/samples/false_mirai",
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234", Done: true},
			wantErr:    false,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:         context.Background(),
				filepath:    "../../tests/samples/false_cryptolocker",
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
						if err := req.ParseMultipartForm(4096); err != nil {
							http.NotFoundHandler().ServeHTTP(rw, req)
							return
						}
						_, h, err := req.FormFile("file")
						if err != nil {
							return
						}
						switch h.Filename {
						case "false_mirai":
							_, err = rw.Write([]byte(`{"uuid":"1234", "status": true}`))
							if err != nil {
								t.Fatalf("cannot write test response: %s", err)
							}
						case "false_cryptolocker":
							_, err = rw.Write([]byte(`{"uuid":"1234_never_done", "status": true}`))
							if err != nil {
								t.Fatalf("cannot write test response: %s", err)
							}
						}
					case "/api/lite/v2/results/1234":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_waiting_one_polling":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"1234_waiting_one_polling", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_never_done":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/6fd51ba6957be10585068b68ab4a0683759436c3eb7cb426668773cdd7b70551":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"1234_waiting_one_polling", "status": true, "done": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						rw.WriteHeader(http.StatusNotFound)
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
			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			waitForOptions := WaitForOptions{
				Tags:        tt.args.tags,
				Description: tt.args.description,
				BypassCache: tt.args.bypassCache,
				Timeout:     tt.args.timeout,
				PullTime:    tt.args.pullTime,
			}

			gotResult, err := client.WaitForFile(tt.args.ctx, tt.args.filepath, waitForOptions)
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
	type args struct {
		ctx         context.Context
		filepath    string
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
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
		{
			name: "VALID",
			args: args{
				ctx:         context.Background(),
				filepath:    "../../tests/samples/false_mirai",
				params:      []int{1},
				timeout:     180 * time.Second,
				pullTime:    15 * time.Millisecond,
				bypassCache: true,
			},
			wantResult: Result{UUID: "1234", Done: true},
			wantErr:    false,
		},
		{
			name: "VALID USE CACHE",
			args: args{
				ctx:      context.Background(),
				filepath: "../../tests/samples/false_mirai",
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: "1234", Done: true},
			wantErr:    false,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:         context.Background(),
				filepath:    "../../tests/samples/false_cryptolocker",
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
					case "/api/v1/submit":
						if req.Method != http.MethodPost {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						if err := req.ParseMultipartForm(4096); err != nil {
							http.NotFoundHandler().ServeHTTP(rw, req)
							return
						}
						_, h, err := req.FormFile("file")
						if err != nil {
							return
						}
						switch h.Filename {
						case "false_mirai":
							_, err := rw.Write([]byte(`{"id":"1234", "status": true}`))
							if err != nil {
								t.Fatalf("cannot write test response: %s", err)
							}
						case "false_cryptolocker":
							_, err := rw.Write([]byte(`{"id":"1234_never_done", "status": true}`))
							if err != nil {
								t.Fatalf("cannot write test response: %s", err)
							}
						}
					case "/api/v1/results/1234":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"id":"1234", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/v1/results/1234_never_done":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"id":"1234", "status": true, "done": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/v1/results/6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72":
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"1234", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
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
			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			waitForOptions := WaitForOptions{
				Tags:        tt.args.tags,
				Description: tt.args.description,
				BypassCache: tt.args.bypassCache,
				Timeout:     tt.args.timeout,
				PullTime:    tt.args.pullTime,
			}

			gotResult, err := client.WaitForFile(tt.args.ctx, tt.args.filepath, waitForOptions)
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
		_, err := w.Write([]byte(`{"status":false,"error":"unauthorized"}`))
		if err != nil {
			panic(fmt.Sprintf("cannot write test response: %s", err))
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
		ctx  context.Context
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
				ctx:  context.Background(),
				uuid: "1234_syndetect",
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:  context.Background(),
				uuid: "1234_timeout",
			},
			wantErr: true,
			timeout: 5 * time.Millisecond,
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:  context.Background(),
				uuid: "1234_not_found",
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				ctx:  context.Background(),
				uuid: "1234_server_error",
			},
			wantErr: true,
		},
		{
			name: "BAD JSON",
			args: args{
				ctx:  context.Background(),
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
						_, err := rw.Write([]byte(`{"uuid":"1234_valid_test", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_timeout/full":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_not_found/full":
						rw.WriteHeader(http.StatusNotFound)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_server_error/full":
						rw.WriteHeader(http.StatusInternalServerError)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/1234_bad_json/full":
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"1234_timeout", "status": true "done": true`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
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

			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			gotResult, err := client.GetFullSubmissionByUUID(tt.args.ctx, tt.args.uuid)
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
	type args struct {
		ctx context.Context
	}
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
			args: args{
				ctx: context.Background(),
			},
			fields: fields{
				setSyndetectClient: true,
			},
			wantErr: true,
		},
		{
			name: "VALID",
			args: args{
				ctx: context.Background(),
			},
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
			args: args{
				ctx: context.Background(),
			},
			fields: fields{
				setBadStatus: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR INVALID BODY",
			args: args{
				ctx: context.Background(),
			},
			fields: fields{
				setBadBody: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR TIMEOUT",
			args: args{
				ctx: context.Background(),
			},
			fields: fields{
				setTimeout: true,
			},
			timeout: 5 * time.Millisecond,
			wantErr: true,
		},
		{
			name: "ERROR FEATURE NOT AVAILABLE",
			args: args{
				ctx: context.Background(),
			},
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
						_, err := rw.Write([]byte(`{"/api/expert/v2":"2.6.1","/api/lite/v1":"1.0.2","/api/lite/v2":"2.5.0"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.fields.setTimeout:
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.fields.setBadStatus:
						rw.WriteHeader(http.StatusTeapot)
						_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.fields.setBadBody:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"dai`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.fields.setNotFound:
						rw.WriteHeader(http.StatusNotFound)
						rw.Header().Add("Content-Type", "application/json")
						_, err := rw.Write([]byte(`{"status":false,"error":"not found"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					default:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202,"malware_threshold":1000}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
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

			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			gotResult, err := client.GetProfileStatus(tt.args.ctx)
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
		ctx          context.Context
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
			name: "VALID",
			args: args{
				ctx: context.Background(),
			},
			wantErr:     false,
			wantVersion: "2.5.0",
		},
		{
			name: "ERROR HTTP STATUS",
			args: args{
				ctx:          context.Background(),
				setBadStatus: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR INVALID BODY",
			args: args{
				ctx:        context.Background(),
				setBadBody: true,
			},
			wantErr: true,
		},
		{
			name: "ERROR TIMEOUT",
			args: args{
				ctx:        context.Background(),
				setTimeout: true,
			},
			timeout: 5 * time.Millisecond,
			wantErr: true,
		},
		{
			name: "ERROR NO VERSION FOUND",
			args: args{
				ctx:         context.Background(),
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
						_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.args.setBadStatus:
						rw.WriteHeader(http.StatusTeapot)
						_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.args.setBadBody:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"dai`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.args.setNotFound:
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						_, err := rw.Write([]byte(`{"/api/expert/v2":"2.6.1","/api/lite/v1":"1.0.2"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					default:
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						_, err := rw.Write([]byte(`{"/api/expert/v2":"2.6.1","/api/lite/v1":"1.0.2","/api/lite/v2":"2.5.0"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}

			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			gotResult, err := client.GetAPIVersion(tt.args.ctx)
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

type ErrorReader struct {
	err error
}

func (e ErrorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func TestClient_Reconfigure(t *testing.T) {
	type args struct {
		endpoint   string
		token      string
		insecure   bool
		syndetect  bool
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
				token:      "other",
				insecure:   false,
				httpClient: nil,
			},
			wantErr: false,
			wantClient: &Client{
				Endpoint: "http://glimps/detect",
				Token:    "other",
			},
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
			gotClient, err := NewClient("http://orig/detect", token, false, nil)
			if err != nil {
				t.Fatalf("NewClient() error on test init : %s", err)
			}
			err = gotClient.Reconfigure(tt.args.endpoint, tt.args.token, tt.args.insecure, tt.args.syndetect, tt.args.httpClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("client.Reconfigure() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantClient != nil {
				if !compareClients(gotClient, tt.wantClient) {
					t.Errorf("NewClient() = %v, want %v", gotClient, tt.wantClient)
				}
			}
		})
	}
}
