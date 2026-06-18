package gdetect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
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

const (
	testUUIDValid      = "ab000001-0000-0000-0000-000000000001"
	testUUIDValid2     = "ab000001-0000-0000-0000-000000000002"
	testUUIDTimeout    = "ab000001-0000-0000-0000-000000000003"
	testUUIDNotFound   = "ab000001-0000-0000-0000-000000000004"
	testUUIDServerErr  = "ab000001-0000-0000-0000-000000000005"
	testUUIDBadJSON    = "ab000001-0000-0000-0000-000000000006"
	testUUIDForbidden  = "ab000001-0000-0000-0000-000000000007"
	testUUIDNeverDone  = "ab000001-0000-0000-0000-000000000008"
	testUUIDWaitPoll   = "ab000001-0000-0000-0000-000000000009"
	testUUIDPDF        = "ab000001-0000-0000-0000-00000000000a"
	testUUIDJSONFull   = "ab000001-0000-0000-0000-00000000000b"
	testUUIDMISP       = "ab000001-0000-0000-0000-00000000000c"
	testUUIDSTIX       = "ab000001-0000-0000-0000-00000000000d"
	testUUIDMarkdown   = "ab000001-0000-0000-0000-00000000000e"
	testUUIDCSV        = "ab000001-0000-0000-0000-00000000000f"
	testUUIDBadRequest = "ab000001-0000-0000-0000-000000000010"
	testSyndetectID    = "syndetectid"
)

const (
	testSHA256Valid     = "ab00000100000000000000000000000000000000000000000000000000000001"
	testSHA256NotFound  = "ab00000100000000000000000000000000000000000000000000000000000004"
	testSHA256Forbidden = "ab00000100000000000000000000000000000000000000000000000000000007"
	testSHA256ServerErr = "ab00000100000000000000000000000000000000000000000000000000000005"
	testSHA256Timeout   = "ab00000100000000000000000000000000000000000000000000000000000003"
	testSHA256BadJSON   = "ab00000100000000000000000000000000000000000000000000000000000006"
)

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
				HTTPClient: http.DefaultClient,
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
				HTTPClient: &http.Client{Timeout: 2 * time.Second},
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
		dynamic          bool
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
		{
			name: "DYNAMIC SUBMIT",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "dynamic submit",
				dynamic:     true,
			},
			wantErr:  false,
			wantUUID: "dynamic-uuid",
		},
		{
			name: "NON DYNAMIC SUBMIT",
			args: args{
				ctx:         context.Background(),
				filepath:    filepath,
				description: "non dynamic submit",
				dynamic:     false,
			},
			wantErr:  false,
			wantUUID: "non-dynamic-uuid",
		},
		{
			name: "DYNAMIC WITH ALL OPTIONS",
			args: args{
				ctx:              context.Background(),
				filepath:         filepath,
				description:      "dynamic all options",
				tags:             []string{"tag1", "tag2"},
				bypassCache:      true,
				archive_password: "pass",
				dynamic:          true,
			},
			wantErr:  false,
			wantUUID: "dynamic-all-uuid",
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
					req.Body = http.MaxBytesReader(rw, req.Body, 10*1024*1024)
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
					case "dynamic submit":
						// Verify dynamic=true query parameter is present
						if req.URL.Query().Get("dynamic") != "true" {
							t.Errorf("handler.SubmitFile() %v: expected dynamic=true query param, got %q", tt.name, req.URL.Query().Get("dynamic"))
						}
						_, err := rw.Write([]byte(`{"status": true, "uuid": "dynamic-uuid"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "non dynamic submit":
						// Verify dynamic query parameter is absent
						if req.URL.Query().Has("dynamic") {
							t.Errorf("handler.SubmitFile() %v: unexpected dynamic query param: %q", tt.name, req.URL.Query().Get("dynamic"))
						}
						_, err := rw.Write([]byte(`{"status": true, "uuid": "non-dynamic-uuid"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "dynamic all options":
						// Verify dynamic=true query parameter is present
						if req.URL.Query().Get("dynamic") != "true" {
							t.Errorf("handler.SubmitFile() %v: expected dynamic=true query param, got %q", tt.name, req.URL.Query().Get("dynamic"))
						}
						// Verify all other form fields are present
						if err := req.ParseMultipartForm(4096); err != nil {
							t.Fatalf("cannot parse multipart form: %s", err)
						}
						switch {
						case req.FormValue("bypass-cache") != "true",
							req.FormValue("description") != "dynamic all options",
							req.FormValue("tags") != "tag1,tag2",
							req.FormValue("archive_password") != "pass":
							t.Errorf("handler.SubmitFile() %v: unexpected form values", tt.name)
						}
						_, err := rw.Write([]byte(`{"status": true, "uuid": "dynamic-all-uuid"}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
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
				Dynamic:         tt.args.dynamic,
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
		ctx       context.Context
		uuid      string
		syndetect bool
	}
	tests := []struct {
		name            string
		args            args
		wantResult      Result
		wantErr         bool
		wantSpecificErr error
		timeout         time.Duration
	}{
		{
			name: "ko invalid UUID",
			args: args{
				ctx:  context.Background(),
				uuid: "not-a-valid-uuid",
			},
			wantErr:         true,
			wantSpecificErr: ErrInvalidUUID,
		},
		{
			name: "syndetect id is not an uuid",
			args: args{
				ctx:       context.Background(),
				uuid:      testSyndetectID,
				syndetect: true,
			},
			wantErr:    false,
			wantResult: Result{UUID: testSyndetectID, ID: testSyndetectID, Done: true},
		},
		{
			name: "VALID",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDValid,
			},
			wantErr:    false,
			wantResult: Result{UUID: testUUIDValid, Done: true},
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDTimeout,
			},
			wantErr: true,
			timeout: 5 * time.Millisecond,
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDNotFound,
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDServerErr,
			},
			wantErr: true,
		},
		{
			name: "BAD JSON",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDBadJSON,
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
					case "/api/lite/v2/results/" + testUUIDValid:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDTimeout:
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDTimeout + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDNotFound:
						rw.WriteHeader(http.StatusNotFound)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDNotFound + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDServerErr:
						rw.WriteHeader(http.StatusInternalServerError)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDServerErr + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDBadJSON:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDBadJSON + `", "status": true "done": true`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/v1/results/" + testSyndetectID:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"id":"` + testSyndetectID + `", "status": true, "done": true}`))
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
			if tt.args.syndetect {
				client.SetSyndetect()
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
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("Client.GetResultByUUID() error = %v, want %v", err, tt.wantSpecificErr)
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
		name            string
		args            args
		wantResult      Result
		wantErr         bool
		wantSpecificErr error
		timeout         time.Duration
	}{
		{
			name: "ko invalid SHA256",
			args: args{
				ctx:    context.Background(),
				sha256: "not-a-valid-sha256",
			},
			wantErr:         true,
			wantSpecificErr: ErrInvalidSHA256,
		},
		{
			name: "VALID",
			args: args{
				ctx:    context.Background(),
				sha256: testSHA256Valid,
			},
			wantErr:    false,
			wantResult: Result{UUID: testUUIDValid, Done: true},
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:    context.Background(),
				sha256: testSHA256NotFound,
			},
			wantErr: true,
		},
		{
			name: "FORBIDDEN",
			args: args{
				ctx:    context.Background(),
				sha256: testSHA256Forbidden,
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				ctx:    context.Background(),
				sha256: testSHA256ServerErr,
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:    context.Background(),
				sha256: testSHA256Timeout,
			},
			wantErr: true,
			timeout: time.Millisecond * 5,
		},
		{
			name: "BAD JSON",
			args: args{
				ctx:    context.Background(),
				sha256: testSHA256BadJSON,
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
					case "/api/lite/v2/search/" + testSHA256Valid:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/" + testSHA256Timeout:
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDTimeout + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/" + testSHA256NotFound:
						rw.WriteHeader(http.StatusNotFound)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDNotFound + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/" + testSHA256ServerErr:
						rw.WriteHeader(http.StatusInternalServerError)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDServerErr + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/" + testSHA256BadJSON:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDBadJSON + `", "status": true, "done": true`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/search/" + testSHA256Forbidden:
						rw.WriteHeader(http.StatusForbidden)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDForbidden + `", "status": true, "done": true}`))
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
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("Client.GetResultBySHA256() error = %v, want %v", err, tt.wantSpecificErr)
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
		syndetect bool
	}
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
		fields     fields
		args       args
		wantResult Result
		wantErr    bool
		timeout    time.Duration
	}{
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
		{
			name: "TIMEOUT syndetect",
			fields: fields{
				syndetect: true,
			},
			args: args{
				ctx:         context.Background(),
				filepath:    "../../tests/samples/false_cryptolocker",
				params:      []int{1},
				timeout:     time.Millisecond * 15,
				bypassCache: true,
			},
			wantErr: true,
		},
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
			wantResult: Result{UUID: testUUIDValid, Done: true},
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
			wantResult: Result{UUID: testUUIDWaitPoll, Done: true},
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
			wantResult: Result{UUID: testUUIDValid, Done: true},
		},
		{
			name: "VALID syndetect",
			fields: fields{
				syndetect: true,
			},
			args: args{
				ctx:         context.Background(),
				filepath:    "../../tests/samples/false_mirai",
				params:      []int{1},
				timeout:     180 * time.Second,
				pullTime:    15 * time.Millisecond,
				bypassCache: true,
			},
			wantResult: Result{UUID: testUUIDValid, ID: testUUIDValid, Done: true},
		},
		{
			name: "VALID syndetect use cache",
			fields: fields{
				syndetect: true,
			},
			args: args{
				ctx:      context.Background(),
				filepath: "../../tests/samples/false_mirai",
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: testUUIDValid, Done: true},
		},
		{
			name: "VALID syndetect use cache not done",
			fields: fields{
				syndetect: true,
			},
			args: args{
				ctx:      context.Background(),
				filepath: "../../tests/samples/false_cryptolocker",
				params:   []int{1},
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: testUUIDValid, ID: testUUIDValid, Done: true},
		},
	}
	// SHA256 hashes of the sample files used for pre-get/search paths.
	const (
		sha256FalseCryptolocker = "6fd51ba6957be10585068b68ab4a0683759436c3eb7cb426668773cdd7b70551"
		sha256FalseMirai        = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiPrefix := "/api/lite/v2/"
			uuidField := "uuid"
			if tt.fields.syndetect {
				apiPrefix = "/api/v1/"
				uuidField = "id"
			}

			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.WaitForFile() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					uri := strings.TrimSpace(req.URL.Path)
					switch {
					case uri == apiPrefix+"submit":
						if req.Method != http.MethodPost {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						req.Body = http.MaxBytesReader(rw, req.Body, 10*1024*1024)
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
							_, err = rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDValid + `", "status": true}`))
							if err != nil {
								t.Fatalf("cannot write test response: %s", err)
							}
						case "false_cryptolocker":
							_, err = rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDNeverDone + `", "status": true}`))
							if err != nil {
								t.Fatalf("cannot write test response: %s", err)
							}
						}
					case uri == apiPrefix+"results/"+testUUIDValid:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDValid + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case uri == apiPrefix+"results/"+testUUIDWaitPoll:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDWaitPoll + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case uri == apiPrefix+"results/"+testUUIDNeverDone:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDValid + `", "status": true, "done": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					// Pre-get search: detect uses /search/, syndetect uses /results/
					case !tt.fields.syndetect && uri == apiPrefix+"search/"+sha256FalseCryptolocker:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDWaitPoll + `", "status": true, "done": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case !tt.fields.syndetect && uri == apiPrefix+"search/"+sha256FalseMirai:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						rw.WriteHeader(http.StatusNotFound)
					case tt.fields.syndetect && uri == apiPrefix+"results/"+sha256FalseMirai:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case tt.fields.syndetect && uri == apiPrefix+"results/"+sha256FalseCryptolocker:
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForFile() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						_, err := rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDValid + `", "done": false}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					default:
						t.Errorf("handler.WaitForFile() %v error = unexpected URL: %v", tt.name, uri)
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			if tt.fields.syndetect {
				client.SetSyndetect()
			}
			if tt.timeout != 0 {
				ctx, cancel := context.WithTimeout(tt.args.ctx, tt.timeout)
				defer cancel()
				tt.args.ctx = ctx
			}

			waitForOptions := WaitForOptions{
				SubmitOptions: SubmitOptions{
					Tags:        tt.args.tags,
					Description: tt.args.description,
					BypassCache: tt.args.bypassCache,
				},
				Timeout:  tt.args.timeout,
				PullTime: tt.args.pullTime,
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

func TestClient_WaitForReader(t *testing.T) {
	type fields struct {
		getResultsNeverDone bool
		searchNotDone       bool
		searchNotFound      bool
	}
	type args struct {
		content     string
		reader      io.Reader
		tags        []string
		description string
		bypassCache bool
		dynamic     bool
		timeout     time.Duration
		pullTime    time.Duration
	}
	tests := []struct {
		name             string
		args             args
		fields           fields
		wantResult       Result
		wantErr          bool
		wantDynamicParam string
	}{
		{
			name: "VALID",
			args: args{
				content:     "test ok bypass cache",
				timeout:     180 * time.Second,
				pullTime:    15 * time.Millisecond,
				bypassCache: true,
			},
			wantResult: Result{UUID: testUUIDValid, Done: true},
			wantErr:    false,
		},
		{
			name: "VALID WITH PREGET",
			fields: fields{
				searchNotDone: true,
			},
			args: args{
				content:  "test ok cache found",
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: testUUIDValid, Done: true},
			wantErr:    false,
		},
		{
			name: "VALID PREGET NOT FOUND",
			fields: fields{
				searchNotFound: true,
			},
			args: args{
				content:  "test ok not found in cache",
				timeout:  180 * time.Second,
				pullTime: 15 * time.Millisecond,
			},
			wantResult: Result{UUID: testUUIDValid, Done: true},
			wantErr:    false,
		},
		{
			name: "ko error reader",
			args: args{
				reader:   ErrorReader{err: errors.New("read error")},
				timeout:  5 * time.Second,
				pullTime: 10 * time.Millisecond,
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			fields: fields{
				searchNotDone:       true,
				getResultsNeverDone: true,
			},
			args: args{
				content:     "timeout",
				timeout:     time.Millisecond * 15,
				bypassCache: true,
			},
			wantErr: true,
		},
		{
			name: "ok dynamic true propagated",
			args: args{
				content:     "dynamic true",
				timeout:     5 * time.Second,
				pullTime:    10 * time.Millisecond,
				bypassCache: true,
				dynamic:     true,
			},
			wantResult:       Result{UUID: testUUIDValid, Done: true},
			wantDynamicParam: "true",
		},
		{
			name: "ok dynamic false not propagated",
			args: args{
				content:     "dynamic false",
				timeout:     5 * time.Second,
				pullTime:    10 * time.Millisecond,
				bypassCache: true,
			},
			wantResult: Result{UUID: testUUIDValid, Done: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDynamicParam := ""
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.WaitForReader() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					uri := strings.TrimSpace(req.URL.Path)
					switch {
					case uri == "/api/lite/v2/submit":
						gotDynamicParam = req.URL.Query().Get("dynamic")
						if req.Method != http.MethodPost {
							t.Errorf("handler.WaitForReader() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}

						_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
						if err != nil {
							t.Fatalf("handler.WaitForReader() error could not parse media type: %v", err)
						}

						boundary := params["boundary"]

						mr := multipart.NewReader(req.Body, boundary)
						content := make([]byte, 4096)
						for {
							part, err := mr.NextPart()
							if err != nil {
								t.Fatalf("handler.WaitForReader() error could not get multipart part: %v", err)
							}
							defer func() {
								if e := part.Close(); e != nil {
									Logger.Warn("could not close part", slog.String("error", e.Error()))
								}
							}()
							if part.FormName() == "file" {
								if _, e := part.Read(content); e != nil && !errors.Is(e, io.EOF) {
									t.Fatalf("handler.WaitForReader() error could not read part: %v", e)
								}
								break
							}
						}
						content = bytes.Trim(content, "\x00")
						if tt.args.content != string(content) {
							t.Fatalf("bad content, got %s, want %s", content, tt.args.content)
						}
						if _, e := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true}`)); e != nil {
							t.Fatalf("could not write response, error: %v", e)
						}

					case strings.HasPrefix(uri, "/api/lite/v2/results/"):
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForReader() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						switch {
						case tt.fields.getResultsNeverDone:
							if _, e := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": false}`)); e != nil {
								t.Fatalf("could not write response, error: %v", e)
							}
						default:
							if _, e := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`)); e != nil {
								t.Fatalf("could not write response, error: %v", e)
							}
						}
					case strings.HasPrefix(uri, "/api/lite/v2/search/"):
						if req.Method != http.MethodGet {
							t.Errorf("handler.WaitForReader() %v error = unexpected METHOD: %v", tt.name, req.Method)
						}
						switch {
						case tt.fields.searchNotDone:
							if _, e := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": false}`)); e != nil {
								t.Fatalf("could not write response, error: %v", e)
							}
						case tt.fields.searchNotFound:
							rw.WriteHeader(http.StatusNotFound)
						default:
							if _, e := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`)); e != nil {
								t.Fatalf("could not write response, error: %v", e)
							}
						}
					default:
						t.Errorf("handler.WaitForReader() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
					}
				}),
			)
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				return
			}
			waitForOptions := WaitForOptions{
				SubmitOptions: SubmitOptions{
					Tags:        tt.args.tags,
					Description: tt.args.description,
					BypassCache: tt.args.bypassCache,
					Dynamic:     tt.args.dynamic,
				},
				Timeout:  tt.args.timeout,
				PullTime: tt.args.pullTime,
			}

			reader := tt.args.reader
			if reader == nil {
				reader = strings.NewReader(tt.args.content)
			}

			gotResult, err := client.WaitForReader(t.Context(), reader, waitForOptions)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.WaitForReader() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Client.WaitForReader() = %+v, want %+v", gotResult, tt.wantResult)
			}
			if tt.wantDynamicParam != gotDynamicParam {
				t.Errorf("Client.WaitForReader() dynamic param = %q, want %q", gotDynamicParam, tt.wantDynamicParam)
			}
		})
	}
}

// TestClient_WaitForReader_PreGetHashesContent is a regression test for the
// empty-file SHA256 bug: WaitForReader buffers the reader into a temp file
// (leaving its offset at EOF), then waitforWithPreGet must seek back to the
// start before hashing. Without that seek the cache lookup used the SHA256 of
// an empty file (e3b0c442...b855) instead of the actual content.
func TestClient_WaitForReader_PreGetHashesContent(t *testing.T) {
	const content = "regression: hash must cover the real content"
	wantSHA256 := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	gotSearchSHA256 := ""
	s := httptest.NewServer(
		http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			uri := strings.TrimSpace(req.URL.Path)
			switch {
			case strings.HasPrefix(uri, "/api/lite/v2/search/"):
				gotSearchSHA256 = strings.TrimPrefix(uri, "/api/lite/v2/search/")
				if _, e := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`)); e != nil {
					t.Fatalf("could not write response, error: %v", e)
				}
			default:
				t.Errorf("unexpected URL: %v", uri)
			}
		}),
	)
	defer s.Close()

	client, err := NewClient(s.URL, token, false, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.WaitForReader(t.Context(), strings.NewReader(content), WaitForOptions{
		Timeout:  5 * time.Second,
		PullTime: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("WaitForReader() error = %v", err)
	}

	if gotSearchSHA256 == emptySHA256 {
		t.Fatalf("cache lookup used empty-file SHA256 %s: content was not hashed (offset not reset)", emptySHA256)
	}
	if gotSearchSHA256 != wantSHA256 {
		t.Errorf("cache lookup SHA256 = %s, want %s", gotSearchSHA256, wantSHA256)
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
		{ //nolint:gosec,nolintlint // G101: test token value, not a real credential
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
		name            string
		fields          fields
		args            args
		wantResult      any
		wantErr         bool
		wantSpecificErr error
		timeout         time.Duration
	}{
		{
			name: "ko invalid UUID",
			args: args{
				ctx:  context.Background(),
				uuid: "not-a-valid-uuid",
			},
			wantErr:         true,
			wantSpecificErr: ErrInvalidUUID,
		},
		{
			name: "ERROR SYNDETECT",
			fields: fields{
				setSyndetect: true,
			},
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDValid,
			},
			wantErr: true,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDTimeout,
			},
			wantErr: true,
			timeout: 5 * time.Millisecond,
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDNotFound,
			},
			wantErr: true,
		},
		{
			name: "INTERNAL SERVER ERROR",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDServerErr,
			},
			wantErr: true,
		},
		{
			name: "BAD JSON",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDBadJSON,
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
					case "/api/lite/v2/results/" + testUUIDValid + "/full":
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDValid + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDTimeout + "/full":
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDTimeout + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDNotFound + "/full":
						rw.WriteHeader(http.StatusNotFound)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDTimeout + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDServerErr + "/full":
						rw.WriteHeader(http.StatusInternalServerError)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDTimeout + `", "status": true, "done": true}`))
						if err != nil {
							t.Fatalf("cannot write test response: %s", err)
						}
					case "/api/lite/v2/results/" + testUUIDBadJSON + "/full":
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"uuid":"` + testUUIDTimeout + `", "status": true "done": true`))
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
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("Client.GetFullSubmissionByUUID() error = %v, want %v", err, tt.wantSpecificErr)
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
		setErrorBody       bool
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
			name: "VALID SYNDETECT",
			args: args{
				ctx: context.Background(),
			},
			fields: fields{
				setSyndetectClient: true,
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
					case tt.fields.setErrorBody:
						rw.WriteHeader(http.StatusOK)
						_, err := io.Copy(rw, io.NopCloser(ErrorReader{err: errors.New("test")}))
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
		setErrorBody bool
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
					case tt.args.setErrorBody:
						rw.WriteHeader(http.StatusOK)
						_, err := io.Copy(rw, io.NopCloser(ErrorReader{err: errors.New("test")}))
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

func TestClient_Reconfigure(t *testing.T) {
	type args struct {
		token                    string
		insecure                 bool
		old_syndetect            bool
		new_syndetect            bool
		httpClient               *http.Client
		setGetProfileStatusError bool
	}
	tests := []struct {
		name       string
		args       args
		wantClient *Client
		wantErr    bool
	}{
		{
			name: "valid syndetect 1.0.0",
			args: args{
				token:         token,
				insecure:      false,
				httpClient:    nil,
				old_syndetect: true,
			},
			wantErr: false,
			wantClient: &Client{
				Token: token,
			},
		},
		{
			name: "valid syndetect > 1.0.0",
			args: args{
				token:         token,
				insecure:      false,
				httpClient:    nil,
				new_syndetect: true,
			},
			wantErr: false,
			wantClient: &Client{
				Token: token,
			},
		},
		{
			name: "valid",
			args: args{
				token:      token,
				insecure:   false,
				httpClient: nil,
			},
			wantErr: false,
			wantClient: &Client{
				Token: token,
			},
		},
		{
			name: "valid default http client",
			args: args{
				token:      token,
				insecure:   false,
				httpClient: http.DefaultClient,
			},
			wantErr: false,
			wantClient: &Client{
				Token:      token,
				HTTPClient: http.DefaultClient,
			},
		},
		{
			name: "valid custom http client",
			args: args{
				token:      token,
				insecure:   false,
				httpClient: &http.Client{Timeout: 2 * time.Second},
			},
			wantErr: false,
			wantClient: &Client{
				Token:      token,
				HTTPClient: &http.Client{Timeout: 2 * time.Second},
			},
		},
		{
			name: "get status error",
			args: args{
				token:                    token,
				insecure:                 false,
				httpClient:               nil,
				setGetProfileStatusError: true,
			},
			wantErr: true,
			wantClient: &Client{
				Token: token,
			},
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
					case tt.args.setGetProfileStatusError:
						rw.WriteHeader(http.StatusBadRequest)
						rw.Header().Add("Content-Type", "application/json")
					case tt.args.old_syndetect && req.URL.Path == "/api/versions":
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						_, err := rw.Write([]byte(`{"/v1":"1.0.0"}`))
						if err != nil {
							t.Fatalf("cannot write test response : %s", err)
						}
					case tt.args.new_syndetect && req.URL.Path == "/api/versions":
						rw.WriteHeader(http.StatusOK)
						rw.Header().Add("Content-Type", "application/json")
						_, err := rw.Write([]byte(`{"v1":"1.1.0"}`))
						if err != nil {
							t.Fatalf("cannot write test response : %s", err)
						}

					default:
						rw.WriteHeader(http.StatusOK)
						_, err := rw.Write([]byte(`{"daily_quota":1000,"available_daily_quota":997,"cache":true,"estimated_analysis_duration":202,"malware_threshold":1000}`))
						if err != nil {
							t.Fatalf("cannot write test response : %s", err)
						}
					}
				}),
			)
			gotClient, err := NewClient("http://orig/detect", token, false, nil)
			if err != nil {
				t.Fatalf("NewClient() error on test init : %s", err)
			}
			err = gotClient.Reconfigure(t.Context(), ClientConfig{
				Endpoint:   s.URL,
				Token:      tt.args.token,
				Insecure:   tt.args.insecure,
				Syndetect:  tt.args.old_syndetect,
				HTTPClient: tt.args.httpClient,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("client.Reconfigure() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantClient != nil {
				if strings.Contains(gotClient.Endpoint, "orig") {
					t.Errorf("NewClient() endpoint si not update, got %s want %s", gotClient.Endpoint, s.URL)
				}
				tt.wantClient.Endpoint = s.URL
				if !compareClients(gotClient, tt.wantClient) {
					t.Errorf("NewClient() = %v, want %v", gotClient, tt.wantClient)
				}
			}
		})
	}
}

func TestClient_ExportResult(t *testing.T) {
	type fields struct {
		setSyndetect bool
	}
	type args struct {
		ctx     context.Context
		uuid    string
		options ExportOptions
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantData        []byte
		wantErr         bool
		wantSpecificErr error
		timeout         time.Duration
	}{
		{
			name: "ko invalid UUID",
			args: args{
				ctx:  context.Background(),
				uuid: "not-a-valid-uuid",
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutEN,
				},
			},
			wantErr:         true,
			wantSpecificErr: ErrInvalidUUID,
		},
		{
			name: "VALID PDF EXPORT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDPDF,
				options: ExportOptions{
					Format: ExportFormatPDF,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  false,
			wantData: []byte("%PDF-1.3\n"),
		},
		{
			name: "VALID JSON EXPORT FULL",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDJSONFull,
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutFR,
					Full:   true,
				},
			},
			wantErr:  false,
			wantData: []byte(`{"verdict":"malicious","score":2800}`),
		},
		{
			name: "VALID MISP EXPORT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDMISP,
				options: ExportOptions{
					Format: ExportFormatMISP,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  false,
			wantData: []byte(`{"Event":{"uuid":"test"}}`),
		},
		{
			name: "VALID STIX EXPORT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDSTIX,
				options: ExportOptions{
					Format: ExportFormatSTIX,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  false,
			wantData: []byte(`{"type":"bundle"}`),
		},
		{
			name: "VALID MARKDOWN EXPORT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDMarkdown,
				options: ExportOptions{
					Format: ExportFormatMarkdown,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  false,
			wantData: []byte("# GMalware submission report\n"),
		},
		{
			name: "VALID CSV EXPORT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDCSV,
				options: ExportOptions{
					Format: ExportFormatCSV,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  false,
			wantData: []byte("name,sha256,size\n"),
		},
		{
			name: "ERROR SYNDETECT",
			fields: fields{
				setSyndetect: true,
			},
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDValid,
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  true,
			wantData: nil,
		},
		{
			name: "NOT FOUND",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDNotFound,
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  true,
			wantData: nil,
		},
		{
			name: "FORBIDDEN",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDForbidden,
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  true,
			wantData: nil,
		},
		{
			name: "TIMEOUT",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDTimeout,
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  true,
			timeout:  5 * time.Millisecond,
			wantData: nil,
		},
		{
			name: "BAD REQUEST",
			args: args{
				ctx:  context.Background(),
				uuid: testUUIDBadRequest,
				options: ExportOptions{
					Format: ExportFormatJSON,
					Layout: ExportLayoutEN,
					Full:   false,
				},
			},
			wantErr:  true,
			wantData: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != token {
						t.Errorf("handler.ExportResult() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					if req.Method != http.MethodGet {
						t.Errorf("handler.ExportResult() %v error = unexpected METHOD: %v", tt.name, req.Method)
					}

					// Parse query parameters
					query := req.URL.Query()
					format := query.Get("format")
					layout := query.Get("layout")
					full := query.Get("full")

					switch {
					case strings.Contains(req.URL.Path, testUUIDPDF):
						if format != "pdf" || layout != "en" {
							t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
						}
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte("%PDF-1.3\n"))
					case strings.Contains(req.URL.Path, testUUIDJSONFull):
						if format != "json" || layout != "fr" || full != "true" {
							t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
						}
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte(`{"verdict":"malicious","score":2800}`))
					case strings.Contains(req.URL.Path, testUUIDMISP):
						if format != "misp" || layout != "en" {
							t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
						}
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte(`{"Event":{"uuid":"test"}}`))
					case strings.Contains(req.URL.Path, testUUIDSTIX):
						if format != "stix" {
							t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
						}
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte(`{"type":"bundle"}`))
					case strings.Contains(req.URL.Path, testUUIDMarkdown):
						if format != "markdown" {
							t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
						}
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte("# GMalware submission report\n"))
					case strings.Contains(req.URL.Path, testUUIDCSV):
						if format != "csv" {
							t.Errorf("handler.ExportResult() %v error = unexpected query params", tt.name)
						}
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte("name,sha256,size\n"))
					case strings.Contains(req.URL.Path, testUUIDTimeout):
						time.Sleep(15 * time.Millisecond)
						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write([]byte(`{"verdict":"malicious"}`))
					case strings.Contains(req.URL.Path, testUUIDNotFound):
						rw.WriteHeader(http.StatusNotFound)
						_, _ = rw.Write([]byte(`{"status":false,"error":"not found"}`))
					case strings.Contains(req.URL.Path, testUUIDForbidden):
						rw.WriteHeader(http.StatusForbidden)
						_, _ = rw.Write([]byte(`{"status":false,"error":"forbidden"}`))
					case strings.Contains(req.URL.Path, testUUIDBadRequest):
						rw.WriteHeader(http.StatusBadRequest)
						_, _ = rw.Write([]byte(`{"status":false,"error":"bad request"}`))
					default:
						t.Errorf("handler.ExportResult() %v error = unexpected URL: %v", tt.name, strings.TrimSpace(req.URL.Path))
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

			gotData, err := client.ExportResult(tt.args.ctx, tt.args.uuid, tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.ExportResult() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("Client.ExportResult() error = %v, want %v", err, tt.wantSpecificErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("Client.ExportResult() = %v, want %v", string(gotData), string(tt.wantData))
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

func TestNewClientFromConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
	}{
		{
			name: "valid",
			config: ClientConfig{
				Endpoint: "http://example.com",
				Token:    token,
				Insecure: false,
			},
			wantErr: false,
		},
		{
			name: "valid insecure",
			config: ClientConfig{
				Endpoint: "http://example.com",
				Token:    token,
				Insecure: true,
			},
			wantErr: false,
		},
		{
			name: "invalid token",
			config: ClientConfig{
				Endpoint: "http://example.com",
				Token:    "bad-token",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClientFromConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClientFromConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClientFromConfig() returned nil client")
			}
		})
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClient_TransportWrapper(t *testing.T) {
	t.Run("wrapper decorates transport and composes with insecure", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		var called bool
		var capturedBase http.RoundTripper
		client, err := NewClientFromConfig(ClientConfig{
			Endpoint: srv.URL,
			Token:    token,
			Insecure: true,
			TransportWrapper: func(base http.RoundTripper) http.RoundTripper {
				capturedBase = base
				return rtFunc(func(r *http.Request) (*http.Response, error) {
					called = true
					return base.RoundTrip(r)
				})
			},
		})
		if err != nil {
			t.Fatalf("NewClientFromConfig() error = %v", err)
		}

		// Insecure must still be honoured on the base transport the wrapper receives.
		tr, ok := capturedBase.(*http.Transport)
		if !ok {
			t.Fatalf("base transport type = %T, want *http.Transport", capturedBase)
		}
		if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Insecure not applied to the base transport built under TransportWrapper")
		}

		// A real request must flow through the wrapper and reach the TLS server.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do() error = %v", err)
		}
		if e := resp.Body.Close(); e != nil {
			t.Fatalf("close body: %v", e)
		}
		if !called {
			t.Error("wrapper RoundTripper was not invoked")
		}
	})

	t.Run("wrapper ignored when HTTPClient set", func(t *testing.T) {
		custom := &http.Client{}
		wrapped := false
		client, err := NewClientFromConfig(ClientConfig{
			Endpoint:   "http://example.com",
			Token:      token,
			HTTPClient: custom,
			TransportWrapper: func(base http.RoundTripper) http.RoundTripper {
				wrapped = true
				return base
			},
		})
		if err != nil {
			t.Fatalf("NewClientFromConfig() error = %v", err)
		}
		if client.HTTPClient != custom {
			t.Error("provided HTTPClient was not used verbatim")
		}
		if wrapped {
			t.Error("TransportWrapper must be ignored when HTTPClient is set")
		}
	})

	t.Run("default transport untouched without wrapper or insecure", func(t *testing.T) {
		client, err := NewClientFromConfig(ClientConfig{Endpoint: "http://example.com", Token: token})
		if err != nil {
			t.Fatalf("NewClientFromConfig() error = %v", err)
		}
		if client.HTTPClient.Transport != nil {
			t.Errorf("default client Transport = %v, want nil", client.HTTPClient.Transport)
		}
	})
}

func TestFeatureNotAvailableError(t *testing.T) {
	e := FeatureNotAvailableError{Version: "2.5.0"}
	want := "feature not available, API version: 2.5.0"
	if e.Error() != want {
		t.Errorf("FeatureNotAvailableError.Error() = %v, want %v", e.Error(), want)
	}
}

func TestGetPath(t *testing.T) {
	c := &Client{}

	// Normal detect path
	path, err := c.getPath("results")
	if err != nil {
		t.Errorf("getPath(results) error = %v", err)
	}
	if path != "/api/lite/v2/results/" {
		t.Errorf("getPath(results) = %v, want /api/lite/v2/results/", path)
	}

	// Unknown path returns error
	_, err = c.getPath("unknown_path")
	if err == nil {
		t.Error("getPath(unknown_path) expected error, got nil")
	}

	// Syndetect path
	c.syndetect = true
	path, err = c.getPath("results")
	if err != nil {
		t.Errorf("getPath(results) syndetect error = %v", err)
	}
	if path != "/api/v1/results/" {
		t.Errorf("getPath(results) syndetect = %v, want /api/v1/results/", path)
	}
}

func TestHTTPError(t *testing.T) {
	resp := &http.Response{
		Status:     "404 Not Found",
		StatusCode: http.StatusNotFound,
	}
	e := NewHTTPError(resp, "resource not found")
	want := "invalid response from endpoint, 404 Not Found: resource not found"
	if e.Error() != want {
		t.Errorf("HTTPError.Error() = %v, want %v", e.Error(), want)
	}
	if e.Code != http.StatusNotFound {
		t.Errorf("HTTPError.Code = %v, want %v", e.Code, http.StatusNotFound)
	}
}

func TestClient_GetResultByUUIDWithWait(t *testing.T) {
	type fields struct {
		syndetect bool
	}
	tests := []struct {
		name            string
		fields          fields
		waitSeconds     int
		wantErr         bool
		wantSpecificErr error
		wantWaitParam   string
		serverDelay     time.Duration
		contextTimeout  time.Duration
	}{
		{
			name:            "ko negative wait",
			waitSeconds:     -1,
			wantErr:         true,
			wantSpecificErr: ErrInvalidWaitSeconds,
		},
		{
			name:            "ko wait exceeds MaxWaitSeconds",
			waitSeconds:     MaxWaitSeconds + 1,
			wantErr:         true,
			wantSpecificErr: ErrInvalidWaitSeconds,
		},
		{
			name:           "ko context cancel",
			waitSeconds:    30,
			serverDelay:    200 * time.Millisecond,
			contextTimeout: 20 * time.Millisecond,
			wantErr:        true,
		},
		{
			name:          "ok wait=0 omits param",
			waitSeconds:   0,
			wantWaitParam: "",
		},
		{
			name:          "ok wait=30 sends param",
			waitSeconds:   30,
			wantWaitParam: "30",
		},
		{
			name:          "ok wait=MaxWaitSeconds accepted",
			waitSeconds:   MaxWaitSeconds,
			wantWaitParam: "59",
		},
		{
			name: "ok syndetect mode omits wait param",
			fields: fields{
				syndetect: true,
			},
			waitSeconds:   30,
			wantWaitParam: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotWaitParam string
			var waitParamPresent bool

			uuidField := "uuid"
			if tt.fields.syndetect {
				uuidField = "id"
			}

			s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				gotWaitParam = req.URL.Query().Get("wait")
				waitParamPresent = req.URL.Query().Has("wait")
				if tt.serverDelay > 0 {
					time.Sleep(tt.serverDelay)
				}
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDValid + `","done":true}`))
			}))
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			if tt.fields.syndetect {
				client.syndetect = true
			}

			ctx := context.Background()
			if tt.contextTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.contextTimeout)
				defer cancel()
			}

			_, err = client.GetResultByUUIDWithWait(ctx, testUUIDValid, tt.waitSeconds)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetResultByUUIDWithWait() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("GetResultByUUIDWithWait() error = %v, want %v", err, tt.wantSpecificErr)
				return
			}
			if err != nil {
				return
			}
			if tt.wantWaitParam == "" {
				if waitParamPresent {
					t.Errorf("expected no 'wait' query param, but got %q", gotWaitParam)
				}
			} else if gotWaitParam != tt.wantWaitParam {
				t.Errorf("'wait' query param = %q, want %q", gotWaitParam, tt.wantWaitParam)
			}
		})
	}
}

func TestWaitSecondsForContext(t *testing.T) {
	t.Run("no deadline returns MaxWaitSeconds", func(t *testing.T) {
		got := waitSecondsForContext(context.Background())
		if got != MaxWaitSeconds {
			t.Errorf("waitSecondsForContext() = %d, want %v", got, MaxWaitSeconds)
		}
	})

	t.Run("long deadline capped at MaxWaitSeconds", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		got := waitSecondsForContext(ctx)
		if got != MaxWaitSeconds {
			t.Errorf("waitSecondsForContext() = %d, want %v", got, MaxWaitSeconds)
		}
	})

	t.Run("short deadline returned as-is", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got := waitSecondsForContext(ctx)
		// Remaining time is ~5 s; allow 1 s of slop for slow CI.
		if got < 4 || got > 5 {
			t.Errorf("waitSecondsForContext() = %d, want ~5", got)
		}
	})

	t.Run("already expired context returns 0", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(5 * time.Millisecond) // ensure expired
		got := waitSecondsForContext(ctx)
		if got != 0 {
			t.Errorf("waitSecondsForContext() = %d, want 0", got)
		}
	})
}

// TestWaitForUUID_DetectMode_UsesWaitParam verifies that waitForUUID sends the
// ?wait= query parameter when in detect mode (not syndetect).
func Test_Client_waitForUUID(t *testing.T) {
	type fields struct {
		syndetect  bool
		neverDone  bool
		rejectWait bool
	}
	type args struct {
		pullTime       time.Duration
		contextTimeout time.Duration
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantErr         bool
		wantSpecificErr error
		wantDone        bool
		wantMinCalls    int
		wantWaitParam   bool
	}{
		{
			name: "ko detect mode timeout",
			fields: fields{
				neverDone: true,
			},
			args: args{
				pullTime:       2 * time.Second,
				contextTimeout: 30 * time.Millisecond,
			},
			wantErr:         true,
			wantSpecificErr: ErrTimeout,
		},
		{
			name: "ok detect mode uses wait param",
			args: args{
				pullTime:       2 * time.Second,
				contextTimeout: 5 * time.Second,
			},
			wantDone:      true,
			wantMinCalls:  2,
			wantWaitParam: true,
		},
		{
			name: "ok syndetect mode no wait param",
			fields: fields{
				syndetect:  true,
				rejectWait: true,
			},
			args: args{
				pullTime:       10 * time.Millisecond,
				contextTimeout: 5 * time.Second,
			},
			wantDone:     true,
			wantMinCalls: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			waitParamSeen := false

			uuidField := "uuid"
			if tt.fields.syndetect {
				uuidField = "id"
			}

			s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				callCount++
				if req.URL.Query().Has("wait") {
					waitParamSeen = true
					if tt.fields.rejectWait {
						rw.WriteHeader(http.StatusBadRequest)
						return
					}
				}
				done := "false"
				if !tt.fields.neverDone && callCount >= 2 {
					done = "true"
				}
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write([]byte(`{"` + uuidField + `":"` + testUUIDValid + `","done":` + done + `}`))
			}))
			defer s.Close()

			client, err := NewClient(s.URL, token, false, nil)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			if tt.fields.syndetect {
				client.syndetect = true
			}

			ctx, cancel := context.WithTimeout(context.Background(), tt.args.contextTimeout)
			defer cancel()

			result, err := client.waitForUUID(ctx, testUUIDValid, tt.args.pullTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("waitForUUID() error = %v, wantErr = %t", err, tt.wantErr)
				return
			}
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("waitForUUID() error = %v, want %v", err, tt.wantSpecificErr)
				return
			}
			if err != nil {
				return
			}
			if result.Done != tt.wantDone {
				t.Errorf("waitForUUID() done = %v, want %v", result.Done, tt.wantDone)
			}
			if tt.wantMinCalls > 0 && callCount < tt.wantMinCalls {
				t.Errorf("waitForUUID() callCount = %d, want >= %d", callCount, tt.wantMinCalls)
			}
			if tt.wantWaitParam && !waitParamSeen {
				t.Error("waitForUUID() expected wait query param in detect mode, got none")
			}
			if !tt.wantWaitParam && waitParamSeen {
				t.Error("waitForUUID() unexpected wait query param")
			}
		})
	}
}
