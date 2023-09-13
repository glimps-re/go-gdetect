package gdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestClient_GetResults(t *testing.T) {
	type fields struct {
		Token string
	}
	type args struct {
		ctx  context.Context
		from int
		size int
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		serverCode int
		serverBody string
		wantSubs   []Submission
		wantErr    bool
	}{
		{
			name:    "empty",
			wantErr: true,
		},
		{
			name: "server returns 500",
			fields: fields{
				Token: token,
			},
			args: args{
				ctx: context.Background(),
			},
			serverCode: http.StatusInternalServerError,
			serverBody: `internal server error`,
			wantErr:    true,
		},
		{
			name: "server returns 404",
			fields: fields{
				Token: token,
			},
			args: args{
				ctx: context.Background(),
			},
			serverCode: http.StatusNotFound,
			serverBody: `{"status":false,"error":"not found"}`,
			wantErr:    false,
		},
		{
			name: "server returns unexpected results",
			fields: fields{
				Token: token,
			},
			args: args{
				ctx: context.Background(),
			},
			serverCode: http.StatusOK,
			serverBody: `{"count": invalid json`,
			wantErr:    true,
		},
		{
			name: "server returns results",
			fields: fields{
				Token: token,
			},
			args: args{
				ctx: context.Background(),
			},
			serverCode: http.StatusOK,
			serverBody: `{"count":2,"submissions":[{"uuid":"50e42d45-d837-4dca-9017-5f02284633be","is_malware":true,"done":true,"error":false,"filename":"","date":1200,"file_size":18,"file_type":"exe","score":1280,"malwares":["test_m2"]},{"uuid":"99f59137-ec95-4927-b766-3d905be9d05d","is_malware":false,"done":false,"error":false,"filename":"","date":1239,"file_size":17,"file_type":"text","score":127,"malwares":[]}]}`,
			wantErr:    false,
			wantSubs: []Submission{
				{UUID: "50e42d45-d837-4dca-9017-5f02284633be", Malware: true, Done: true, Score: 1280, FileSize: 18, FileType: "exe", Date: 1200, Malwares: []string{"test_m2"}},
				{UUID: "99f59137-ec95-4927-b766-3d905be9d05d", Malware: false, Done: false, Score: 127, FileSize: 17, FileType: "text", Date: 1239, Malwares: []string{}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.Header.Get("X-Auth-Token") != tt.fields.Token {
						t.Errorf("handler.SubmitFile() %v error = unexpected TOKEN: %v", tt.name, req.Header.Get("X-Auth-Token"))
					}
					rw.WriteHeader(tt.serverCode)
					rw.Write([]byte(tt.serverBody))
				}),
			)
			defer s.Close()
			c := &Client{
				Endpoint:   s.URL,
				Token:      tt.fields.Token,
				HttpClient: http.DefaultClient,
			}

			gotUuids, err := c.GetResults(tt.args.ctx, tt.args.from, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUuids, tt.wantSubs) {
				t.Errorf("Client.GetResults() = %v, want %v", gotUuids, tt.wantSubs)
			}
		})
	}
}
