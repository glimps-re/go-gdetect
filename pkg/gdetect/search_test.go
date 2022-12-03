package gdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestClient_GetResults(t *testing.T) {
	type fields struct {
		Token     string
		transport http.RoundTripper
		Timeout   time.Duration
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
		wantUuids  []string
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
			serverBody: `{"count":2,"submissions":[{"uuid":"50e42d45-d837-4dca-9017-5f02284633be","is_malware":true},{"uuid":"99f59137-ec95-4927-b766-3d905be9d05d","is_malware":false}]}`,
			wantErr:    false,
			wantUuids:  []string{"50e42d45-d837-4dca-9017-5f02284633be", "99f59137-ec95-4927-b766-3d905be9d05d"},
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
				Endpoint:  s.URL,
				Token:     tt.fields.Token,
				transport: tt.fields.transport,
				Timeout:   tt.fields.Timeout,
			}

			gotUuids, err := c.GetResults(tt.args.ctx, tt.args.from, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUuids, tt.wantUuids) {
				t.Errorf("Client.GetResults() = %v, want %v", gotUuids, tt.wantUuids)
			}
		})
	}
}
