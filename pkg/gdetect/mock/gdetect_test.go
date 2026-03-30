package gdetectmock

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

// TestMockImplementsInterfaces verifies that MockGDetectSubmitter implements all required interfaces
func TestMockImplementsInterfaces(t *testing.T) {
	var _ gdetect.GDetectSubmitter = &MockGDetectSubmitter{}
	var _ gdetect.ExtendedGDetectSubmitter = &MockGDetectSubmitter{}
	var _ gdetect.ControllerExtendedGDetectSubmitter = &MockGDetectSubmitter{}
}

// TestGetResultByUUID tests the GetResultByUUID mock method
func TestGetResultByUUID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedResult := gdetect.Result{UUID: "test-uuid", SHA256: "abc123", Malware: true}
		mock := &MockGDetectSubmitter{
			GetResultByUUIDMock: func(ctx context.Context, uuid string) (gdetect.Result, error) {
				if uuid != "test-uuid" {
					t.Errorf("Expected uuid 'test-uuid', got '%s'", uuid)
				}
				return expectedResult, nil
			},
		}

		result, err := mock.GetResultByUUID(context.Background(), "test-uuid")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if result.UUID != expectedResult.UUID {
			t.Errorf("Expected UUID '%s', got '%s'", expectedResult.UUID, result.UUID)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetResultByUUIDMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetResultByUUID(context.Background(), "test-uuid")
	})
}

// TestGetResultByUUIDWithWait tests the GetResultByUUIDWithWait mock method
func TestGetResultByUUIDWithWait(t *testing.T) {
	t.Run("success with wait", func(t *testing.T) {
		expectedResult := gdetect.Result{UUID: "test-uuid", Done: true}
		mock := &MockGDetectSubmitter{
			GetResultByUUIDWithWaitMock: func(ctx context.Context, uuid string, waitSeconds int) (gdetect.Result, error) {
				if uuid != "test-uuid" {
					t.Errorf("expected uuid 'test-uuid', got '%s'", uuid)
				}
				if waitSeconds != 30 {
					t.Errorf("expected waitSeconds=30, got %d", waitSeconds)
				}
				return expectedResult, nil
			},
		}

		result, err := mock.GetResultByUUIDWithWait(context.Background(), "test-uuid", 30)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.UUID != expectedResult.UUID {
			t.Errorf("expected UUID '%s', got '%s'", expectedResult.UUID, result.UUID)
		}
		if !result.Done {
			t.Error("expected Done=true")
		}
	})

	t.Run("returns error from mock", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			GetResultByUUIDWithWaitMock: func(ctx context.Context, uuid string, waitSeconds int) (gdetect.Result, error) {
				return gdetect.Result{}, errors.New("mock error")
			},
		}

		_, err := mock.GetResultByUUIDWithWait(context.Background(), "test-uuid", 10)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "mock error" {
			t.Errorf("expected 'mock error', got '%s'", err.Error())
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetResultByUUIDWithWaitMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetResultByUUIDWithWait(context.Background(), "test-uuid", 30)
	})
}

// TestGetResultBySHA256 tests the GetResultBySHA256 mock method
func TestGetResultBySHA256(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedResult := gdetect.Result{SHA256: "abc123", Malware: false}
		mock := &MockGDetectSubmitter{
			GetResultBySHA256Mock: func(ctx context.Context, sha256 string) (gdetect.Result, error) {
				if sha256 != "abc123" {
					t.Errorf("Expected sha256 'abc123', got '%s'", sha256)
				}
				return expectedResult, nil
			},
		}

		result, err := mock.GetResultBySHA256(context.Background(), "abc123")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if result.SHA256 != expectedResult.SHA256 {
			t.Errorf("Expected SHA256 '%s', got '%s'", expectedResult.SHA256, result.SHA256)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetResultBySHA256Mock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetResultBySHA256(context.Background(), "abc123")
	})
}

// TestGetResults tests the GetResults mock method
func TestGetResults(t *testing.T) {
	t.Run("success with tags", func(t *testing.T) {
		expectedSubmissions := []gdetect.Submission{
			{UUID: "uuid1", Filename: "file1.exe"},
			{UUID: "uuid2", Filename: "file2.exe"},
		}
		mock := &MockGDetectSubmitter{
			GetResultsMock: func(ctx context.Context, from int, size int, tags ...string) ([]gdetect.Submission, error) {
				if from != 0 {
					t.Errorf("Expected from=0, got %d", from)
				}
				if size != 10 {
					t.Errorf("Expected size=10, got %d", size)
				}
				if len(tags) != 2 || tags[0] != "tag1" || tags[1] != "tag2" {
					t.Errorf("Expected tags [tag1, tag2], got %v", tags)
				}
				return expectedSubmissions, nil
			},
		}

		results, err := mock.GetResults(context.Background(), 0, 10, "tag1", "tag2")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if len(results) != 2 {
			t.Errorf("Expected 2 results, got %d", len(results))
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetResultsMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetResults(context.Background(), 0, 10)
	})
}

// TestSubmitFile tests the SubmitFile mock method
func TestSubmitFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			SubmitFileMock: func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (string, error) {
				if filepath != "/path/to/file" {
					t.Errorf("Expected filepath '/path/to/file', got '%s'", filepath)
				}
				if len(options.Tags) != 1 || options.Tags[0] != "test" {
					t.Errorf("Expected tags [test], got %v", options.Tags)
				}
				return "submitted-uuid", nil
			},
		}

		uuid, err := mock.SubmitFile(context.Background(), "/path/to/file", gdetect.SubmitOptions{Tags: []string{"test"}})
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if uuid != "submitted-uuid" {
			t.Errorf("Expected uuid 'submitted-uuid', got '%s'", uuid)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when SubmitFileMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.SubmitFile(context.Background(), "/path/to/file", gdetect.SubmitOptions{})
	})
}

// TestSubmitReader tests the SubmitReader mock method
func TestSubmitReader(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			SubmitReaderMock: func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (string, error) {
				if options.Filename != "test.exe" {
					t.Errorf("Expected filename 'test.exe', got '%s'", options.Filename)
				}
				return "reader-uuid", nil
			},
		}

		reader := strings.NewReader("test data")
		uuid, err := mock.SubmitReader(context.Background(), reader, gdetect.SubmitOptions{Filename: "test.exe"})
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if uuid != "reader-uuid" {
			t.Errorf("Expected uuid 'reader-uuid', got '%s'", uuid)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when SubmitReaderMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.SubmitReader(context.Background(), strings.NewReader("test"), gdetect.SubmitOptions{})
	})
}

// TestWaitForFile tests the WaitForFile mock method
func TestWaitForFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedResult := gdetect.Result{UUID: "wait-uuid", Done: true, Malware: true}
		mock := &MockGDetectSubmitter{
			WaitForFileMock: func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (gdetect.Result, error) {
				if filepath != "/path/to/malware" {
					t.Errorf("Expected filepath '/path/to/malware', got '%s'", filepath)
				}
				if options.PullTime != 5 {
					t.Errorf("Expected pull time 5, got %d", options.PullTime)
				}
				return expectedResult, nil
			},
		}

		result, err := mock.WaitForFile(context.Background(), "/path/to/malware", gdetect.WaitForOptions{PullTime: 5})
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if !result.Done {
			t.Error("Expected result to be done")
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when WaitForFileMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.WaitForFile(context.Background(), "/path/to/file", gdetect.WaitForOptions{})
	})
}

// TestWaitForReader tests the WaitForReader mock method
func TestWaitForReader(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedResult := gdetect.Result{UUID: "reader-wait-uuid", Done: true}
		mock := &MockGDetectSubmitter{
			WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (gdetect.Result, error) {
				if options.Filename != "stream.bin" {
					t.Errorf("Expected filename 'stream.bin', got '%s'", options.Filename)
				}
				return expectedResult, nil
			},
		}

		reader := strings.NewReader("binary data")
		result, err := mock.WaitForReader(context.Background(), reader, gdetect.WaitForOptions{
			SubmitOptions: gdetect.SubmitOptions{
				Filename: "stream.bin",
			},
		})
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if result.UUID != "reader-wait-uuid" {
			t.Errorf("Expected UUID 'reader-wait-uuid', got '%s'", result.UUID)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when WaitForReaderMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.WaitForReader(context.Background(), strings.NewReader("test"), gdetect.WaitForOptions{})
	})
}

// TestExtractTokenViewURL tests the ExtractTokenViewURL mock method
func TestExtractTokenViewURL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			ExtractTokenViewURLMock: func(result *gdetect.Result) (string, error) {
				if result.UUID != "url-uuid" {
					t.Errorf("Expected UUID 'url-uuid', got '%s'", result.UUID)
				}
				return "https://example.com/token/view", nil
			},
		}

		result := &gdetect.Result{UUID: "url-uuid"}
		url, err := mock.ExtractTokenViewURL(result)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if url != "https://example.com/token/view" {
			t.Errorf("Expected URL 'https://example.com/token/view', got '%s'", url)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when ExtractTokenViewURLMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.ExtractTokenViewURL(&gdetect.Result{})
	})
}

// TestExtractExpertViewURL tests the ExtractExpertViewURL mock method
func TestExtractExpertViewURL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			ExtractExpertViewURLMock: func(result *gdetect.Result) (string, error) {
				if result.UUID != "expert-uuid" {
					t.Errorf("Expected UUID 'expert-uuid', got '%s'", result.UUID)
				}
				return "https://example.com/expert/view", nil
			},
		}

		result := &gdetect.Result{UUID: "expert-uuid"}
		url, err := mock.ExtractExpertViewURL(result)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if url != "https://example.com/expert/view" {
			t.Errorf("Expected URL 'https://example.com/expert/view', got '%s'", url)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when ExtractExpertViewURLMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.ExtractExpertViewURL(&gdetect.Result{})
	})
}

// TestGetFullSubmissionByUUID tests the GetFullSubmissionByUUID mock method
func TestGetFullSubmissionByUUID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedData := map[string]any{"uuid": "full-uuid", "details": "full analysis"}
		mock := &MockGDetectSubmitter{
			GetFullSubmissionByUUIDMock: func(ctx context.Context, uuid string) (any, error) {
				if uuid != "full-uuid" {
					t.Errorf("Expected uuid 'full-uuid', got '%s'", uuid)
				}
				return expectedData, nil
			},
		}

		result, err := mock.GetFullSubmissionByUUID(context.Background(), "full-uuid")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		data := result.(map[string]any)
		if data["uuid"] != "full-uuid" {
			t.Errorf("Expected uuid 'full-uuid', got '%v'", data["uuid"])
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetFullSubmissionByUUIDMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetFullSubmissionByUUID(context.Background(), "uuid")
	})
}

// TestGetProfileStatus tests the GetProfileStatus mock method
func TestGetProfileStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedStatus := gdetect.ProfileStatus{DailyQuota: 1000, AvailableDailyQuota: 500}
		mock := &MockGDetectSubmitter{
			GetProfileStatusMock: func(ctx context.Context) (gdetect.ProfileStatus, error) {
				return expectedStatus, nil
			},
		}

		status, err := mock.GetProfileStatus(context.Background())
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if status.DailyQuota != 1000 {
			t.Errorf("Expected daily quota 1000, got %d", status.DailyQuota)
		}
		if status.AvailableDailyQuota != 500 {
			t.Errorf("Expected available quota 500, got %d", status.AvailableDailyQuota)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetProfileStatusMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetProfileStatus(context.Background())
	})
}

// TestGetAPIVersion tests the GetAPIVersion mock method
func TestGetAPIVersion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			GetAPIVersionMock: func(ctx context.Context) (string, error) {
				return "v2.0.0", nil
			},
		}

		version, err := mock.GetAPIVersion(context.Background())
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if version != "v2.0.0" {
			t.Errorf("Expected version 'v2.0.0', got '%s'", version)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when GetAPIVersionMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.GetAPIVersion(context.Background())
	})
}

// TestExportResult tests the ExportResult mock method
func TestExportResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			ExportResultMock: func(ctx context.Context, uuid string, options gdetect.ExportOptions) ([]byte, error) {
				if uuid != "test-uuid" {
					t.Errorf("Expected uuid 'test-uuid', got '%s'", uuid)
				}
				if options.Format != gdetect.ExportFormatJSON {
					t.Errorf("Expected format JSON, got '%s'", options.Format)
				}
				if options.Layout != gdetect.ExportLayoutEN {
					t.Errorf("Expected layout EN, got '%s'", options.Layout)
				}
				if options.Full {
					t.Error("Expected full=false")
				}
				return []byte(`{"test":"data"}`), nil
			},
		}

		data, err := mock.ExportResult(context.Background(), "test-uuid", gdetect.ExportOptions{
			Format: gdetect.ExportFormatJSON,
			Layout: gdetect.ExportLayoutEN,
			Full:   false,
		})
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if string(data) != `{"test":"data"}` {
			t.Errorf("Expected data '{\"test\":\"data\"}', got '%s'", string(data))
		}
	})

	t.Run("all export formats", func(t *testing.T) {
		formats := []gdetect.ExportFormat{
			gdetect.ExportFormatMISP,
			gdetect.ExportFormatSTIX,
			gdetect.ExportFormatJSON,
			gdetect.ExportFormatPDF,
			gdetect.ExportFormatMarkdown,
			gdetect.ExportFormatCSV,
		}

		for _, format := range formats {
			mock := &MockGDetectSubmitter{
				ExportResultMock: func(ctx context.Context, uuid string, options gdetect.ExportOptions) ([]byte, error) {
					return []byte("export data for " + string(options.Format)), nil
				},
			}

			data, err := mock.ExportResult(context.Background(), "uuid", gdetect.ExportOptions{
				Format: format,
				Layout: gdetect.ExportLayoutEN,
			})
			if err != nil {
				t.Errorf("Format %s: expected no error, got: %v", format, err)
			}
			if len(data) == 0 {
				t.Errorf("Format %s: expected data, got empty", format)
			}
		}
	})

	t.Run("error handling", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			ExportResultMock: func(ctx context.Context, uuid string, options gdetect.ExportOptions) ([]byte, error) {
				return nil, errors.New("export failed")
			},
		}

		_, err := mock.ExportResult(context.Background(), "uuid", gdetect.ExportOptions{})
		if err == nil {
			t.Error("Expected error, got nil")
		}
		if err.Error() != "export failed" {
			t.Errorf("Expected error 'export failed', got '%s'", err.Error())
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when ExportResultMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_, _ = mock.ExportResult(context.Background(), "test-uuid", gdetect.ExportOptions{})
	})
}

// TestReconfigure tests the Reconfigure mock method
func TestReconfigure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &MockGDetectSubmitter{
			ReconfigureMock: func(ctx context.Context, config gdetect.ClientConfig) error {
				if config.Endpoint != "https://new-endpoint.com" {
					t.Errorf("Expected endpoint 'https://new-endpoint.com', got '%s'", config.Endpoint)
				}
				if config.Token != "new-token" {
					t.Errorf("Expected token 'new-token', got '%s'", config.Token)
				}
				if config.Insecure {
					t.Error("Expected insecure=false")
				}
				if config.Syndetect {
					t.Error("Expected syndetect=false")
				}
				return nil
			},
		}

		err := mock.Reconfigure(t.Context(), gdetect.ClientConfig{Endpoint: "https://new-endpoint.com", Token: "new-token"})
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
	})

	t.Run("panic when not implemented", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when ReconfigureMock is not set")
			}
		}()

		mock := &MockGDetectSubmitter{}
		_ = mock.Reconfigure(t.Context(), gdetect.ClientConfig{})
	})
}
