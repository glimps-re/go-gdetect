package gdetect_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

// exampleToken is a valid token for use in examples (UUID format required by the API).
const exampleToken = "abcdef01-23456789-abcdef01-23456789-abcdef01"

// ExampleNewClientFromConfig demonstrates creating a Client using ClientConfig.
func ExampleNewClientFromConfig() {
	client, err := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint: "https://my.gdetect.example.com",
		Token:    exampleToken,
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("client created:", client.Endpoint)
	// Output: client created: https://my.gdetect.example.com
}

// ExampleClient_GetResultByUUID demonstrates retrieving an analysis result by UUID.
func ExampleClient_GetResultByUUID() {
	const analysisUUID = "ab000001-0000-0000-0000-000000000001"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, analysisUUID) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		payload := map[string]any{
			"uuid":       analysisUUID,
			"sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"is_malware": false,
			"done":       true,
			"score":      0,
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	client, _ := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint:   srv.URL,
		Token:      exampleToken,
		HTTPClient: srv.Client(),
	})

	result, err := client.GetResultByUUID(context.Background(), analysisUUID)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("done=%v malware=%v\n", result.Done, result.Malware)
	// Output: done=true malware=false
}

// ExampleClient_GetResultBySHA256 demonstrates searching for a previous analysis by SHA256.
func ExampleClient_GetResultBySHA256() {
	const fileSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]any{
			"uuid":       "ab000001-0000-0000-0000-000000000001",
			"sha256":     fileSHA256,
			"is_malware": false,
			"done":       true,
			"score":      0,
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	client, _ := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint:   srv.URL,
		Token:      exampleToken,
		HTTPClient: srv.Client(),
	})

	result, err := client.GetResultBySHA256(context.Background(), fileSHA256)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("sha256=%v done=%v\n", result.SHA256, result.Done)
	// Output: sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 done=true
}

// ExampleClient_SubmitFile demonstrates submitting a local file for analysis.
// In real usage filePath points to an actual file on disk.
func ExampleClient_SubmitFile() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": true,
			"uuid":   "ab000001-0000-0000-0000-000000000001",
		})
	}))
	defer srv.Close()

	client, _ := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint:   srv.URL,
		Token:      exampleToken,
		HTTPClient: srv.Client(),
	})

	uuid, err := client.SubmitFile(context.Background(), "../../tests/samples/false_mirai",
		gdetect.SubmitOptions{Tags: []string{"example"}})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("submitted:", uuid)
	// Output: submitted: ab000001-0000-0000-0000-000000000001
}

// ExampleClient_GetProfileStatus demonstrates retrieving profile quota information.
func ExampleClient_GetProfileStatus() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := gdetect.ProfileStatus{
			DailyQuota:                100,
			AvailableDailyQuota:       87,
			Cache:                     true,
			EstimatedAnalysisDuration: 2000,
			MalwareThreshold:          1000,
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	client, _ := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint:   srv.URL,
		Token:      exampleToken,
		HTTPClient: srv.Client(),
	})

	status, err := client.GetProfileStatus(context.Background())
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("quota=%d available=%d threshold=%d\n",
		status.DailyQuota, status.AvailableDailyQuota, status.MalwareThreshold)
	// Output: quota=100 available=87 threshold=1000
}

// ExampleClient_ExportResult demonstrates exporting an analysis result as JSON.
func ExampleClient_ExportResult() {
	const analysisUUID = "ab000001-0000-0000-0000-000000000001"
	const exportBody = `{"Verdict":"safe"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, exportBody); err != nil {
			http.Error(w, "write error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	client, _ := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint:   srv.URL,
		Token:      exampleToken,
		HTTPClient: srv.Client(),
	})

	data, err := client.ExportResult(context.Background(), analysisUUID, gdetect.ExportOptions{
		Format: gdetect.ExportFormatJSON,
		Layout: gdetect.ExportLayoutEN,
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(string(data))
	// Output: {"Verdict":"safe"}
}

// ExampleClient_WaitForFile demonstrates submitting a file and waiting for completion.
// The example uses a test server that completes the analysis on the second poll.
func ExampleClient_WaitForFile() {
	// callCount tracks how many GET requests have been made.
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": true,
				"uuid":   "ab000001-0000-0000-0000-000000000001",
			})
		case http.MethodGet:
			callCount++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uuid":       "ab000001-0000-0000-0000-000000000001",
				"sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"is_malware": false,
				"done":       callCount >= 2,
				"score":      0,
			})
		}
	}))
	defer srv.Close()

	client, _ := gdetect.NewClientFromConfig(gdetect.ClientConfig{
		Endpoint:   srv.URL,
		Token:      exampleToken,
		HTTPClient: srv.Client(),
	})

	result, err := client.WaitForFile(context.Background(), "../../tests/samples/false_mirai",
		gdetect.WaitForOptions{
			BypassCache: true,
			PullTime:    50 * time.Millisecond,
		})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("done=%v malware=%v\n", result.Done, result.Malware)
	// Output: done=true malware=false
}
