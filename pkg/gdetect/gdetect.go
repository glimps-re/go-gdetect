// Package gdetect provides implements utility functions to interact with GLIMPS'
// detect API.
//
// The gdetect package should only be used to intercat with detect API.
// Package path implements utility routines for manipulating slash-separated
// paths.
package gdetect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Generic gdetect client errors.
var (
	ErrTimeout  = fmt.Errorf("timeout")
	ErrBadToken = fmt.Errorf("bad token")
	ErrNoToken  = fmt.Errorf("no token in result")
	ErrNoSID    = fmt.Errorf("no sid in result")
)

type GDetectSubmitter interface {
	GetResultByUUID(ctx context.Context, uuid string) (result Result, err error)
	GetResultBySHA256(ctx context.Context, sha256 string) (result Result, err error)
	GetResults(ctx context.Context, from int, size int, tags ...string) (uuids []string, err error)
	SubmitFile(ctx context.Context, filepath string, options SubmitOptions) (uuid string, err error)
	WaitForFile(ctx context.Context, filepath string, options WaitForOptions) (result Result, err error)
}

var _ GDetectSubmitter = &Client{}

// Client is the representation of a Detect API CLient.
type Client struct {
	Endpoint  string
	Token     string
	transport http.RoundTripper
	Timeout   time.Duration
}

// Result represent typical json result from Detect API operations like get or
// search. It maps elements from the json result to fields.
type Result struct {
	UUID      string            `json:"uuid"`
	SHA256    string            `json:"sha256"`
	SHA1      string            `json:"sha1"`
	MD5       string            `json:"md5"`
	SSDeep    string            `json:"ssdeep"`
	Malware   bool              `json:"is_malware"`
	Score     int               `json:"score"`
	Done      bool              `json:"done"`
	Timestamp int64             `json:"timestamp"`
	Errors    map[string]string `json:"errors,omitempty"`
	Error     string            `json:"error,omitempty"`
	FileType  string            `json:"filetype"`
	FileSize  int64             `json:"size"`
	Filenames []string          `json:"filenames,omitempty"`
	Malwares  []string          `json:"malwares,omitempty"`
	Files     []FileResult      `json:"files,omitempty"`
	SID       string            `json:"sid,omitempty"`
	Comment   string            `json:"comment,omitempty"`
	FileCount int               `json:"file_count"`
	Duration  int64             `json:"duration"`
	Token     string            `json:"token,omitempty"`
	Threats   map[string]Threat `json:"threats,omitempty"`
}

// Threat part of an analysis result
type Threat struct {
	Filenames []string `json:"filenames"`
	Tags      []Tag    `json:"tags"`
	Score     int      `json:"score"`
	Magic     string   `json:"magic"`
	SHA256    string   `json:"sha256"`
	SHA1      string   `json:"sha1"`
	MD5       string   `json:"md5"`
	SSDeep    string   `json:"ssdeep"`
	FileSize  int64    `json:"file_size"`
	Mime      string   `json:"mime"`
}

// Tag part for Threat
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FileResult represents results for a file in an analysis result
type FileResult struct {
	SHA256    string     `json:"sha256"`
	SHA1      string     `json:"sha1"`
	MD5       string     `json:"md5"`
	SSDeep    string     `json:"ssdeep"`
	Magic     string     `json:"magic"`
	AVResults []AvResult `json:"av_results,omitempty"`
	Size      int64      `json:"size"`
	IsMalware bool       `json:"is_malware"`
}

// AvResult represents antivirus results from an analysis result
type AvResult struct {
	AVName string `json:"av"`
	Result string `json:"result"`
	Score  int    `json:"score"`
}

// Options for SubmitFile method
type SubmitOptions struct {
	Tags        []string
	Description string
	BypassCache bool
	Filename    string
}

// Options for WaitForFile method
type WaitForOptions struct {
	Tags        []string
	Description string
	BypassCache bool
	Timeout     time.Duration
	PullTime    time.Duration
}

// Default timeout for gdetect client
var DefaultTimeout = time.Minute * 5

// NewClient returns a fresh client, given endpoint token and insecure params.
// The returned client could be used to perform operations on gdetect.
//
// If Client is well-formed, it returns error == nil. If error != nil, that
// could mean that Token is invalid (by its length for example).
func NewClient(endpoint, token string, insecure bool) (client *Client, err error) {
	err = checkToken(token)
	if err != nil {
		return
	}

	client = &Client{
		Endpoint:  endpoint,
		Token:     token,
		Timeout:   DefaultTimeout,
		transport: http.DefaultTransport,
	}
	if insecure {
		client.transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return
}

func checkToken(token string) (err error) {
	if !regexp.MustCompile(`^[a-f0-9-]{44}$`).MatchString(token) {
		err = ErrBadToken
		return
	}
	return
}

func (c *Client) prepareRequest(ctx context.Context, method string, path string, body io.Reader) (request *http.Request, err error) {
	var u url.URL

	urlTmp, err := url.Parse(c.Endpoint)
	if err != nil {
		return
	}

	u.Host = urlTmp.Host
	u.Scheme = urlTmp.Scheme
	u.Path = path
	request, err = http.NewRequestWithContext(ctx, method, u.String(), body)
	return
}

func (c *Client) prepareClient(request *http.Request) (client *http.Client) {
	if c.Token != "" {
		request.Header.Add("X-Auth-Token", c.Token)
	}
	client = &http.Client{Transport: c.transport, Timeout: c.Timeout}
	return
}

type HTTPError struct {
	Status string
	Code   int
	Body   string
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("invalid response from endpoint, %s: %s", e.Status, e.Body)
}

func NewHTTPError(r *http.Response, body string) HTTPError {
	return HTTPError{
		Status: r.Status,
		Code:   r.StatusCode,
		Body:   body,
	}
}

// GetResultByUUID retrieves result using results endpoint on Detect API with
// given UUID.
func (c *Client) GetResultByUUID(ctx context.Context, uuid string) (result Result, err error) {
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/results/"+uuid, nil)
	if err != nil {
		return
	}

	client := c.prepareClient(request)

	resp, err := client.Do(request)
	if err != nil {
		return
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &result)
	if err != nil {
		err = fmt.Errorf("error unmarshaling response json, %s", err)
		return
	}

	return
}

// GetResultBySHA256 search for an analysis using search endpoint on Detect API with
// given file SHA256.
func (c *Client) GetResultBySHA256(ctx context.Context, sha256 string) (result Result, err error) {
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/search/"+sha256, nil)
	if err != nil {
		return
	}

	client := c.prepareClient(request)

	resp, err := client.Do(request)
	if err != nil {
		return
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &result)
	if err != nil {
		err = fmt.Errorf("error unmarshaling response json, %s", err)
		return
	}

	return
}

// SubmitFile method submit a file to Detect API. The file is described by its
// path and it's possible to provides some params to be submitted with the file.
func (c *Client) SubmitFile(ctx context.Context, filepath string, submitOptions SubmitOptions) (uuid string, err error) {

	// Struct corresponding to submit json result
	type responseT struct {
		Status bool   `json:"status"`
		UUID   string `json:"uuid,omitempty"`
		Error  string `json:"error,omitempty"`
	}

	var (
		part     io.Writer
		response responseT
		resp     *http.Response
	)

	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	if file == nil {
		err = fmt.Errorf("invalid file")
		return
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create form-data header with given filename
	name := file.Name()
	if submitOptions.Filename != "" {
		name = submitOptions.Filename
	}
	part, err = writer.CreateFormFile("file", name)

	if err != nil {
		return
	}

	// Copy file content
	_, err = io.Copy(part, file)
	if err != nil {
		return
	}

	// Submit file even if it exists in db
	if submitOptions.BypassCache {
		part, err = writer.CreateFormField("bypass-cache")
		if err != nil {
			return
		}
		_, err = part.Write([]byte("true"))
		if err != nil {
			return
		}
	}

	// Add description if filled in
	if submitOptions.Description != "" {
		part, err = writer.CreateFormField("description")
		if err != nil {
			return
		}
		_, err = part.Write([]byte(submitOptions.Description))
		if err != nil {
			return
		}
	}

	// Add all tags if filled in
	if len(submitOptions.Tags) > 0 {
		part, err = writer.CreateFormField("tags")
		if err != nil {
			return
		}

		_, err = part.Write([]byte(strings.Join(submitOptions.Tags, ",")))
		if err != nil {
			return
		}
	}

	writer.Close()

	// Post file to API
	request, err := c.prepareRequest(ctx, "POST", "/api/lite/v2/submit", body)
	if err != nil {
		return
	}
	request.Header.Add("Content-Type", writer.FormDataContentType())

	client := c.prepareClient(request)

	resp, err = client.Do(request)
	if err != nil {
		return
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &response)
	if err != nil {
		err = fmt.Errorf("error unmarshaling response json, %s", err)
		return
	}

	if !response.Status {
		err = fmt.Errorf("%s", response.Error)
		return
	}
	uuid = response.UUID
	return
}

// WaitForFile method submit a file, using SubmitFile method, and try to get
// analysis results using GetResultByUUID method.
func (c *Client) WaitForFile(ctx context.Context, filepath string, waitOptions WaitForOptions) (result Result, err error) {
	timeout := time.Second * 180
	if waitOptions.Timeout != 0*time.Second {
		timeout = waitOptions.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Submit file
	submitOptions := SubmitOptions{
		Tags:        waitOptions.Tags,
		Description: waitOptions.Description,
		BypassCache: waitOptions.BypassCache,
	}
	uuid, err := c.SubmitFile(ctx, filepath, submitOptions)
	if err != nil {
		return
	}

	// Ticker to perform get every n seconds
	pullTime := time.Second * 2
	if waitOptions.PullTime != 0*time.Second {
		pullTime = waitOptions.PullTime
	}
	ticker := time.NewTicker(pullTime)

	for {
		select {
		case <-ticker.C:
			result, err = c.GetResultByUUID(ctx, uuid)
			if err != nil {
				return
			}
			if result.Done {
				return
			}
		case <-ctx.Done():
			err = ErrTimeout
			return
		}
	}
}

// Extract URL token view from given result, use client to retrieve API base endpoint
func (c *Client) ExtractTokenViewURL(result *Result) (urlTokenView string, err error) {
	token := result.Token
	if token == "" {
		err = ErrNoToken
		return
	}
	urlTokenView = c.Endpoint + "/expert/en/analysis-redirect/" + token
	return
}

// Extract URL analysis expert view from given result, use client to retrieve API base endpoint
func (c *Client) ExtractExpertViewURL(result *Result) (urlExpertView string, err error) {
	sid := result.SID
	if sid == "" {
		err = ErrNoSID
		return
	}
	urlExpertView = c.Endpoint + "/expert/en/analysis/advanced/" + sid
	return
}

// GetFullSubmissionByUUID retrieves fullsubmission using results full endpoint
// on Detect API with given UUID.
func (c *Client) GetFullSubmissionByUUID(ctx context.Context, uuid string) (result interface{}, err error) {
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/results/"+uuid+"/full", nil)
	if err != nil {
		return
	}

	client := c.prepareClient(request)

	resp, err := client.Do(request)
	if err != nil {
		return
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &result)
	if err != nil {
		err = fmt.Errorf("error unmarshaling response json, %s", err)
		return
	}

	return
}
