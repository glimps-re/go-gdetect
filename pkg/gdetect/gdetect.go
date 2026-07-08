// Package gdetect provides utility functions for interacting with the GLIMPS
// Detect and SynDetect malware analysis APIs.
//
// It supports file submission, result retrieval by UUID or SHA256, waiting for
// analysis completion, status queries, and result export. Both the standard
// Detect API and the limited SynDetect API variant are supported.
package gdetect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-semver/semver"
)

var (
	// ErrTimeout indicates that an operation exceeded its configured timeout.
	ErrTimeout = errors.New("timeout")
	// ErrBadToken indicates that the token failed format validation.
	ErrBadToken = errors.New("bad token")
	// ErrNoToken indicates that a Result has no token field.
	ErrNoToken = errors.New("no token in result")
	// ErrNoSID indicates that a Result has no SID field.
	ErrNoSID = errors.New("no sid in result")
	// ErrNotAvailable indicates that the called method is not supported
	// in the currently active API mode (e.g., calling ExportResult in SynDetect mode).
	ErrNotAvailable = errors.New("this feature is not available")
	// ErrInvalidWaitSeconds indicates that a waitSeconds parameter has an invalid value.
	ErrInvalidWaitSeconds = errors.New("waitSeconds must be between 0 and MaxWaitSeconds")
	// ErrInvalidUUID indicates that a UUID parameter failed format validation.
	ErrInvalidUUID = errors.New("invalid UUID format")
	// ErrInvalidSHA256 indicates that a SHA256 parameter failed format validation.
	ErrInvalidSHA256 = errors.New("invalid SHA256 format")
	// ErrPathNotFound indicates that an API path key is missing from the path maps.
	ErrPathNotFound = errors.New("path not found")
)

// MaxWaitSeconds is the maximum allowed value for the server-side wait parameter
// on the /results/{UUID} endpoint. The server will hold the connection open for
// at most this many seconds waiting for the analysis to complete.
const MaxWaitSeconds = 59

// maxResponseSize caps the amount of data read from API responses to prevent
// memory exhaustion from a malicious or compromised server (50 MB).
const maxResponseSize = 50 * 1024 * 1024

// reValidToken matches the API token format (40 hex chars in 5 groups of 8).
var reValidToken = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{8}-[a-f0-9]{8}-[a-f0-9]{8}-[a-f0-9]{8}$`)

// reValidUUID matches a standard UUID format (8-4-4-4-12 hex chars).
var reValidUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// reValidSHA256 matches a valid SHA256 hex string (64 lowercase hex chars).
var reValidSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Logger is the structured logger used by the package for diagnostic output.
// It defaults to WARN level on stderr; callers may replace it with their own
// slog.Logger before creating any Client.
var Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

// FeatureNotAvailableError indicates that a required Detect API feature
// is not present in the server version reported by the endpoint.
type FeatureNotAvailableError struct {
	// Version is the API version string returned by the server.
	Version string
}

func (e FeatureNotAvailableError) Error() string {
	return "feature not available, API version: " + e.Version
}

// GDetectSubmitter is the base interface for interacting with the GLIMPS Detect API.
// It covers the most common operations: submitting files, retrieving results, and
// querying profile status.
type GDetectSubmitter interface {
	GetResultByUUID(ctx context.Context, uuid string) (result Result, err error)
	GetResultByUUIDWithWait(ctx context.Context, uuid string, waitSeconds int) (result Result, err error)
	GetResultBySHA256(ctx context.Context, sha256 string) (result Result, err error)
	GetResults(ctx context.Context, from int, size int, tags ...string) (submissions []Submission, err error)
	SubmitFile(ctx context.Context, filepath string, options SubmitOptions) (uuid string, err error)
	SubmitReader(ctx context.Context, r io.Reader, options SubmitOptions) (uuid string, err error)
	WaitForFile(ctx context.Context, filepath string, options WaitForOptions) (result Result, err error)
	WaitForReader(ctx context.Context, r io.Reader, options WaitForOptions) (result Result, err error)
	GetProfileStatus(ctx context.Context) (status ProfileStatus, err error)
	GetAPIVersion(ctx context.Context) (version string, err error)
	ExportResult(ctx context.Context, uuid string, options ExportOptions) (data []byte, err error)
}

// ExtendedGDetectSubmitter extends GDetectSubmitter with methods that return
// richer analysis data: full submissions, and URL extraction for the Expert View.
type ExtendedGDetectSubmitter interface {
	GDetectSubmitter
	ExtractTokenViewURL(result *Result) (urlTokenView string, err error)
	ExtractExpertViewURL(result *Result) (urlExpertView string, err error)
	GetFullSubmissionByUUID(ctx context.Context, uuid string) (result any, err error)
}

// ControllerSubmitter provides runtime reconfiguration of the client.
type ControllerSubmitter interface {
	Reconfigure(ctx context.Context, config ClientConfig) (err error)
}

// ControllerGDetectSubmitter combines GDetectSubmitter with ControllerSubmitter,
// enabling both analysis operations and runtime reconfiguration.
type ControllerGDetectSubmitter interface {
	GDetectSubmitter
	ControllerSubmitter
}

// ControllerExtendedGdetectSubmitter combines ExtendedGDetectSubmitter with
// ControllerSubmitter. Deprecated: use ControllerExtendedGDetectSubmitter instead.
type ControllerExtendedGdetectSubmitter = ControllerExtendedGDetectSubmitter

// ControllerExtendedGDetectSubmitter combines ExtendedGDetectSubmitter with
// ControllerSubmitter, providing both full analysis capabilities and runtime
// reconfiguration.
type ControllerExtendedGDetectSubmitter interface {
	ExtendedGDetectSubmitter
	ControllerSubmitter
}

var (
	_ ExtendedGDetectSubmitter           = &Client{}
	_ ControllerExtendedGDetectSubmitter = &Client{}
)

// ClientConfig holds the configuration needed to create or reconfigure a Client.
type ClientConfig struct {
	// Endpoint is the base URL of the GLIMPS Detect or SynDetect API server.
	Endpoint string
	// Token is the API authentication token (must match the UUID format).
	Token string
	// ExpertURL is an optional alternate base URL used for constructing Expert
	// View links. Falls back to Endpoint when empty.
	ExpertURL string
	// Syndetect selects the SynDetect API path set instead of the default Detect paths.
	Syndetect bool
	// HTTPClient is an optional custom HTTP client. When nil, a default client
	// with DefaultTimeout is created; Insecure is ignored when this is set.
	HTTPClient *http.Client
	// Insecure disables TLS certificate verification. Only used when HTTPClient is nil.
	Insecure bool
	// MaxIdleConnsPerHost, when > 0, sizes the idle connection pool (both the
	// per-host and the global MaxIdleConns). Only used when HTTPClient is nil.
	// If empty, net/http's DefaultMaxIdleConnsPerHost applies.
	MaxIdleConnsPerHost int
	// TransportWrapper wraps the transport the library builds, letting callers
	// layer instrumentation (e.g. otelhttp) while keeping the managed Insecure/TLS
	// settings. Ignored when HTTPClient is set.
	TransportWrapper func(http.RoundTripper) http.RoundTripper
}

// Client is the representation of a Detect API Client.
type Client struct {
	lock       *sync.RWMutex
	Endpoint   string
	ExpertURL  string
	Token      string
	HTTPClient *http.Client
	syndetect  bool
}

// Result represent typical json result from Detect API operations like get or
// search. It maps elements from the json result to fields.
type Result struct {
	UUID              string            `json:"uuid"`         // detect only (analysis ID)
	ID                string            `json:"id,omitempty"` // syndetect only (analysis ID)
	SHA256            string            `json:"sha256"`
	SHA1              string            `json:"sha1"`
	MD5               string            `json:"md5"`
	SSDeep            string            `json:"ssdeep"`
	Malware           bool              `json:"is_malware"`
	Score             int               `json:"score"`
	Done              bool              `json:"done"`
	Timestamp         int64             `json:"timestamp"`
	Errors            map[string]string `json:"errors,omitempty"`
	Error             string            `json:"error,omitempty"`
	FileType          string            `json:"filetype"`
	FileSize          int64             `json:"size"`
	Filenames         []string          `json:"filenames,omitempty"`
	Malwares          []string          `json:"malwares,omitempty"`
	Files             []FileResult      `json:"files,omitempty"`
	SID               string            `json:"sid,omitempty"`
	Comment           string            `json:"comment,omitempty"`
	FileCount         int               `json:"file_count"`
	Duration          int64             `json:"duration"`
	Token             string            `json:"token,omitempty"`
	Threats           map[string]Threat `json:"threats,omitempty"`
	SpecialStatusCode int               `json:"special_status_code"`
}

// Threat describes a single malicious file found within an analysis result.
// The Result.Threats map is keyed by each file's SHA256 hash; the value is a
// Threat record containing identification hashes, filenames, AV tags, and the
// score that exceeded the malware threshold for that file.
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

// Tag is a key-value label attached to a Threat, typically carrying AV verdict
// names (e.g., Name="av.virus_name", Value="win_cybergate_auto").
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

// Submission represents a summary entry returned by the GetResults list endpoint.
type Submission struct {
	UUID              string   `json:"uuid"`
	Malware           bool     `json:"is_malware"`
	Done              bool     `json:"done"`
	Error             bool     `json:"error"`
	Filename          string   `json:"filename"`
	Date              int64    `json:"date"`
	FileSize          int64    `json:"file_size"`
	FileType          string   `json:"file_type"`
	Score             int      `json:"score"`
	Malwares          []string `json:"malwares"`
	SpecialStatusCode int      `json:"special_status_code"`
}

// SubmitOptions holds optional parameters for file submission.
type SubmitOptions struct {
	Tags            []string
	Description     string
	BypassCache     bool
	Filename        string
	ArchivePassword string
	// Dynamic selects the profile dynamic analysis services.
	// When true, the submit request includes the "dynamic=true" query parameter.
	// This option is forced to true server-side when the profile has force_dynamic enabled.
	Dynamic bool
}

// WaitForOptions holds optional parameters for wait-based submission.
type WaitForOptions struct {
	SubmitOptions
	// Timeout controls the maximum duration to wait for analysis completion; it
	// defaults to 180 seconds when zero.
	Timeout time.Duration
	// PullTime sets the polling interval; it defaults to 2 seconds when zero.
	// Only used in SynDetect mode. In Detect mode, the server-side ?wait=
	// long-polling is used instead.
	PullTime time.Duration
}

// ExportFormat represents the export format type
type ExportFormat string

const (
	// ExportFormatMISP exports the analysis result as a MISP event.
	ExportFormatMISP ExportFormat = "misp"
	// ExportFormatSTIX exports the analysis result as a STIX bundle.
	ExportFormatSTIX ExportFormat = "stix"
	// ExportFormatJSON exports the analysis result as a JSON report.
	ExportFormatJSON ExportFormat = "json"
	// ExportFormatPDF exports the analysis result as a PDF report.
	ExportFormatPDF ExportFormat = "pdf"
	// ExportFormatMarkdown exports the analysis result as a Markdown report.
	ExportFormatMarkdown ExportFormat = "markdown"
	// ExportFormatCSV exports the analysis result as a CSV spreadsheet.
	ExportFormatCSV ExportFormat = "csv"
)

// ExportLayout represents the report language layout
type ExportLayout string

const (
	// ExportLayoutFR selects French as the report language.
	ExportLayoutFR ExportLayout = "fr"
	// ExportLayoutEN selects English as the report language.
	ExportLayoutEN ExportLayout = "en"
)

// ExportOptions contains options for ExportResult method
type ExportOptions struct {
	// Format defines the export's format: misp, stix, json, pdf, markdown or csv
	Format ExportFormat
	// Full defines if export must be full analysis or summarized
	Full bool
	// Layout defines the report's language layout: fr or en
	Layout ExportLayout
}

// ProfileStatus contains information about profile status
type ProfileStatus struct {
	// MonthlySubmissionQuota is the amount of submissions allowed in a month (0 means unlimited)
	MonthlySubmissionQuota int `json:"monthly_submission_quota"`
	// MonthlyVolumeQuota is the volume of data in bytes allowed in a month (0 means unlimited)
	MonthlyVolumeQuota int64 `json:"monthly_volume_quota"`
	// ParallelSubmissionQuota is the amount of concurrent submissions allowed (0 means unlimited)
	ParallelSubmissionQuota int `json:"parallel_submission_quota"`
	// AvailableMonthlySubmissions is the amount of submissions currently available for the month
	AvailableMonthlySubmissions int `json:"available_monthly_submissions"`
	// AvailableMonthlyVolume is the volume of data in bytes currently available for the month
	AvailableMonthlyVolume int64 `json:"available_monthly_volume"`
	// AvailableParallel is the amount of concurrent submissions currently available
	AvailableParallel int `json:"available_parallel"`
	// Cache is true if the profile is configured to use detect SHA256 cache
	Cache bool `json:"cache"`
	// EstimatedAnalysisDuration is an estimated duration for the next analysis in milliseconds
	// It's an optimistic estimation based on the average analysis time and the analysis queue
	EstimatedAnalysisDuration int `json:"estimated_analysis_duration"`
	// MalwareThreshold is the threshold at which a file is considered malicious
	MalwareThreshold int `json:"malware_threshold"`
}

// DefaultTimeout is the default timeout for gdetect client
var DefaultTimeout = time.Minute * 5

// NewClient returns a fresh client, given endpoint token and insecure params.
// The returned client could be used to perform operations on gdetect.
//
// If Client is well-formed, it returns error == nil. If error != nil, that
// could mean that Token is invalid (by its length for example).
//
// Deprecated: must use NewClientFromConfig
func NewClient(endpoint, token string, insecure bool, httpClient *http.Client) (client *Client, err error) {
	err = checkToken(token)
	if err != nil {
		return
	}

	client = &Client{
		lock: &sync.RWMutex{},
	}
	client.setFromConfig(ClientConfig{
		Endpoint:   endpoint,
		Token:      token,
		Insecure:   insecure,
		HTTPClient: httpClient,
	})
	return client, nil
}

// NewClientFromConfig returns a new Client configured from the provided ClientConfig.
// It validates the token format and initialises the HTTP client.
// Returns ErrBadToken when config.Token does not match the required UUID format.
func NewClientFromConfig(config ClientConfig) (client *Client, err error) {
	err = checkToken(config.Token)
	if err != nil {
		return
	}
	client = &Client{
		lock: &sync.RWMutex{},
	}
	client.setFromConfig(config)
	return client, nil
}

// Reconfigure applies a new ClientConfig to the client at runtime.
// It is safe to call concurrently; a write lock is held for the duration.
// For SynDetect mode, it also validates the server API version.
func (c *Client) Reconfigure(ctx context.Context, config ClientConfig) (err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.setFromConfig(config)
	if c.syndetect {
		v, err := c.getAPIVersions(ctx, c.HTTPClient.Do)
		if err != nil {
			return err
		}
		ver, err := semver.NewVersion(v)
		if err != nil {
			return err
		}
		verLimit := semver.New("1.1.0")
		if ver.LessThan(*verLimit) {
			return nil
		}
	}
	_, err = c.getProfileStatus(ctx, c.HTTPClient.Do)
	if err != nil {
		return
	}
	return
}

func (c *Client) setFromConfig(config ClientConfig) {
	c.Endpoint = config.Endpoint
	c.ExpertURL = config.ExpertURL
	c.Token = config.Token
	c.syndetect = config.Syndetect
	if config.HTTPClient != nil {
		c.HTTPClient = config.HTTPClient
		return
	}

	// Create a dedicated transport to avoid mutating http.DefaultTransport.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-requested insecure mode
	}
	if config.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
		transport.MaxIdleConns = config.MaxIdleConnsPerHost
	}
	var rt http.RoundTripper = transport
	if config.TransportWrapper != nil {
		rt = config.TransportWrapper(transport)
	}
	c.HTTPClient = &http.Client{Transport: rt, Timeout: DefaultTimeout}
}

// Do executes an HTTP request using the client's underlying HTTP client.
// The request URL is constructed from the user-configured endpoint, which is
// intentional by design — callers must ensure the endpoint is a trusted server.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.HTTPClient.Do(req) //nolint:gosec,nolintlint // G704: SSRF by design, endpoint is user-configured and trusted
}

func checkToken(token string) (err error) {
	if !reValidToken.MatchString(token) {
		err = ErrBadToken
		return
	}
	return
}

// SetSyndetect configures the client to use the SynDetect API path set.
// This method logs a warning because SynDetect is a limited variant and
// some analysis information will not be accessible.
func (c *Client) SetSyndetect() {
	c.syndetect = true
	Logger.Warn("syndetect is a limited version of detect API, some analysis information won't be accessible.")
}

func (c *Client) prepareRequest(ctx context.Context, method string, path string, body io.Reader, queries ...map[string]string) (request *http.Request, err error) {
	var u url.URL

	urlTmp, err := url.Parse(c.Endpoint)
	if err != nil {
		return
	}

	u.Host = urlTmp.Host
	u.Scheme = urlTmp.Scheme
	u.Path = path

	if len(queries) > 0 {
		q := u.Query()
		for k, v := range queries[0] {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	request, err = http.NewRequestWithContext(ctx, method, u.String(), body)
	if c.Token != "" {
		request.Header.Add("X-Auth-Token", c.Token)
	}
	return
}

// HTTPError represents a non-2xx HTTP response from the API, carrying the
// response status, status code, and raw response body for diagnosis.
type HTTPError struct {
	Status string
	Code   int
	Body   string
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("invalid response from endpoint, %s: %s", e.Status, e.Body)
}

// NewHTTPError creates an HTTPError from an HTTP response and a pre-read body string.
func NewHTTPError(r *http.Response, body string) HTTPError {
	return HTTPError{
		Status: r.Status,
		Code:   r.StatusCode,
		Body:   body,
	}
}

var (
	// DetectPaths maps logical path keys to their corresponding Detect API URL prefixes.
	DetectPaths = map[string]string{
		"results": "/api/lite/v2/results/",
		"search":  "/api/lite/v2/search/",
		"submit":  "/api/lite/v2/submit",
		"status":  "/api/lite/v2/status",
	}
	// SyndetectPaths maps logical path keys to their corresponding SynDetect API URL prefixes.
	SyndetectPaths = map[string]string{
		"results": "/api/v1/results/",
		"search":  "/api/v1/results/",
		"submit":  "/api/v1/submit",
		"status":  "/api/v1/status",
	}
)

func (c *Client) getPath(path string) (string, error) {
	if c.syndetect {
		if v, ok := SyndetectPaths[path]; ok {
			return v, nil
		}
	}
	if v, ok := DetectPaths[path]; ok {
		return v, nil
	}
	return "", ErrPathNotFound
}

// getResultByUUID is the internal implementation for retrieving an analysis result
// by UUID. When waitSeconds > 0 and the client is in detect mode (not syndetect),
// a ?wait=N query parameter is added to instruct the server to hold the connection
// open for up to N seconds until the analysis completes.
func (c *Client) getResultByUUID(ctx context.Context, analysisID string, waitSeconds int) (result Result, err error) {
	if !c.syndetect && !reValidUUID.MatchString(analysisID) {
		err = ErrInvalidUUID
		return
	}
	resultsPath, err := c.getPath("results")
	if err != nil {
		return
	}

	var request *http.Request
	if waitSeconds > 0 && !c.syndetect {
		queries := map[string]string{"wait": strconv.Itoa(waitSeconds)}
		request, err = c.prepareRequest(ctx, "GET", resultsPath+analysisID, nil, queries)
	} else {
		request, err = c.prepareRequest(ctx, "GET", resultsPath+analysisID, nil)
	}
	if err != nil {
		return
	}

	resp, err := c.Do(request)
	if err != nil {
		return
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Warn("cannot close response body", slog.String("error", e.Error()))
		}
	}()
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &result)
	switch {
	case err == nil:
		// not error
	case c.syndetect && err.Error() == "json: cannot unmarshal number into Go struct field Result.files of type []gdetect.FileResult":
		// SynDetect returns the file count as a plain number in the "files" field
		// instead of an array when there are no sub-file results; ignore the mismatch.
		err = nil
	default:
		err = fmt.Errorf("error unmarshalling response json, %w", err)
		return
	}
	if c.syndetect {
		result.UUID = analysisID
	}

	return
}

// GetResultByUUID retrieves result using results endpoint on Detect API with
// given analysis ID. The server responds immediately regardless of whether the
// analysis is complete (done may be false). Use GetResultByUUIDWithWait to
// instruct the server to hold the connection until the analysis completes.
func (c *Client) GetResultByUUID(ctx context.Context, analysisID string) (result Result, err error) {
	return c.getResultByUUID(ctx, analysisID, 0)
}

// GetResultByUUIDWithWait retrieves an analysis result by UUID, instructing the
// server to hold the connection open for up to waitSeconds seconds until the
// analysis is complete. When the analysis finishes before the timeout, the server
// returns immediately with done=true. If not, done=false is returned and the
// caller may poll again.
//
// waitSeconds must be in the range [0, MaxWaitSeconds]. Use 0 to get the same
// behaviour as GetResultByUUID (immediate response). The wait parameter is only
// sent in Detect mode; in SynDetect mode the call behaves like GetResultByUUID.
//
// Returns ErrInvalidWaitSeconds when waitSeconds is negative or exceeds MaxWaitSeconds.
func (c *Client) GetResultByUUIDWithWait(ctx context.Context, analysisID string, waitSeconds int) (result Result, err error) {
	if waitSeconds < 0 || waitSeconds > MaxWaitSeconds {
		err = ErrInvalidWaitSeconds
		return
	}
	return c.getResultByUUID(ctx, analysisID, waitSeconds)
}

// GetResultBySHA256 searches for a previous analysis using the search endpoint of
// the Detect API with the given file SHA256 hash. Returns ErrInvalidSHA256 when
// the sha256 parameter is not a valid 64-character lowercase hex string.
func (c *Client) GetResultBySHA256(ctx context.Context, sha256 string) (result Result, err error) {
	if !reValidSHA256.MatchString(sha256) {
		err = ErrInvalidSHA256
		return
	}
	searchPath, err := c.getPath("search")
	if err != nil {
		return
	}
	request, err := c.prepareRequest(ctx, "GET", searchPath+sha256, nil)
	if err != nil {
		return
	}

	resp, err := c.Do(request)
	if err != nil {
		return
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Warn("cannot close response body", slog.String("error", e.Error()))
		}
	}()
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &result)
	if err != nil {
		err = fmt.Errorf("error unmarshalling response json, %w", err)
		return
	}

	return
}

// SubmitFile opens a local file and submits it to the Detect API.
// It returns the analysis UUID assigned by the server.
// If submitOptions.Filename is empty it is populated from the opened file's name.
func (c *Client) SubmitFile(ctx context.Context, filePath string, submitOptions SubmitOptions) (uuid string, err error) {
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return
	}
	defer func() {
		err := file.Close()
		if err != nil {
			Logger.Warn("cannot close file", slog.String("error", err.Error()))
		}
	}()

	if submitOptions.Filename == "" {
		submitOptions.Filename = file.Name()
	}

	return c.SubmitReader(ctx, file, submitOptions)
}

// SubmitReader submits content from an io.Reader to the Detect API for analysis.
// The data is streamed via a multipart form upload; the caller's reader is never
// fully buffered in memory.
// Returns the analysis UUID assigned by the server.
func (c *Client) SubmitReader(ctx context.Context, r io.Reader, submitOptions SubmitOptions) (uuid string, err error) {
	// Struct corresponding to submit json result
	type responseT struct {
		Status bool   `json:"status"`          // detect & syndetect
		UUID   string `json:"uuid,omitempty"`  // detect only (analysis id)
		ID     string `json:"id,omitempty"`    // syndetect only (analysis id)
		Error  string `json:"error,omitempty"` // detect & syndetect
	}

	var (
		part     io.Writer
		response responseT
		resp     *http.Response
	)

	pr, pw := io.Pipe()
	defer func() {
		if errClose := pr.Close(); errClose != nil {
			Logger.Warn("failed to close pipe reader")
		}
	}()

	writer := multipart.NewWriter(pw)

	go func() {
		defer func() {
			if errClose := pw.Close(); errClose != nil {
				Logger.Warn(fmt.Sprintf("failed to close pipe writer, err: %s", errClose))
			}
		}()

		part, err = writer.CreateFormFile("file", submitOptions.Filename)
		if err != nil {
			pw.CloseWithError(err)
			return
		}

		// Copy file content
		_, err = io.Copy(part, r)
		if err != nil {
			pw.CloseWithError(err)
			return
		}

		// Create form-data header with given filename
		if submitOptions.Filename == "" {
			submitOptions.Filename = "unknown"
		}

		// Submit file even if it exists in db
		if submitOptions.BypassCache {
			if err = addFormField(writer, "bypass-cache", "true"); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		// Add description if filled in
		if submitOptions.Description != "" {
			if err = addFormField(writer, "description", submitOptions.Description); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		// Add all tags if filled in
		if len(submitOptions.Tags) > 0 {
			if err = addFormField(writer, "tags", strings.Join(submitOptions.Tags, ",")); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		// Add archive_password if filled in
		if submitOptions.ArchivePassword != "" {
			if err = addFormField(writer, "archive_password", submitOptions.ArchivePassword); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		if errClose := writer.Close(); errClose != nil {
			pw.CloseWithError(errClose)
		}
	}()

	// Post file to API
	submitPath, err := c.getPath("submit")
	if err != nil {
		return
	}
	var request *http.Request
	if submitOptions.Dynamic {
		request, err = c.prepareRequest(ctx, http.MethodPost, submitPath, pr,
			map[string]string{"dynamic": "true"})
	} else {
		request, err = c.prepareRequest(ctx, http.MethodPost, submitPath, pr)
	}
	if err != nil {
		return
	}
	request.Header.Add("Content-Type", writer.FormDataContentType())

	resp, err = c.Do(request)
	if err != nil {
		return
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Warn("cannot close response body", slog.String("error", e.Error()))
		}
	}()
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &response)
	if err != nil {
		err = fmt.Errorf("error unmarshalling response json, %w", err)
		return
	}

	if !response.Status {
		err = errors.New(response.Error)
		return
	}
	uuid = response.UUID
	if c.syndetect {
		uuid = response.ID
	}
	return
}

func addFormField(w *multipart.Writer, field string, value string) (err error) {
	part, err := w.CreateFormField(field)
	if err != nil {
		return
	}
	_, err = part.Write([]byte(value))
	if err != nil {
		return
	}
	return
}

// WaitForFile submits a local file and blocks until analysis is complete or the
// configured timeout elapses. It returns the final analysis Result.
func (c *Client) WaitForFile(ctx context.Context, filePath string, waitOptions WaitForOptions) (result Result, err error) {
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		err = fmt.Errorf("error opening input file: %w", err)
		return
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			Logger.Warn(fmt.Sprintf("failed to close input file, err: %s", errClose))
		}
	}()

	if waitOptions.Filename == "" {
		waitOptions.Filename = file.Name()
	}

	return c.waitFor(ctx, file, waitOptions,
		func(ctx context.Context, pullTime time.Duration, submitOptions SubmitOptions) (result Result, err error) {
			return c.waitforWithPreGet(ctx, file, pullTime, submitOptions)
		},
	)
}

// WaitForReader submits data from an io.Reader and blocks until analysis is complete
// or the configured timeout elapses. The reader content is buffered to a temporary
// file so it can be re-read on cache-miss retries.
func (c *Client) WaitForReader(ctx context.Context, r io.Reader, waitOptions WaitForOptions) (result Result, err error) {
	return c.waitFor(ctx, r, waitOptions,
		func(ctx context.Context, pullTime time.Duration, submitOptions SubmitOptions) (result Result, err error) {
			tmpFile, err := os.CreateTemp(os.TempDir(), "gdetect-tmp-*")
			if err != nil {
				err = fmt.Errorf("error creating temp file: %w", err)
				return
			}

			// Set secure permissions (owner read/write only)
			if err = tmpFile.Chmod(0o600); err != nil {
				_ = tmpFile.Close()
				_ = os.Remove(tmpFile.Name())
				err = fmt.Errorf("error setting temp file permissions: %w", err)
				return
			}

			defer func() {
				if e := tmpFile.Close(); e != nil {
					Logger.Warn(fmt.Sprintf("failed to close tmp file, err: %s", e))
				}
				if e := os.Remove(tmpFile.Name()); e != nil {
					Logger.Warn(fmt.Sprintf("failed to remove tmp file, err: %s", e))
				}
			}()

			// Compute the SHA256 from the same pass that fills the temp file.
			hasher := sha256.New()
			if _, err = io.Copy(io.MultiWriter(tmpFile, hasher), r); err != nil {
				err = fmt.Errorf("error copying input to temp file: %w", err)
				return
			}
			return c.waitforWithPreGetHash(ctx, tmpFile, hex.EncodeToString(hasher.Sum(nil)), pullTime, submitOptions)
		},
	)
}

func (c *Client) waitFor(ctx context.Context, r io.Reader, waitOptions WaitForOptions, cacheFn func(ctx context.Context, pullTime time.Duration, submitOptions SubmitOptions) (result Result, err error)) (result Result, err error) {
	if waitOptions.Timeout == 0 {
		waitOptions.Timeout = time.Second * 180
	}
	ctx, cancel := context.WithTimeout(ctx, waitOptions.Timeout)
	defer cancel()

	// Ticker to perform get every n seconds
	if waitOptions.PullTime == 0 {
		waitOptions.PullTime = 2 * time.Second
	}

	submitOptions := waitOptions.SubmitOptions
	if waitOptions.BypassCache {
		// Submit file
		uuid, submitErr := c.SubmitReader(ctx, r, submitOptions)
		if submitErr != nil {
			err = fmt.Errorf("error submitting file: %w", submitErr)
			return
		}
		result, err = c.waitForUUID(ctx, uuid, waitOptions.PullTime)
		if err != nil {
			err = fmt.Errorf("error waiting for result: %w", err)
			return
		}
		return
	}
	return cacheFn(ctx, waitOptions.PullTime, submitOptions)
}

func (c *Client) waitforWithPreGet(ctx context.Context, r io.ReadSeeker, pullTime time.Duration, submitOptions SubmitOptions) (result Result, err error) {
	return c.waitforWithPreGetHash(ctx, r, "", pullTime, submitOptions)
}

// waitforWithPreGetHash looks up the result cache by SHA256 ("preget") and
// submits r on a miss. A non-empty precomputedSHA256 is used as r's content
// hash; otherwise r is hashed here. On a miss r is rewound and read to submit,
// so r must be seekable in either case.
func (c *Client) waitforWithPreGetHash(ctx context.Context, r io.ReadSeeker, precomputedSHA256 string, pullTime time.Duration, submitOptions SubmitOptions) (result Result, err error) {
	readerSHA256 := precomputedSHA256
	if readerSHA256 == "" {
		// Ensure we hash from the beginning of the reader. Callers such as
		// WaitForFile hand us a file whose offset may not be at the start, so
		// without this seek io.Copy would read zero bytes and produce the
		// SHA256 of an empty file.
		if _, err = r.Seek(0, io.SeekStart); err != nil {
			err = fmt.Errorf("error seeking input: %w", err)
			return
		}
		hash := sha256.New()
		if _, err = io.Copy(hash, r); err != nil {
			err = fmt.Errorf("error hashing input: %w", err)
			return
		}
		readerSHA256 = hex.EncodeToString(hash.Sum(nil))
	}
	analysisID := ""
	result, err = c.GetResultBySHA256(ctx, readerSHA256)
	httpErr := new(HTTPError)
	switch {
	case errors.As(err, httpErr) && httpErr.Code == http.StatusNotFound:
		// Submit file
		if _, err = r.Seek(0, io.SeekStart); err != nil {
			return
		}
		analysisID, err = c.SubmitReader(ctx, r, submitOptions)
		if err != nil {
			err = fmt.Errorf("error submitting file: %w", err)
			return
		}
	case err != nil:
		err = fmt.Errorf("error getting result from cache: %w", err)
		return
	case result.Done:
		return
	default:
		// result exist in cache but is not done yet
		analysisID = result.UUID
		if c.syndetect {
			analysisID = result.ID
		}
	}
	result, err = c.waitForUUID(ctx, analysisID, pullTime)
	if err != nil {
		err = fmt.Errorf("error waiting for result: %w", err)
		return
	}
	return
}

// waitSecondsForContext computes how many seconds to pass as the server-side
// wait parameter given the remaining context deadline. The value is capped at
// MaxWaitSeconds to avoid holding server connections for excessively long
// periods. Returns 0 if the remaining time is less than one second.
func waitSecondsForContext(ctx context.Context) int {
	deadline, ok := ctx.Deadline()
	if !ok {
		return MaxWaitSeconds
	}
	remaining := int(time.Until(deadline).Seconds())
	if remaining <= 0 {
		return 0
	}
	if remaining > MaxWaitSeconds {
		return MaxWaitSeconds
	}
	return remaining
}

func (c *Client) waitForUUID(ctx context.Context, analysisID string, pullTime time.Duration) (result Result, err error) {
	// In detect mode, use the server-side ?wait= parameter to reduce polling
	// round-trips. The server holds the connection open for up to waitSeconds
	// seconds and returns immediately when the analysis completes.
	// In syndetect mode the wait parameter is not documented, so we fall back
	// to the original ticker-based polling.
	if !c.syndetect {
		for {
			select {
			case <-ctx.Done():
				err = ErrTimeout
				return
			default:
			}
			wait := waitSecondsForContext(ctx)
			if wait == 0 {
				err = ErrTimeout
				return
			}
			result, err = c.getResultByUUID(ctx, analysisID, wait)
			if err != nil {
				return
			}
			if result.Done {
				return
			}
		}
	}

	ticker := time.NewTicker(pullTime)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			result, err = c.GetResultByUUID(ctx, analysisID)
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

// ExtractTokenViewURL builds a URL for the Expert View token-redirect page from
// the Token field of the given Result. Returns ErrNoToken when the result has no token.
func (c *Client) ExtractTokenViewURL(result *Result) (urlTokenView string, err error) {
	token := result.Token
	if token == "" {
		err = ErrNoToken
		return
	}
	endpoint := c.Endpoint
	if c.ExpertURL != "" {
		endpoint = c.ExpertURL
	}
	urlTokenView = endpoint + "/expert/en/analysis-redirect/" + token
	return
}

// ExtractExpertViewURL extracts URL analysis expert view from given result, use client to retrieve API base endpoint
func (c *Client) ExtractExpertViewURL(result *Result) (urlExpertView string, err error) {
	sid := result.SID
	if sid == "" {
		err = ErrNoSID
		return
	}
	endpoint := c.Endpoint
	if c.ExpertURL != "" {
		endpoint = c.ExpertURL
	}
	urlExpertView = endpoint + "/expert/en/analysis/advanced/" + sid
	return
}

// GetFullSubmissionByUUID retrieves full submission using results full endpoint
// on Detect API with given UUID.
func (c *Client) GetFullSubmissionByUUID(ctx context.Context, uuid string) (result any, err error) {
	if c.syndetect {
		return nil, ErrNotAvailable
	}
	if !reValidUUID.MatchString(uuid) {
		return nil, ErrInvalidUUID
	}
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/results/"+uuid+"/full", nil)
	if err != nil {
		return
	}

	resp, err := c.Do(request)
	if err != nil {
		return
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Warn("cannot close response body", slog.String("error", e.Error()))
		}
	}()
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &result)
	if err != nil {
		err = fmt.Errorf("error unmarshalling response json, %w", err)
		return
	}

	return
}

// GetProfileStatus retrieves the current profile quota and configuration status
// from the API.
func (c *Client) GetProfileStatus(ctx context.Context) (status ProfileStatus, err error) {
	return c.getProfileStatus(ctx, c.Do)
}

func (c *Client) getProfileStatus(ctx context.Context, do func(req *http.Request) (*http.Response, error)) (status ProfileStatus, err error) {
	statusPath, err := c.getPath("status")
	if err != nil {
		return
	}
	request, err := c.prepareRequest(ctx, "GET", statusPath, nil)
	if err != nil {
		return
	}

	resp, err := do(request)
	if err != nil {
		return
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			Logger.Warn("cannot close response body", slog.String("error", err.Error()))
		}
	}()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// do nothing
	case http.StatusNotFound:
		// the feature does not seems to be available
		err = c.generateFeatureError(ctx)
		return
	default:
		err = NewHTTPError(resp, string(rawBody))
		return
	}

	err = json.Unmarshal(rawBody, &status)
	if err != nil {
		err = fmt.Errorf("error unmarshaling response json, %w", err)
		return
	}

	return
}

// GetAPIVersion retrieves detect API version
func (c *Client) GetAPIVersion(ctx context.Context) (version string, err error) {
	return c.getAPIVersions(ctx, c.Do)
}

func (c *Client) getAPIVersions(ctx context.Context, do func(*http.Request) (*http.Response, error)) (version string, err error) {
	request, err := c.prepareRequest(ctx, "GET", "/api/versions", nil)
	if err != nil {
		return
	}

	resp, err := do(request)
	if err != nil {
		return
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Warn("cannot close response body", slog.String("error", e.Error()))
		}
	}()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(rawBody))
		return
	}
	response := map[string]string{}

	err = json.Unmarshal(rawBody, &response)
	if err != nil {
		err = fmt.Errorf("error unmarshalling response json, %w", err)
		return
	}

	if v, ok := response["/api/lite/v2"]; ok {
		version = v
		return
	}
	if c.syndetect {
		if v, ok := response["/v1"]; ok {
			version = v
			return
		}
	}

	version = "unknown"
	err = errors.New("could not find detect API version in the server response")
	return
}

// generateFeatureError add the server API version in an FeatureNotAvailableError
func (c *Client) generateFeatureError(ctx context.Context) (err error) {
	e := FeatureNotAvailableError{}
	e.Version, err = c.GetAPIVersion(ctx)
	if err != nil {
		return
	}
	return e
}

// ExportResult exports a specific analysis result by UUID in the specified format.
// The returned data is the raw file content (PDF, JSON, CSV, etc.) depending on the format.
func (c *Client) ExportResult(ctx context.Context, uuid string, options ExportOptions) (data []byte, err error) {
	if c.syndetect {
		return nil, ErrNotAvailable
	}
	if !reValidUUID.MatchString(uuid) {
		return nil, ErrInvalidUUID
	}
	queries := map[string]string{
		"format": string(options.Format),
		"layout": string(options.Layout),
	}
	if options.Full {
		queries["full"] = "true"
	}
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/results/"+uuid+"/export", nil, queries)
	if err != nil {
		return
	}
	resp, err := c.Do(request)
	if err != nil {
		return
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Warn(fmt.Sprintf("failed to close resp body, err: %s", e))
		}
	}()
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = NewHTTPError(resp, string(data))
		return
	}

	return
}
