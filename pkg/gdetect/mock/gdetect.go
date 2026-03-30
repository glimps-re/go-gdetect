// Package gdetectmock provides a mock implementation of the gdetect interfaces
// for use in unit tests. Each method delegates to a configurable function field,
// allowing tests to inject specific return values or error conditions without
// running a real GLIMPS Detect API server.
package gdetectmock

import (
	"context"
	"io"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

// MockGDetectSubmitter is a configurable mock implementation of
// [gdetect.ControllerExtendedGDetectSubmitter]. Each method delegates to the
// corresponding *Mock function field when set. If a field is nil and the method
// is called, the mock panics with a message identifying the unimplemented method.
//
// Usage in tests:
//
//	m := &gdetectmock.MockGDetectSubmitter{
//	    GetResultByUUIDMock: func(ctx context.Context, uuid string) (gdetect.Result, error) {
//	        return gdetect.Result{Done: true}, nil
//	    },
//	}
type MockGDetectSubmitter struct {
	GetResultByUUIDMock         func(ctx context.Context, uuid string) (result gdetect.Result, err error)
	GetResultByUUIDWithWaitMock func(ctx context.Context, uuid string, waitSeconds int) (result gdetect.Result, err error)
	GetResultBySHA256Mock       func(ctx context.Context, sha256 string) (result gdetect.Result, err error)
	GetResultsMock              func(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error)
	SubmitFileMock              func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error)
	SubmitReaderMock            func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error)
	WaitForFileMock             func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error)
	WaitForReaderMock           func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error)
	ExtractTokenViewURLMock     func(result *gdetect.Result) (urlTokenView string, err error)
	ExtractExpertViewURLMock    func(result *gdetect.Result) (urlExpertView string, err error)
	GetFullSubmissionByUUIDMock func(ctx context.Context, uuid string) (result any, err error)
	GetProfileStatusMock        func(ctx context.Context) (status gdetect.ProfileStatus, err error)
	GetAPIVersionMock           func(ctx context.Context) (version string, err error)
	ExportResultMock            func(ctx context.Context, uuid string, options gdetect.ExportOptions) (data []byte, err error)

	ReconfigureMock func(ctx context.Context, config gdetect.ClientConfig) (err error)
}

var (
	_ gdetect.ExtendedGDetectSubmitter           = &MockGDetectSubmitter{}
	_ gdetect.ControllerExtendedGDetectSubmitter = &MockGDetectSubmitter{}
)

// GetResultByUUID delegates to GetResultByUUIDMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetResultByUUID(ctx context.Context, uuid string) (result gdetect.Result, err error) {
	if m.GetResultByUUIDMock != nil {
		return m.GetResultByUUIDMock(ctx, uuid)
	}
	panic("GetResultByUUID not implemented in current test")
}

// GetResultByUUIDWithWait delegates to GetResultByUUIDWithWaitMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetResultByUUIDWithWait(ctx context.Context, uuid string, waitSeconds int) (result gdetect.Result, err error) {
	if m.GetResultByUUIDWithWaitMock != nil {
		return m.GetResultByUUIDWithWaitMock(ctx, uuid, waitSeconds)
	}
	panic("GetResultByUUIDWithWait not implemented in current test")
}

// GetResultBySHA256 delegates to GetResultBySHA256Mock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetResultBySHA256(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
	if m.GetResultBySHA256Mock != nil {
		return m.GetResultBySHA256Mock(ctx, sha256)
	}
	panic("GetResultBySHA256 not implemented in current test")
}

// GetResults delegates to GetResultsMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetResults(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error) {
	if m.GetResultsMock != nil {
		return m.GetResultsMock(ctx, from, size, tags...)
	}
	panic("GetResults not implemented in current test")
}

// SubmitFile delegates to SubmitFileMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) SubmitFile(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitFileMock != nil {
		return m.SubmitFileMock(ctx, filepath, options)
	}
	panic("SubmitFile not implemented in current test")
}

// SubmitReader delegates to SubmitReaderMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) SubmitReader(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitReaderMock != nil {
		return m.SubmitReaderMock(ctx, r, options)
	}
	panic("SubmitReader not implemented in current test")
}

// WaitForFile delegates to WaitForFileMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) WaitForFile(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForFileMock != nil {
		return m.WaitForFileMock(ctx, filepath, options)
	}
	panic("WaitForFile not implemented in current test")
}

// WaitForReader delegates to WaitForReaderMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) WaitForReader(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForReaderMock != nil {
		return m.WaitForReaderMock(ctx, r, options)
	}
	panic("WaitForReader not implemented in current test")
}

// ExtractTokenViewURL delegates to ExtractTokenViewURLMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) ExtractTokenViewURL(result *gdetect.Result) (urlTokenView string, err error) {
	if m.ExtractTokenViewURLMock != nil {
		return m.ExtractTokenViewURLMock(result)
	}
	panic("ExtractTokenViewURL not implemented in current test")
}

// ExtractExpertViewURL delegates to ExtractExpertViewURLMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error) {
	if m.ExtractExpertViewURLMock != nil {
		return m.ExtractExpertViewURLMock(result)
	}
	panic("ExtractExpertViewURLMock not implemented in current test")
}

// GetFullSubmissionByUUID delegates to GetFullSubmissionByUUIDMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetFullSubmissionByUUID(ctx context.Context, uuid string) (result any, err error) {
	if m.GetFullSubmissionByUUIDMock != nil {
		return m.GetFullSubmissionByUUIDMock(ctx, uuid)
	}
	panic("GetFullSubmissionByUUID not implemented in current test")
}

// GetProfileStatus delegates to GetProfileStatusMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetProfileStatus(ctx context.Context) (status gdetect.ProfileStatus, err error) {
	if m.GetProfileStatusMock != nil {
		return m.GetProfileStatusMock(ctx)
	}
	panic("GetProfileStatus not implemented in current test")
}

// GetAPIVersion delegates to GetAPIVersionMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) GetAPIVersion(ctx context.Context) (version string, err error) {
	if m.GetAPIVersionMock != nil {
		return m.GetAPIVersionMock(ctx)
	}
	panic("GetAPIVersion not implemented in current test")
}

// ExportResult delegates to ExportResultMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) ExportResult(ctx context.Context, uuid string, options gdetect.ExportOptions) (data []byte, err error) {
	if m.ExportResultMock != nil {
		return m.ExportResultMock(ctx, uuid, options)
	}
	panic("ExportResult not implemented in current test")
}

// Reconfigure delegates to ReconfigureMock. Panics if the field is nil.
func (m *MockGDetectSubmitter) Reconfigure(ctx context.Context, config gdetect.ClientConfig) (err error) {
	if m.ReconfigureMock != nil {
		return m.ReconfigureMock(ctx, config)
	}
	panic("Reconfigure not implemented in current test")
}
