package gdetectmock

import (
	"context"
	"io"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

type MockGDetectSubmitter struct {
	GetResultByUUIDMock         func(ctx context.Context, uuid string) (result gdetect.Result, err error)
	GetResultBySHA256Mock       func(ctx context.Context, sha256 string) (result gdetect.Result, err error)
	GetResultsMock              func(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error)
	SubmitFileMock              func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error)
	SubmitReaderMock            func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error)
	WaitForFileMock             func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error)
	WaitForReaderMock           func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error)
	ExtractTokenViewURLMock     func(result *gdetect.Result) (urlTokenView string, err error)
	ExtractExpertViewURLMock    func(result *gdetect.Result) (urlExpertView string, err error)
	GetFullSubmissionByUUIDMock func(ctx context.Context, uuid string) (result interface{}, err error)
	GetProfileStatusMock        func(ctx context.Context) (status gdetect.ProfileStatus, err error)
	GetAPIVersionMock           func(ctx context.Context) (version string, err error)
	WaitForUUIDMock             func(ctx context.Context, uuid string, pullTime time.Duration) (result gdetect.Result, err error)
}

func (m *MockGDetectSubmitter) GetResultByUUID(ctx context.Context, uuid string) (result gdetect.Result, err error) {
	if m.GetResultByUUIDMock != nil {
		return m.GetResultByUUIDMock(ctx, uuid)
	}
	panic("GetResultByUUID not implemented in current test")
}

func (m *MockGDetectSubmitter) GetResultBySHA256(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
	if m.GetResultBySHA256Mock != nil {
		return m.GetResultBySHA256Mock(ctx, sha256)
	}
	panic("GetResultBySHA256 not implemented in current test")
}

func (m *MockGDetectSubmitter) GetResults(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error) {
	if m.GetResultsMock != nil {
		return m.GetResultsMock(ctx, from, size, tags...)
	}
	panic("GetResults not implemented in current test")
}

func (m *MockGDetectSubmitter) SubmitFile(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitFileMock != nil {
		return m.SubmitFileMock(ctx, filepath, options)
	}
	panic("SubmitFile not implemented in current test")
}

func (m *MockGDetectSubmitter) SubmitReader(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitReaderMock != nil {
		return m.SubmitReaderMock(ctx, r, options)
	}
	panic("SubmitReader not implemented in current test")
}

func (m *MockGDetectSubmitter) WaitForFile(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForFileMock != nil {
		return m.WaitForFileMock(ctx, filepath, options)
	}
	panic("WaitForFile not implemented in current test")
}

func (m *MockGDetectSubmitter) WaitForReader(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForReaderMock != nil {
		return m.WaitForReaderMock(ctx, r, options)
	}
	panic("WaitForReader not implemented in current test")
}

func (m *MockGDetectSubmitter) ExtractTokenViewURL(result *gdetect.Result) (urlTokenView string, err error) {
	if m.ExtractTokenViewURLMock != nil {
		return m.ExtractTokenViewURLMock(result)
	}
	panic("ExtractTokenViewURL not implemented in current test")
}

func (m *MockGDetectSubmitter) ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error) {
	if m.ExtractExpertViewURLMock != nil {
		return m.ExtractExpertViewURLMock(result)
	}
	panic("ExtractExpertViewURLMock not implemented in current test")
}

func (m *MockGDetectSubmitter) GetFullSubmissionByUUID(ctx context.Context, uuid string) (result interface{}, err error) {
	if m.GetFullSubmissionByUUIDMock != nil {
		return m.GetFullSubmissionByUUIDMock(ctx, uuid)
	}
	panic("GetFullSubmissionByUUID not implemented in current test")
}

func (m *MockGDetectSubmitter) GetProfileStatus(ctx context.Context) (status gdetect.ProfileStatus, err error) {
	if m.GetProfileStatusMock != nil {
		return m.GetProfileStatusMock(ctx)
	}
	panic("GetProfileStatus not implemented in current test")
}

func (m *MockGDetectSubmitter) GetAPIVersion(ctx context.Context) (version string, err error) {
	if m.GetAPIVersionMock != nil {
		return m.GetAPIVersionMock(ctx)
	}
	panic("GetAPIVersion not implemented in current test")
}

func (m *MockGDetectSubmitter) WaitForUUID(ctx context.Context, uuid string, pullTime time.Duration) (result gdetect.Result, err error) {
	if m.WaitForUUIDMock != nil {
		return m.WaitForUUIDMock(ctx, uuid, pullTime)
	}
	panic("WaitForUUID not implemented in current test")
}
