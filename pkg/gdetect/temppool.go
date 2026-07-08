package gdetect

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// defaultTempPoolSize bounds how many reusable temp files are kept idle. Files
// returned when the pool is full are closed and removed instead of retained.
const defaultTempPoolSize = 512

// copyBufSize is the buffer size used when streaming request bodies to temp
// files.
const copyBufSize = 64 * 1024

// bufPool recycles the byte slices used to copy request bodies so a fresh buffer
// is not allocated on every stream.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufSize)
		return &b
	},
}

// tempFilePool hands out reusable temp files so the hot path avoids a
// CreateTemp/Remove syscall pair per request. Files are truncated on return, so
// idle files hold no data. It is safe for concurrent use.
type tempFilePool struct {
	dir  string
	free chan *os.File
}

func newTempFilePool(dir string, size int) *tempFilePool {
	if size <= 0 {
		size = defaultTempPoolSize
	}
	return &tempFilePool{dir: dir, free: make(chan *os.File, size)}
}

// get returns a temp file positioned at offset 0, reusing an idle one when
// available or creating a new one otherwise. The file has owner-only
// permissions.
func (p *tempFilePool) get() (*os.File, error) {
	select {
	case f := <-p.free:
		return f, nil
	default:
	}
	f, err := os.CreateTemp(p.dir, "gdetect-tmp-*")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file: %w", err)
	}
	if err = f.Chmod(0o600); err != nil {
		p.discard(f)
		return nil, fmt.Errorf("error setting temp file permissions: %w", err)
	}
	return f, nil
}

// put truncates f, rewinds it, and returns it to the pool. If truncation fails
// or the pool is full, f is closed and removed instead.
func (p *tempFilePool) put(f *os.File) {
	if f == nil {
		return
	}
	if err := p.reset(f); err != nil {
		p.discard(f)
		return
	}
	select {
	case p.free <- f:
	default:
		p.discard(f)
	}
}

func (p *tempFilePool) reset(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err := f.Seek(0, io.SeekStart)
	return err
}

func (p *tempFilePool) discard(f *os.File) {
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
}

// close drains the pool, closing and removing every idle file. Files currently
// checked out are cleaned up by the put that returns them.
func (p *tempFilePool) close() {
	for {
		select {
		case f := <-p.free:
			p.discard(f)
		default:
			return
		}
	}
}
