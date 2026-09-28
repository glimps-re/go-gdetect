package gdetect

import (
	"io"
	"os"
	"sync"
	"testing"
)

func TestTempFilePool_ReusesFile(t *testing.T) {
	p := newTempFilePool(t.TempDir(), 4)

	f1, err := p.get()
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	name := f1.Name()
	if _, err := f1.WriteString("some content"); err != nil {
		t.Fatalf("write error = %v", err)
	}
	p.put(f1)

	f2, err := p.get()
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	if f2.Name() != name {
		t.Errorf("get() returned a new file %s, want reused %s", f2.Name(), name)
	}
	// The reused file must be empty and positioned at the start.
	info, err := f2.Stat()
	if err != nil {
		t.Fatalf("stat error = %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("reused file size = %d, want 0 (not truncated)", info.Size())
	}
	off, err := f2.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("seek error = %v", err)
	}
	if off != 0 {
		t.Errorf("reused file offset = %d, want 0", off)
	}
	p.put(f2)
	p.close()
}

func TestTempFilePool_DiscardsWhenFull(t *testing.T) {
	p := newTempFilePool(t.TempDir(), 1)

	f1, _ := p.get()
	f2, _ := p.get()
	name2 := f2.Name()

	p.put(f1) // fills the single free slot
	p.put(f2) // pool full -> f2 must be closed and removed

	if _, err := os.Stat(name2); !os.IsNotExist(err) {
		t.Errorf("overflow file %s still exists, want removed (stat err = %v)", name2, err)
	}
	p.close()
}

func TestTempFilePool_CloseRemovesIdleFiles(t *testing.T) {
	p := newTempFilePool(t.TempDir(), 4)

	f, _ := p.get()
	name := f.Name()
	p.put(f)

	p.close()

	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Errorf("idle file %s still exists after close, want removed (stat err = %v)", name, err)
	}
}

func TestTempFilePool_ConcurrentGetPut(t *testing.T) {
	p := newTempFilePool(t.TempDir(), 8)
	defer p.close()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				f, err := p.get()
				if err != nil {
					t.Errorf("get() error = %v", err)
					return
				}
				if _, err := f.WriteString("x"); err != nil {
					t.Errorf("write error = %v", err)
					return
				}
				p.put(f)
			}
		}()
	}
	wg.Wait()
}
