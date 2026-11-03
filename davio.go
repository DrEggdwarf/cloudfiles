package main

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/webdav"
)

// ─── Request bodies ───────────────────────────────────────────────────────────

type putStateKey struct{}

// putState is written by the body reader and read by atomicFile.Close, both on the
// request goroutine (io.Copy then Close), so it needs no lock.
type putState struct {
	failed   bool
	tooLarge bool
}

var errBodyTooLarge = errors.New("request body too large")

type limitedBody struct {
	rc    io.ReadCloser
	left  int64
	state *putState
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		// One byte more tells "exactly at the limit" from "over it".
		var probe [1]byte
		n, err := b.rc.Read(probe[:])
		if n > 0 {
			b.state.failed, b.state.tooLarge = true, true
			return 0, errBodyTooLarge
		}
		if err != nil && err != io.EOF {
			b.state.failed = true
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if err != nil && err != io.EOF {
		b.state.failed = true
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }

// davResponse records the status for the follow-up work, and turns the 405 that
// webdav.Handler gives a failed copy into 413 when the body was over the limit.
type davResponse struct {
	http.ResponseWriter
	status  int
	state   *putState
	swallow bool
}

func (d *davResponse) WriteHeader(code int) {
	if d.status != 0 {
		return
	}
	if d.state != nil && d.state.tooLarge && code >= 400 {
		code = http.StatusRequestEntityTooLarge
		d.swallow = true
		d.ResponseWriter.WriteHeader(code)
		io.WriteString(d.ResponseWriter, "Request Entity Too Large")
		d.status = code
		return
	}
	d.status = code
	d.ResponseWriter.WriteHeader(code)
}

func (d *davResponse) Write(b []byte) (int, error) {
	if d.status == 0 {
		d.WriteHeader(http.StatusOK)
	}
	if d.swallow {
		return len(b), nil
	}
	return d.ResponseWriter.Write(b)
}

// ─── Disk space ───────────────────────────────────────────────────────────────

// davReserveBytes stays free on the volume after any WebDAV write, for the database and logs.
var davReserveBytes int64 = 256 << 20

var freeBytes = func(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func hasRoom(dir string, need int64) bool {
	free, err := freeBytes(dir)
	if err != nil {
		return true // no reading, no refusal: the write itself fails on a full disk
	}
	return free-need >= davReserveBytes
}

func treeSize(root string) int64 {
	var total int64
	filepath.WalkDir(root, func(_ string, e fs.DirEntry, err error) error {
		if err == nil && e.Type().IsRegular() {
			if info, err := e.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// ─── Locks ────────────────────────────────────────────────────────────────────

const (
	davMaxLockDuration = time.Hour
	davMaxLocks        = 1000
)

// boundedLocks caps every lock at an hour (an "Infinite" one would never go) and their number.
type boundedLocks struct {
	webdav.LockSystem
	mu      sync.Mutex
	expires map[string]time.Time
}

func newBoundedLocks() *boundedLocks {
	return &boundedLocks{LockSystem: webdav.NewMemLS(), expires: map[string]time.Time{}}
}

func capLockDuration(d time.Duration) time.Duration {
	if d < 0 || d > davMaxLockDuration {
		return davMaxLockDuration
	}
	return d
}

func (l *boundedLocks) Create(now time.Time, details webdav.LockDetails) (string, error) {
	details.Duration = capLockDuration(details.Duration)
	l.mu.Lock()
	defer l.mu.Unlock()
	for token, at := range l.expires {
		if !now.Before(at) {
			delete(l.expires, token)
		}
	}
	if len(l.expires) >= davMaxLocks {
		return "", webdav.ErrLocked
	}
	token, err := l.LockSystem.Create(now, details)
	if err == nil {
		l.expires[token] = now.Add(details.Duration)
	}
	return token, err
}

func (l *boundedLocks) Refresh(now time.Time, token string, duration time.Duration) (webdav.LockDetails, error) {
	duration = capLockDuration(duration)
	details, err := l.LockSystem.Refresh(now, token, duration)
	if err == nil {
		l.mu.Lock()
		l.expires[token] = now.Add(duration)
		l.mu.Unlock()
	}
	return details, err
}

func (l *boundedLocks) Unlock(now time.Time, token string) error {
	err := l.LockSystem.Unlock(now, token)
	l.mu.Lock()
	delete(l.expires, token)
	l.mu.Unlock()
	return err
}

// ─── Leftovers ────────────────────────────────────────────────────────────────

// removeDAVLeftovers deletes temporary files a crash may have left behind mid-upload.
func removeDAVLeftovers(root string) {
	filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err == nil && e.Type().IsRegular() && len(e.Name()) > len(davTempPrefix) && e.Name()[:len(davTempPrefix)] == davTempPrefix {
			os.Remove(p)
		}
		return nil
	})
}
