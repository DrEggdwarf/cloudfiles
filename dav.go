package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/webdav"
)

// WebDAV on /dav/, over filesDir, so any standard client (iji, rclone, a file manager)
// can reach the same files as the admin page. It has its own credentials, never the
// admin password nor AUTH_TOKEN.

const (
	davPrefix = "/dav"
	// PROPFIND, PROPPATCH and LOCK carry small XML bodies.
	maxDAVXMLBytes = 1 << 20
)

var (
	// maxUploadBytes bounds one file, through /api/upload or a WebDAV PUT.
	maxUploadBytes int64 = 512 << 20

	davUser     string
	davPassHash []byte // nil: WebDAV disabled

	// davFailRL counts wrong credentials only: a client sends them on every request.
	davFailRL = newRateLimiter(5, 15*time.Minute)
	davRL     = newRateLimiter(1200, time.Minute)

	davAnalyze      = analyzeFile
	davAnalyzeDelay = 30 * time.Second
	davPendingMu    sync.Mutex
	davPending      = map[string]*time.Timer{}
)

func isDAVPath(p string) bool {
	return p == davPrefix || strings.HasPrefix(p, davPrefix+"/")
}

// configureDAV enables WebDAV for user, whose password is known only by its SHA-256 (hex).
func configureDAV(user, passwordSHA256 string) error {
	davUser, davPassHash = "", nil
	passwordSHA256 = strings.ToLower(strings.TrimSpace(passwordSHA256))
	if user == "" || passwordSHA256 == "" {
		return errors.New("DAV_USER and DAV_PASSWORD_SHA256 are not both set")
	}
	sum, err := hex.DecodeString(passwordSHA256)
	if err != nil || len(sum) != sha256.Size {
		return errors.New("DAV_PASSWORD_SHA256 is not a hex SHA-256 digest")
	}
	for _, secret := range []string{adminPassword, authToken} {
		s := sha256.Sum256([]byte(secret))
		if subtle.ConstantTimeCompare(s[:], sum) == 1 {
			return errors.New("the WebDAV password must differ from ADMIN_PASSWORD and AUTH_TOKEN")
		}
	}
	davUser, davPassHash = user, sum
	return nil
}

// checkDAVCredentials compares fixed-size digests in constant time, user and password both
// evaluated, so neither the length nor the first wrong byte shows in the timing.
func checkDAVCredentials(user, pass string) bool {
	if davPassHash == nil {
		return false
	}
	gotUser := sha256.Sum256([]byte(user))
	wantUser := sha256.Sum256([]byte(davUser))
	gotPass := sha256.Sum256([]byte(pass))
	userOK := subtle.ConstantTimeCompare(gotUser[:], wantUser[:])
	passOK := subtle.ConstantTimeCompare(gotPass[:], davPassHash)
	return userOK&passOK == 1
}

func newDAVHandler() http.Handler {
	dav := &webdav.Handler{
		Prefix:     davPrefix,
		FileSystem: &davFS{root: filesDir},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil && !os.IsNotExist(err) {
				log.Printf("dav %s: %v", r.Method, err)
			}
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A file fetched here in a browser runs sandboxed, away from the admin page's storage.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		if davPassHash == nil {
			http.NotFound(w, r)
			return
		}
		ip := clientIP(r)
		if davFailRL.Exceeded(ip) {
			w.Header().Set("Retry-After", "900")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			challengeDAV(w)
			return
		}
		if !checkDAVCredentials(user, pass) {
			davFailRL.Allow(ip)
			challengeDAV(w)
			return
		}
		if !davRL.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		serveDAV(dav, w, r)
	})
}

func challengeDAV(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="cloudfiles", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func serveDAV(dav *webdav.Handler, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PROPFIND":
		// A whole-tree listing is refused (RFC 4918 §9.1); no header means one level here.
		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Depth"))) {
		case "":
			r.Header.Set("Depth", "1")
		case "infinity":
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>`)
			return
		}
	case "COPY", "MOVE":
		if status := checkDAVDestination(r); status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
	}

	rec := &davResponse{ResponseWriter: w}
	if r.Method == http.MethodPut {
		if r.ContentLength > maxUploadBytes {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		state := &putState{}
		r.Body = &limitedBody{rc: r.Body, left: maxUploadBytes, state: state}
		r = r.WithContext(context.WithValue(r.Context(), putStateKey{}, state))
		rec.state = state
	} else if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxDAVXMLBytes)
	}

	dav.ServeHTTP(rec, r)

	if rec.status < 200 || rec.status >= 300 {
		return
	}
	// DELETE and MOVE update cloud.db inside davFS; PUT and COPY finish here.
	switch r.Method {
	case http.MethodPut:
		scheduleAnalysis(davRel(strings.TrimPrefix(r.URL.Path, davPrefix)))
	case "COPY":
		src, dst, _ := davCopyMovePaths(r)
		if err := copyMeta(src, dst, r.Header.Get("Depth") != "0"); err != nil {
			log.Printf("dav: could not copy meta: %v", err)
		}
	}
}

// davCopyMovePaths returns source and destination as cloud.db paths.
func davCopyMovePaths(r *http.Request) (src, dst string, ok bool) {
	u, err := url.Parse(r.Header.Get("Destination"))
	if err != nil || !isDAVPath(u.Path) {
		return "", "", false
	}
	return davRel(strings.TrimPrefix(r.URL.Path, davPrefix)), davRel(strings.TrimPrefix(u.Path, davPrefix)), true
}

// checkDAVDestination refuses what webdav.Handler would let through: a destination outside
// /dav/, the root itself, or a folder copied or moved into itself (an endless COPY).
func checkDAVDestination(r *http.Request) int {
	if r.Header.Get("Destination") == "" {
		return 0 // webdav.Handler answers 400
	}
	src, dst, ok := davCopyMovePaths(r)
	if !ok {
		return http.StatusBadGateway
	}
	if src == "" || dst == "" {
		return http.StatusForbidden
	}
	if strings.HasPrefix(dst+"/", src+"/") && dst != src {
		return http.StatusForbidden
	}
	return 0
}

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

// scheduleAnalysis runs the same AI analysis as /api/upload, once a file has stopped
// changing: clients often write a file several times in a row.
func scheduleAnalysis(rel string) {
	if rel == "" || strings.HasPrefix(path.Base(rel), ".") {
		return
	}
	davPendingMu.Lock()
	defer davPendingMu.Unlock()
	if t, ok := davPending[rel]; ok {
		t.Stop()
	}
	analyze, full := davAnalyze, filepath.Join(filesDir, filepath.FromSlash(rel))
	davPending[rel] = time.AfterFunc(davAnalyzeDelay, func() {
		davPendingMu.Lock()
		delete(davPending, rel)
		davPendingMu.Unlock()
		if fi, err := os.Stat(full); err != nil || fi.IsDir() || fi.Size() == 0 {
			return
		}
		analyze(rel)
	})
}
