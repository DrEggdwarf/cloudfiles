package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/webdav"
)

// WebDAV on /dav/, over filesDir (or its DAV_ROOT sub-folder), so any standard client
// (iji, rclone, a file manager) reaches the same files as the admin page. It has its own
// credentials, never the admin password nor AUTH_TOKEN.

const (
	davPrefix = "/dav"
	// PROPFIND, PROPPATCH and LOCK carry small XML bodies.
	maxDAVXMLBytes   = 1 << 20
	davMinBcryptCost = 10
)

var (
	// maxUploadBytes bounds one file, through /api/upload or a WebDAV PUT.
	maxUploadBytes int64 = 512 << 20

	davUser     string
	davPassHash []byte // bcrypt; nil: WebDAV disabled
	davRoot     string // DAV_ROOT, relative to filesDir; empty: everything

	// The last accepted credentials, as an HMAC under a key that never leaves this
	// process, so that only the first request pays for bcrypt.
	davGoodMu  sync.Mutex
	davGood    []byte
	davGoodKey = randomKey()

	davFails = newFailGuard(5, 15*time.Minute)
	davRL    = newRateLimiter(1200, time.Minute)

	davAnalyze      = analyzeFile
	davAnalyzeDelay = 30 * time.Second
	davPendingMu    sync.Mutex
	davPending      = map[string]*time.Timer{}
)

func randomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

func isDAVPath(p string) bool {
	return p == davPrefix || strings.HasPrefix(p, davPrefix+"/")
}

// configureDAV enables WebDAV for user, whose password is known only by its bcrypt hash.
func configureDAV(user, bcryptHash string) error {
	davUser, davPassHash = "", nil
	davGoodMu.Lock()
	davGood = nil
	davGoodMu.Unlock()
	// A bcrypt hash is full of '$': env files often need it quoted, and some tools keep the quotes.
	bcryptHash = strings.TrimSpace(bcryptHash)
	if len(bcryptHash) >= 2 && (bcryptHash[0] == '\'' || bcryptHash[0] == '"') && bcryptHash[len(bcryptHash)-1] == bcryptHash[0] {
		bcryptHash = bcryptHash[1 : len(bcryptHash)-1]
	}
	if user == "" || bcryptHash == "" {
		return errors.New("DAV_USER and DAV_PASSWORD_BCRYPT are not both set")
	}
	cost, err := bcrypt.Cost([]byte(bcryptHash))
	if err != nil {
		return errors.New("DAV_PASSWORD_BCRYPT is not a bcrypt hash")
	}
	if cost < davMinBcryptCost {
		return fmt.Errorf("DAV_PASSWORD_BCRYPT has cost %d, below %d", cost, davMinBcryptCost)
	}
	for _, weak := range []string{"", adminPassword, authToken} {
		if bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(weak)) == nil {
			return errors.New("the WebDAV password must not be empty, ADMIN_PASSWORD nor AUTH_TOKEN")
		}
	}
	davUser, davPassHash = user, []byte(bcryptHash)
	return nil
}

func credentialDigest(user, pass string) []byte {
	m := hmac.New(sha256.New, davGoodKey)
	m.Write([]byte(user))
	m.Write([]byte{0})
	m.Write([]byte(pass))
	return m.Sum(nil)
}

func checkDAVCredentials(user, pass string) bool {
	if davPassHash == nil {
		return false
	}
	digest := credentialDigest(user, pass)
	davGoodMu.Lock()
	good := davGood
	davGoodMu.Unlock()
	if good != nil && subtle.ConstantTimeCompare(digest, good) == 1 {
		return true
	}
	userOK := secretEqual(user, davUser)
	passOK := bcrypt.CompareHashAndPassword(davPassHash, []byte(pass)) == nil
	if userOK && passOK {
		davGoodMu.Lock()
		davGood = digest
		davGoodMu.Unlock()
		return true
	}
	return false
}

// runDAVHash reads a password on stdin and prints its bcrypt hash, for DAV_PASSWORD_BCRYPT.
func runDAVHash(in io.Reader, out, errOut io.Writer) int {
	line, err := bufio.NewReader(io.LimitReader(in, 1024)).ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintln(errOut, "could not read the password:", err)
		return 1
	}
	pass := strings.TrimRight(line, "\r\n")
	if pass == "" || len(pass) > 72 {
		fmt.Fprintln(errOut, "the password must be 1 to 72 bytes long")
		return 1
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		fmt.Fprintln(errOut, "could not hash:", err)
		return 1
	}
	fmt.Fprintln(out, string(hash))
	return 0
}

func newDAVHandler() http.Handler {
	fs, err := newDAVFS()
	if err != nil {
		log.Printf("WebDAV disabled: %v", err)
		return http.HandlerFunc(http.NotFound)
	}
	dav := &webdav.Handler{
		Prefix:     davPrefix,
		FileSystem: fs,
		LockSystem: newBoundedLocks(),
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
		key := clientIP(r)
		if davFails.Blocked(key) {
			tooManyDAV(w)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			challengeDAV(w)
			return
		}
		ok, blocked := davFails.Check(key, func() bool { return checkDAVCredentials(user, pass) })
		if blocked {
			tooManyDAV(w)
			return
		}
		if !ok {
			challengeDAV(w)
			return
		}
		if !davRL.Allow(key) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		serveDAV(dav, fs, w, r)
	})
}

func challengeDAV(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="cloudfiles", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func tooManyDAV(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "900")
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

func serveDAV(dav *webdav.Handler, fs *davFS, w http.ResponseWriter, r *http.Request) {
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
	case "LOCK":
		// The lock system caps the duration too, but the answer echoes this header.
		r.Header.Set("Timeout", cappedLockTimeout(r.Header.Get("Timeout")))
	case "COPY", "MOVE":
		if status := checkDAVDestination(r); status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
		if r.Method == "COPY" {
			src, _, _ := davCopyMovePaths(r)
			if full, err := fs.resolve(src); err == nil && !hasRoom(fs.root, treeSize(full)) {
				http.Error(w, "Insufficient Storage", http.StatusInsufficientStorage)
				return
			}
		}
	}

	rec := &davResponse{ResponseWriter: w}
	if r.Method == http.MethodPut {
		if r.ContentLength > maxUploadBytes {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if !hasRoom(fs.root, max(r.ContentLength, 0)) {
			http.Error(w, "Insufficient Storage", http.StatusInsufficientStorage)
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
	// Creations, DELETE and MOVE update cloud.db inside davFS; PUT and COPY finish here.
	switch r.Method {
	case http.MethodPut:
		scheduleAnalysis(fs.dbRel(strings.TrimPrefix(r.URL.Path, davPrefix)))
	case "COPY":
		src, dst, _ := davCopyMovePaths(r)
		if err := copyMeta(fs.dbRel(src), fs.dbRel(dst), r.Header.Get("Depth") != "0"); err != nil {
			log.Printf("dav: could not copy meta: %v", err)
		}
	}
}

// cappedLockTimeout keeps a requested "Second-N" up to an hour; anything else
// (Infinite, nothing, garbage) becomes an hour.
func cappedLockTimeout(v string) string {
	first := strings.TrimSpace(strings.Split(v, ",")[0])
	if n, ok := strings.CutPrefix(first, "Second-"); ok {
		if secs, err := strconv.ParseUint(n, 10, 32); err == nil && secs <= uint64(davMaxLockDuration/time.Second) {
			return first
		}
	}
	return fmt.Sprintf("Second-%d", int(davMaxLockDuration/time.Second))
}

// davCopyMovePaths returns source and destination relative to the WebDAV root.
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
