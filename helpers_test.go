package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testAdminPassword = "test-admin-password"
	testAuthToken     = "test-auth-token"
	testBaseURL       = "https://cloud.test"
)

// setupServer gives each test a fresh files dir, database and rate limiters.
func setupServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	filesDir = filepath.Join(dir, "files")
	dbPath = filepath.Join(dir, "cloud.db")
	adminPassword = testAdminPassword
	authToken = testAuthToken
	baseURL = testBaseURL
	anthropicKey = ""
	generalRL = newRateLimiter(10000, time.Minute)
	authRL = newRateLimiter(5, 15*time.Minute)
	uploadRL = newRateLimiter(10000, time.Minute)
	adminFails = newFailGuard(20, 15*time.Minute)
	davFails = newFailGuard(5, 15*time.Minute)
	davRL = newRateLimiter(10000, time.Minute)
	davLinkWrites = newRateLimiter(60, time.Minute)
	davRoot = ""
	davReserveBytes = 256 << 20
	freeBytes = func(string) (int64, error) { return 1 << 40, nil }
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initDB(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initTemplates(); err != nil {
		t.Fatal(err)
	}
	return newServer()
}

type call struct {
	method  string
	target  string
	body    io.Reader
	headers map[string]string
}

func do(t *testing.T, h http.Handler, c call) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(c.method, c.target, c.body)
	req.RemoteAddr = "192.0.2.10:4242"
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func admin(extra ...string) map[string]string {
	h := map[string]string{"Authorization": "Bearer " + testAdminPassword}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

func jsonBody(t *testing.T, v interface{}) io.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", rec.Body.String(), err)
	}
	return out
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d (body %q)", rec.Code, want, rec.Body.String())
	}
}

func uploadFile(t *testing.T, h http.Handler, dir, name, content string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte(content))
	mw.Close()
	target := "/api/upload"
	if dir != "" {
		target += "?path=" + dir
	}
	return do(t, h, call{"POST", target, &buf, admin("Content-Type", mw.FormDataContentType())})
}

func countRows(t *testing.T, table, path string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE path = ?`, path).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func writeFile(t *testing.T, rel, content string) {
	t.Helper()
	full := filepath.Join(filesDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
