package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testDAVUser     = "iji"
	testDAVPassword = "un-mot-de-passe-d-application"
)

var (
	hashOnce sync.Once
	hashes   = map[string]string{}
)

// bcryptOf hashes at the lowest accepted cost, once per password for the whole run.
func bcryptOf(t *testing.T, pass string) string {
	t.Helper()
	hashOnce.Do(func() {
		for _, p := range []string{testDAVPassword, testAdminPassword, testAuthToken, ""} {
			h, err := bcrypt.GenerateFromPassword([]byte(p), davMinBcryptCost)
			if err != nil {
				panic(err)
			}
			hashes[p] = string(h)
		}
	})
	h, ok := hashes[pass]
	if !ok {
		t.Fatalf("no precomputed hash for %q", pass)
	}
	return h
}

// setupDAV starts a server with WebDAV on, and returns a channel of analysed paths.
func setupDAV(t *testing.T) (http.Handler, chan string) {
	t.Helper()
	h := setupServer(t)
	if err := configureDAV(testDAVUser, bcryptOf(t, testDAVPassword)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configureDAV("", "") })
	analysed := make(chan string, 16)
	davAnalyze = func(rel string) { analysed <- rel }
	davAnalyzeDelay = 0
	t.Cleanup(func() { davAnalyze = analyzeFile; davAnalyzeDelay = 30 * time.Second })
	return h, analysed
}

func davDo(t *testing.T, h http.Handler, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.20:4242"
	req.SetBasicAuth(testDAVUser, testDAVPassword)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filesDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func noTempFiles(t *testing.T) {
	t.Helper()
	filepath.Walk(filesDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(info.Name(), davTempPrefix) {
			t.Errorf("temporary file left: %s", p)
		}
		return nil
	})
}

func publishAndShare(t *testing.T, h http.Handler, rel string) (fileSlug, shareSlug string) {
	t.Helper()
	url := decode(t, do(t, h, call{"POST", "/api/publish", jsonBody(t, map[string]string{"path": rel}), admin()}))["public_url"].(string)
	fileSlug = url[strings.LastIndex(url, "/")+1:]
	shareSlug = decode(t, do(t, h, call{"POST", "/api/share", jsonBody(t, map[string]string{"path": rel}), admin()}))["slug"].(string)
	expectStatus(t, do(t, h, call{"POST", "/api/meta", jsonBody(t, map[string]interface{}{
		"path": rel, "description": "décrit", "tags": []string{"a"}}), admin()}), 200)
	return fileSlug, shareSlug
}

func TestDAVConfiguration(t *testing.T) {
	h := setupServer(t)
	if err := configureDAV("", ""); err == nil {
		t.Fatal("empty config accepted")
	}
	expectStatus(t, davDo(t, h, "PROPFIND", "/dav/", "", "Depth", "1"), 404)
	sum := sha256.Sum256([]byte(testDAVPassword))
	for name, hash := range map[string]string{
		"not a hash":            "pas-un-hash",
		"a SHA-256 digest":      hex.EncodeToString(sum[:]),
		"a cheap bcrypt":        mustBcrypt(t, testDAVPassword, bcrypt.MinCost),
		"the empty password":    bcryptOf(t, ""),
		"ADMIN_PASSWORD reused": bcryptOf(t, testAdminPassword),
		"AUTH_TOKEN reused":     bcryptOf(t, testAuthToken),
	} {
		if err := configureDAV("iji", hash); err == nil {
			t.Errorf("%s accepted", name)
		}
		if checkDAVCredentials("iji", "") {
			t.Fatalf("%s: empty password opens WebDAV", name)
		}
	}
	if err := configureDAV("iji", "  "+bcryptOf(t, testDAVPassword)+"\n"); err != nil {
		t.Fatalf("padded hash refused: %v", err)
	}
	if err := configureDAV("iji", "'"+bcryptOf(t, testDAVPassword)+"'"); err != nil {
		t.Fatalf("quoted hash refused: %v", err)
	}
	if !checkDAVCredentials("iji", testDAVPassword) || checkDAVCredentials("iji", "") || checkDAVCredentials("IJI", testDAVPassword) {
		t.Fatal("credential check")
	}
	configureDAV("", "")
	if checkDAVCredentials("iji", testDAVPassword) {
		t.Fatal("cached credentials survived a reconfiguration")
	}
}

func mustBcrypt(t *testing.T, pass string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pass), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestDAVHashCommand(t *testing.T) {
	var out, errOut strings.Builder
	if code := runDAVHash(strings.NewReader(testDAVPassword+"\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	hash := strings.TrimSpace(out.String())
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(testDAVPassword)) != nil {
		t.Fatal("hash does not match")
	}
	if cost, _ := bcrypt.Cost([]byte(hash)); cost < davMinBcryptCost {
		t.Fatalf("cost %d", cost)
	}
	if strings.Contains(out.String()+errOut.String(), testDAVPassword) {
		t.Fatal("password echoed")
	}
	for _, bad := range []string{"", "\n", strings.Repeat("x", 73)} {
		if runDAVHash(strings.NewReader(bad), &out, &errOut) == 0 {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDAVAuth(t *testing.T) {
	h, _ := setupDAV(t)
	anon := func(headers ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PROPFIND", "/dav/", nil)
		req.RemoteAddr = "192.0.2.30:1"
		req.Header.Set("Depth", "0")
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	basic := func(user, pass string) string {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth(user, pass)
		return req.Header.Get("Authorization")
	}

	rec := anon()
	expectStatus(t, rec, 401)
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatal("no Basic challenge")
	}
	// The admin secrets never open WebDAV, as Bearer or as Basic.
	expectStatus(t, anon("Authorization", "Bearer "+testAdminPassword), 401)
	expectStatus(t, anon("Authorization", "Bearer "+testAuthToken), 401)
	expectStatus(t, anon("Authorization", basic(testDAVUser, testAdminPassword)), 401)
	expectStatus(t, anon("Authorization", basic("robin", testDAVPassword)), 401)
	expectStatus(t, anon("Authorization", basic(testDAVUser, testDAVPassword)), 207)
	// Good credentials spend nothing; a fifth failure locks the IP, even with the right password.
	for i := 0; i < 10; i++ {
		expectStatus(t, anon("Authorization", basic(testDAVUser, testDAVPassword)), 207)
	}
	for i := 0; i < 3; i++ {
		expectStatus(t, anon("Authorization", basic(testDAVUser, "faux")), 401)
	}
	expectStatus(t, anon("Authorization", basic(testDAVUser, testDAVPassword)), 429)
	// Another address is unaffected.
	expectStatus(t, davDo(t, h, "PROPFIND", "/dav/", "", "Depth", "0"), 207)

	if strings.Contains(rec.Header().Get("WWW-Authenticate")+rec.Body.String(), testDAVPassword) {
		t.Fatal("secret echoed")
	}
}

func TestDAVOptionsLockAndHeaders(t *testing.T) {
	h, _ := setupDAV(t)
	rec := davDo(t, h, "OPTIONS", "/dav/", "", "Origin", "https://evil.example")
	expectStatus(t, rec, 200)
	if !strings.Contains(rec.Header().Get("DAV"), "2") {
		t.Fatalf("DAV header %q", rec.Header().Get("DAV"))
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS on WebDAV")
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatal("WebDAV responses must be sandboxed")
	}
	// OPTIONS without credentials is not the anonymous 204 of the API.
	req := httptest.NewRequest("OPTIONS", "/dav/", nil)
	anon := httptest.NewRecorder()
	h.ServeHTTP(anon, req)
	expectStatus(t, anon, 401)

	writeFile(t, "verrou.txt", "x")
	lockBody := `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
	rec = davDo(t, h, "LOCK", "/dav/verrou.txt", lockBody, "Depth", "0", "Timeout", "Second-60")
	expectStatus(t, rec, 200)
	token := rec.Header().Get("Lock-Token")
	if token == "" {
		t.Fatal("no lock token")
	}
	expectStatus(t, davDo(t, h, "PUT", "/dav/verrou.txt", "y"), 423)
	expectStatus(t, davDo(t, h, "PUT", "/dav/verrou.txt", "y", "If", "("+token+")"), 201)
	expectStatus(t, davDo(t, h, "UNLOCK", "/dav/verrou.txt", "", "Lock-Token", token), 204)
}

func TestDAVPropfind(t *testing.T) {
	h, _ := setupDAV(t)
	writeFile(t, "docs/a.txt", "a")
	writeFile(t, "docs/profond/b.txt", "b")

	rec := davDo(t, h, "PROPFIND", "/dav/docs/", "", "Depth", "1")
	expectStatus(t, rec, 207)
	body := rec.Body.String()
	for _, want := range []string{"/dav/docs/", "/dav/docs/a.txt", "/dav/docs/profond/"} {
		if !strings.Contains(body, "<D:href>"+want+"</D:href>") {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	if strings.Contains(body, "b.txt") {
		t.Fatal("Depth 1 went deeper")
	}
	// No Depth header: one level, not the whole tree.
	rec = davDo(t, h, "PROPFIND", "/dav/", "")
	expectStatus(t, rec, 207)
	if strings.Contains(rec.Body.String(), "a.txt") {
		t.Fatal("missing Depth treated as infinity")
	}
	rec = davDo(t, h, "PROPFIND", "/dav/", "", "Depth", "infinity")
	expectStatus(t, rec, 403)
	if !strings.Contains(rec.Body.String(), "propfind-finite-depth") {
		t.Fatal("no finite-depth precondition")
	}
	expectStatus(t, davDo(t, h, "PROPFIND", "/dav/", "", "Depth", "Infinity"), 403)
	expectStatus(t, davDo(t, h, "PROPFIND", "/dav", "", "Depth", "0"), 207)
	expectStatus(t, davDo(t, h, "PROPFIND", "/dav/absent", "", "Depth", "0"), 404)
}

func TestDAVPut(t *testing.T) {
	h, analysed := setupDAV(t)
	expectStatus(t, davDo(t, h, "PUT", "/dav/notes/a.txt", "bonjour"), 409) // parent missing
	expectStatus(t, davDo(t, h, "MKCOL", "/dav/notes", ""), 201)
	expectStatus(t, davDo(t, h, "PUT", "/dav/notes/a.txt", "bonjour"), 201)
	if readFile(t, "notes/a.txt") != "bonjour" {
		t.Fatal("content")
	}
	select {
	case rel := <-analysed:
		if rel != "notes/a.txt" {
			t.Fatalf("analysed %q", rel)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no analysis after PUT, unlike /api/upload")
	}
	rec := davDo(t, h, "GET", "/dav/notes/a.txt", "")
	expectStatus(t, rec, 200)
	if rec.Body.String() != "bonjour" {
		t.Fatal("GET")
	}
	// The admin page sees it.
	items := decode(t, do(t, h, call{"GET", "/api/files?path=notes", nil, admin()}))["items"].([]interface{})
	if len(items) != 1 || items[0].(map[string]interface{})["name"] != "a.txt" {
		t.Fatalf("admin listing %v", items)
	}

	// Overwriting keeps the public link and the share, like an upload over the same name.
	fileSlug, shareSlug := publishAndShare(t, h, "notes/a.txt")
	expectStatus(t, davDo(t, h, "PUT", "/dav/notes/a.txt", "nouvelle version"), 201)
	if do(t, h, call{method: "GET", target: "/f/" + fileSlug}).Body.String() != "nouvelle version" {
		t.Fatal("/f/ lost after overwrite")
	}
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + shareSlug}), 200)

	expectStatus(t, davDo(t, h, "PUT", "/dav/notes", "x"), 404) // a folder is not a file
	expectStatus(t, davDo(t, h, "PUT", "/dav/", "x"), 404)
	noTempFiles(t)
}

func TestDAVPutTooLarge(t *testing.T) {
	h, _ := setupDAV(t)
	maxUploadBytes = 10
	t.Cleanup(func() { maxUploadBytes = 512 << 20 })
	writeFile(t, "gros.bin", "ancien")

	// Announced size over the limit: refused before reading.
	expectStatus(t, davDo(t, h, "PUT", "/dav/gros.bin", "01234567890"), 413)

	// Unannounced size (chunked): refused on the way, previous version intact.
	req := httptest.NewRequest("PUT", "/dav/gros.bin", io.MultiReader(strings.NewReader("0123456789"), strings.NewReader("X")))
	req.ContentLength = -1
	req.SetBasicAuth(testDAVUser, testDAVPassword)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	expectStatus(t, rec, 413)
	if readFile(t, "gros.bin") != "ancien" {
		t.Fatal("partial upload replaced the file")
	}
	// Exactly at the limit is fine.
	req = httptest.NewRequest("PUT", "/dav/gros.bin", strings.NewReader("0123456789"))
	req.ContentLength = -1
	req.SetBasicAuth(testDAVUser, testDAVPassword)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	expectStatus(t, rec, 201)
	if readFile(t, "gros.bin") != "0123456789" {
		t.Fatal("content at the limit")
	}
	noTempFiles(t)
}

func TestDAVMoveCarriesRecords(t *testing.T) {
	h, _ := setupDAV(t)
	uploadFile(t, h, "docs", "a.txt", "contenu")
	fileSlug, shareSlug := publishAndShare(t, h, "docs/a.txt")
	expectStatus(t, davDo(t, h, "MKCOL", "/dav/archive", ""), 201)

	expectStatus(t, davDo(t, h, "MOVE", "/dav/docs/a.txt", "", "Destination", "https://example.com/dav/archive/b.txt"), 201)
	if readFile(t, "archive/b.txt") != "contenu" {
		t.Fatal("not moved")
	}
	for _, table := range pathTables {
		if countRows(t, table, "docs/a.txt") != 0 || countRows(t, table, "archive/b.txt") != 1 {
			t.Fatalf("%s did not follow the move", table)
		}
	}
	if do(t, h, call{method: "GET", target: "/f/" + fileSlug}).Body.String() != "contenu" {
		t.Fatal("/f/ link broken by MOVE")
	}
	if !strings.Contains(do(t, h, call{method: "GET", target: "/s/" + shareSlug}).Body.String(), "b.txt") {
		t.Fatal("share page shows the old name")
	}
	item := decode(t, do(t, h, call{"GET", "/api/files?path=archive", nil, admin()}))["items"].([]interface{})[0].(map[string]interface{})
	if item["description"] != "décrit" {
		t.Fatalf("meta lost: %v", item)
	}

	// A folder carries everything under it.
	expectStatus(t, davDo(t, h, "MOVE", "/dav/archive/", "", "Destination", "/dav/ancien/"), 201)
	if countRows(t, "slugs", "ancien/b.txt") != 1 || countRows(t, "file_meta", "ancien/b.txt") != 1 || countRows(t, "shares", "ancien/b.txt") != 1 {
		t.Fatal("descendants did not follow the folder")
	}

	// Overwriting a destination drops what was known about the replaced file.
	uploadFile(t, h, "", "c.txt", "c")
	_, cShare := publishAndShare(t, h, "c.txt")
	expectStatus(t, davDo(t, h, "MOVE", "/dav/ancien/b.txt", "", "Destination", "/dav/c.txt", "Overwrite", "T"), 204)
	if countRows(t, "slugs", "c.txt") != 1 || countRows(t, "shares", "c.txt") != 1 {
		t.Fatal("records at destination")
	}
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + cShare}), 404)
	if do(t, h, call{method: "GET", target: "/f/" + fileSlug}).Body.String() != "contenu" {
		t.Fatal("moved file lost its link")
	}
}

func TestDAVCopyCopiesMetaOnly(t *testing.T) {
	h, _ := setupDAV(t)
	uploadFile(t, h, "docs", "a.txt", "contenu")
	publishAndShare(t, h, "docs/a.txt")
	expectStatus(t, davDo(t, h, "COPY", "/dav/docs/", "", "Destination", "/dav/copie/"), 201)
	if readFile(t, "copie/a.txt") != "contenu" {
		t.Fatal("not copied")
	}
	if countRows(t, "file_meta", "copie/a.txt") != 1 {
		t.Fatal("meta not copied")
	}
	if countRows(t, "slugs", "copie/a.txt") != 0 || countRows(t, "shares", "copie/a.txt") != 0 {
		t.Fatal("a copy must not inherit public links")
	}
	if countRows(t, "slugs", "docs/a.txt") != 1 || countRows(t, "shares", "docs/a.txt") != 1 {
		t.Fatal("original lost its links")
	}
	noTempFiles(t)
}

func TestDAVDeleteCleansRecords(t *testing.T) {
	h, _ := setupDAV(t)
	uploadFile(t, h, "docs", "a.txt", "contenu")
	fileSlug, shareSlug := publishAndShare(t, h, "docs/a.txt")
	uploadFile(t, h, "docs/sous", "b.txt", "b")
	_, bShare := publishAndShare(t, h, "docs/sous/b.txt")
	uploadFile(t, h, "", "docs-voisin.txt", "v")
	_, neighbour := publishAndShare(t, h, "docs-voisin.txt")

	expectStatus(t, davDo(t, h, "DELETE", "/dav/docs/a.txt", ""), 204)
	for _, table := range pathTables {
		if countRows(t, table, "docs/a.txt") != 0 {
			t.Fatalf("%s still knows the deleted file", table)
		}
	}
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + shareSlug}), 404)
	expectStatus(t, do(t, h, call{method: "GET", target: "/f/" + fileSlug}), 404)

	expectStatus(t, davDo(t, h, "DELETE", "/dav/docs", ""), 204)
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + bShare}), 404)
	if countRows(t, "file_meta", "docs/sous/b.txt") != 0 {
		t.Fatal("descendant meta left")
	}
	// A sibling sharing the prefix is untouched.
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + neighbour}), 200)
	expectStatus(t, davDo(t, h, "DELETE", "/dav/", ""), 405)
	expectStatus(t, davDo(t, h, "DELETE", "/dav/absent", ""), 404)
}

func TestDAVTraversalRefused(t *testing.T) {
	h, _ := setupDAV(t)
	outside := filepath.Join(filepath.Dir(filesDir), "dehors")
	os.MkdirAll(outside, 0755)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0644)
	writeFile(t, "a.txt", "a")

	leaks := func(rec *httptest.ResponseRecorder) bool {
		return strings.Contains(rec.Body.String(), "SECRET")
	}

	// Dot segments, plain or encoded, through the server and straight into the handler.
	direct := newDAVHandler()
	for _, target := range []string{"/dav/../dehors/secret.txt", "/dav/%2e%2e/dehors/secret.txt", "/dav/..%2fdehors/secret.txt", "/dav/a/../../dehors/secret.txt"} {
		for _, handler := range []http.Handler{h, direct} {
			rec := davDo(t, handler, "GET", target, "")
			if rec.Code == 200 || leaks(rec) {
				t.Fatalf("%s: %d %q", target, rec.Code, rec.Body.String())
			}
		}
	}
	rec := davDo(t, direct, "PUT", "/dav/../../evade.txt", "x")
	if _, err := os.Stat(filepath.Join(filepath.Dir(filesDir), "evade.txt")); err == nil {
		t.Fatal("PUT escaped the root")
	}
	if rec.Code == 201 {
		os.Remove(filepath.Join(filesDir, "evade.txt")) // landed inside the root, which is fine
	}

	// Destinations outside /dav/ or on another host.
	expectStatus(t, davDo(t, h, "MOVE", "/dav/a.txt", "", "Destination", "/api/files"), 502)
	expectStatus(t, davDo(t, h, "COPY", "/dav/a.txt", "", "Destination", "https://ailleurs.example/dav/b.txt"), 502)
	rec = davDo(t, h, "COPY", "/dav/a.txt", "", "Destination", "/dav/../../evade2.txt")
	if _, err := os.Stat(filepath.Join(filepath.Dir(filesDir), "evade2.txt")); err == nil {
		t.Fatal("COPY escaped the root")
	}

	// Symbolic links, to a folder or a file, are neither followed nor listed.
	if err := os.Symlink(outside, filepath.Join(filesDir, "lien")); err != nil {
		t.Fatal(err)
	}
	os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(filesDir, "lien.txt"))
	for _, target := range []string{"/dav/lien/secret.txt", "/dav/lien.txt", "/dav/lien/"} {
		for _, method := range []string{"GET", "PROPFIND"} {
			if rec := davDo(t, h, method, target, "", "Depth", "1"); rec.Code < 300 || leaks(rec) {
				t.Fatalf("%s %s: %d", method, target, rec.Code)
			}
		}
	}
	if rec := davDo(t, h, "PROPFIND", "/dav/", "", "Depth", "1"); strings.Contains(rec.Body.String(), "lien") {
		t.Fatal("links listed")
	}
	if rec := davDo(t, h, "PUT", "/dav/lien/nouveau.txt", "x"); rec.Code < 300 {
		t.Fatal("PUT through a link")
	}
	if rec := davDo(t, h, "PUT", "/dav/lien.txt", "ecrase"); rec.Code < 300 {
		t.Fatal("PUT over a link")
	}
	if rec := davDo(t, h, "MOVE", "/dav/a.txt", "", "Destination", "/dav/lien/a.txt"); rec.Code < 300 {
		t.Fatal("MOVE into a link")
	}
	if rec := davDo(t, h, "COPY", "/dav/lien/secret.txt", "", "Destination", "/dav/vole.txt"); rec.Code < 300 {
		t.Fatal("COPY out of a link")
	}
	if rec := davDo(t, h, "DELETE", "/dav/lien/secret.txt", ""); rec.Code < 300 {
		t.Fatal("DELETE through a link")
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "secret.txt")); string(b) != "SECRET" {
		t.Fatal("outside file touched")
	}
	if _, err := os.Stat(filepath.Join(outside, "nouveau.txt")); err == nil {
		t.Fatal("file written outside")
	}

	// A folder into itself, the root, in-flight uploads, NUL bytes.
	os.MkdirAll(filepath.Join(filesDir, "dossier"), 0755)
	expectStatus(t, davDo(t, h, "COPY", "/dav/dossier/", "", "Destination", "/dav/dossier/sous/"), 403)
	expectStatus(t, davDo(t, h, "MOVE", "/dav/dossier/", "", "Destination", "/dav/dossier/sous/"), 403)
	expectStatus(t, davDo(t, h, "MOVE", "/dav/", "", "Destination", "/dav/racine/"), 403)
	expectStatus(t, davDo(t, h, "COPY", "/dav/a.txt", "", "Destination", "/dav/"), 403)
	writeFile(t, davTempPrefix+"123", "en cours")
	expectStatus(t, davDo(t, h, "GET", "/dav/"+davTempPrefix+"123", ""), 404)
	if rec := davDo(t, h, "GET", "/dav/a%00.txt", ""); rec.Code == 200 {
		t.Fatal("NUL byte accepted")
	}
}

func TestAdminAPIFolderRecords(t *testing.T) {
	h := setupServer(t)
	uploadFile(t, h, "docs/sous", "b.txt", "b")
	_, share := publishAndShare(t, h, "docs/sous/b.txt")
	expectStatus(t, do(t, h, call{"PUT", "/api/rename", jsonBody(t, map[string]string{"old_path": "docs", "new_name": "papiers"}), admin()}), 200)
	if countRows(t, "shares", "papiers/sous/b.txt") != 1 || countRows(t, "file_meta", "papiers/sous/b.txt") != 1 {
		t.Fatal("renaming a folder must carry its files' records")
	}
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + share + "/dl"}), 200)
	for _, root := range []string{".", "..", "/", "./"} {
		expectStatus(t, do(t, h, call{"DELETE", "/api/delete?path=" + root, nil, admin()}), 400)
	}
	if _, err := os.Stat(filepath.Join(filesDir, "papiers", "sous", "b.txt")); err != nil {
		t.Fatal("root deletion went through")
	}
	expectStatus(t, do(t, h, call{"DELETE", "/api/delete?path=papiers", nil, admin()}), 200)
	if countRows(t, "shares", "papiers/sous/b.txt") != 0 {
		t.Fatal("deleting a folder must clean its files' records")
	}
}
