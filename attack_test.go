package main

import (
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

// Scenarios found by the attacker review, kept as regression tests.

func plantOrphans(t *testing.T, path, folder string) (fileSlug, shareSlug string) {
	t.Helper()
	fileSlug, shareSlug = "orphan0001", "orphanshare00001"
	if _, err := db.Exec(`INSERT INTO slugs (slug, path, created_at) VALUES (?, ?, '2026-01-01T00:00:00Z')`, fileSlug, path); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO shares (slug, path, filename, created_at, is_folder) VALUES (?, ?, ?, '2026-01-01T00:00:00Z', 1)`, shareSlug, folder, folder); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO file_meta (path, description) VALUES (?, 'ancienne')`, path); err != nil {
		t.Fatal(err)
	}
	return fileSlug, shareSlug
}

func expectGone(t *testing.T, h http.Handler, what string, fileSlug, shareSlug, path string) {
	t.Helper()
	if rec := do(t, h, call{method: "GET", target: "/f/" + fileSlug}); rec.Code != 404 {
		t.Errorf("%s: old /f/ link serves the new file (%d %q)", what, rec.Code, rec.Body.String())
	}
	if rec := do(t, h, call{method: "GET", target: "/s/" + shareSlug + "/dl"}); rec.Code != 404 {
		t.Errorf("%s: old folder share serves the new content (%d)", what, rec.Code)
	}
	if countRows(t, "file_meta", path) != 0 {
		t.Errorf("%s: old meta attached to the new file", what)
	}
}

func TestCreationDoesNotResurrectOrphanLinks(t *testing.T) {
	lockBody := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
	// share is where the orphan share points: the folder, or the file when the folder
	// already exists on disk (then a share on it would be a live one).
	cases := []struct {
		name   string
		share  string
		create func(t *testing.T, h http.Handler)
	}{
		{"MKCOL then PUT", "Projets", func(t *testing.T, h http.Handler) {
			expectStatus(t, davDo(t, h, "MKCOL", "/dav/Projets", ""), 201)
			expectStatus(t, davDo(t, h, "PUT", "/dav/Projets/cv.pdf", "contenu prive"), 201)
		}},
		{"COPY to a new name", "Projets", func(t *testing.T, h http.Handler) {
			writeFile(t, "source/cv.pdf", "contenu prive")
			expectStatus(t, davDo(t, h, "COPY", "/dav/source/", "", "Destination", "/dav/Projets/"), 201)
		}},
		{"LOCK a new name", "Projets/cv.pdf", func(t *testing.T, h http.Handler) {
			os.MkdirAll(filepath.Join(filesDir, "Projets"), 0755) // outside the app, like the old data
			expectStatus(t, davDo(t, h, "LOCK", "/dav/Projets/cv.pdf", lockBody, "Timeout", "Second-60"), 201)
		}},
		{"admin upload", "Projets", func(t *testing.T, h http.Handler) {
			expectStatus(t, uploadFile(t, h, "Projets", "cv.pdf", "contenu prive"), 200)
		}},
		{"admin mkdir", "Projets", func(t *testing.T, h http.Handler) {
			expectStatus(t, do(t, h, call{"POST", "/api/mkdir", jsonBody(t, map[string]string{"path": "Projets/sous"}), admin()}), 200)
			writeFile(t, "Projets/cv.pdf", "contenu prive")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _ := setupDAV(t)
			fileSlug, shareSlug := plantOrphans(t, "Projets/cv.pdf", c.share)
			c.create(t, h)
			expectGone(t, h, c.name, fileSlug, shareSlug, "Projets/cv.pdf")
		})
	}
}

func TestOrphanSweep(t *testing.T) {
	setupServer(t)
	writeFile(t, "garde.txt", "x")
	db.Exec(`INSERT INTO slugs (slug, path, created_at) VALUES ('garde00001', 'garde.txt', 'now'), ('perdu00001', 'perdu.txt', 'now')`)
	db.Exec(`INSERT INTO shares (slug, path, filename, created_at) VALUES ('perdushare000001', 'dossier/perdu', 'perdu', 'now')`)
	db.Exec(`INSERT INTO file_meta (path) VALUES ('garde.txt'), ('../dehors.txt')`)
	if err := sweepOrphanRecords(); err != nil {
		t.Fatal(err)
	}
	if countRows(t, "slugs", "garde.txt") != 1 || countRows(t, "file_meta", "garde.txt") != 1 {
		t.Fatal("live records dropped")
	}
	if countRows(t, "slugs", "perdu.txt") != 0 || countRows(t, "shares", "dossier/perdu") != 0 || countRows(t, "file_meta", "../dehors.txt") != 0 {
		t.Fatal("orphans kept")
	}
	// Once only.
	db.Exec(`INSERT INTO slugs (slug, path, created_at) VALUES ('perdu00002', 'perdu2.txt', 'now')`)
	if err := sweepOrphanRecords(); err != nil || countRows(t, "slugs", "perdu2.txt") != 1 {
		t.Fatal("the sweep ran twice")
	}
}

func TestOrphanSweepSparesAnUnmountedVolume(t *testing.T) {
	setupServer(t)
	for i := 0; i < 6; i++ {
		db.Exec(`INSERT INTO slugs (slug, path, created_at) VALUES (?, ?, 'now')`, fmt.Sprintf("s%09d", i), fmt.Sprintf("f%d.txt", i))
	}
	if err := sweepOrphanRecords(); err == nil {
		t.Fatal("an empty files dir wiped every link")
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM slugs`).Scan(&n)
	if n != 6 {
		t.Fatalf("%d slugs left", n)
	}
}

// breakRecords makes every write on file_meta fail, as a broken database would.
func breakRecords(t *testing.T) {
	t.Helper()
	dbRetryDelays = []time.Duration{0}
	t.Cleanup(func() { dbRetryDelays = []time.Duration{0, 50 * time.Millisecond, 250 * time.Millisecond, time.Second} })
	if _, err := db.Exec(`DROP TABLE file_meta`); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseFailureLeavesNoOrphan(t *testing.T) {
	h, _ := setupDAV(t)
	writeFile(t, "a.txt", "a")
	writeFile(t, "b.txt", "b")
	breakRecords(t)

	if rec := davDo(t, h, "PUT", "/dav/neuf.txt", "x"); rec.Code < 300 {
		t.Fatal("PUT went through without clearing its path")
	}
	if rec := davDo(t, h, "MKCOL", "/dav/neuf", ""); rec.Code < 300 {
		t.Fatal("MKCOL went through without clearing its path")
	}
	if rec := davDo(t, h, "MOVE", "/dav/a.txt", "", "Destination", "/dav/c.txt"); rec.Code < 300 {
		t.Fatal("MOVE kept although its records could not follow")
	}
	if rec := davDo(t, h, "DELETE", "/dav/b.txt", ""); rec.Code < 300 {
		t.Fatal("DELETE went through, leaving its records behind")
	}
	expectStatus(t, do(t, h, call{"PUT", "/api/rename", jsonBody(t, map[string]string{"old_path": "a.txt", "new_name": "c.txt"}), admin()}), 500)
	expectStatus(t, do(t, h, call{"DELETE", "/api/delete?path=b.txt", nil, admin()}), 500)
	expectStatus(t, uploadFile(t, h, "", "neuf.txt", "x"), 500)

	for _, rel := range []string{"neuf.txt", "neuf", "c.txt"} {
		if _, err := os.Lstat(filepath.Join(filesDir, rel)); err == nil {
			t.Errorf("%s exists", rel)
		}
	}
	if readFile(t, "a.txt") != "a" || readFile(t, "b.txt") != "b" {
		t.Fatal("files changed")
	}
	noTempFiles(t)
}

func TestParallelGuessesAreCounted(t *testing.T) {
	h, _ := setupDAV(t)
	counts := map[int]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest("PROPFIND", "/dav/", nil)
			req.RemoteAddr = "198.51.100.7:1"
			req.SetBasicAuth(testDAVUser, "mauvais")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			mu.Lock()
			counts[rec.Code]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if counts[401] > 5 {
		t.Fatalf("%d passwords tested in parallel, limit is 5: %v", counts[401], counts)
	}

	counts = map[int]int{}
	start = make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest("GET", "/api/files", nil)
			req.RemoteAddr = "198.51.100.8:1"
			req.Header.Set("Authorization", "Bearer mauvais")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			mu.Lock()
			counts[rec.Code]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if counts[401] > 20 {
		t.Fatalf("%d admin tokens tested in parallel, limit is 20: %v", counts[401], counts)
	}
}

func TestAdminFailureLimit(t *testing.T) {
	h := setupServer(t)
	good := func() *httptest.ResponseRecorder {
		return do(t, h, call{"GET", "/api/files", nil, admin()})
	}
	for i := 0; i < 30; i++ {
		expectStatus(t, good(), 200) // right tokens never count
	}
	for i := 0; i < 20; i++ {
		expectStatus(t, do(t, h, call{"GET", "/api/files", nil, map[string]string{"Authorization": "Bearer faux"}}), 401)
	}
	expectStatus(t, do(t, h, call{"GET", "/api/files", nil, map[string]string{"Authorization": "Bearer faux"}}), 429)
	expectStatus(t, good(), 429)
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"203.0.113.5:1", nil, "203.0.113.5"},
		{"203.0.113.5:1", []string{"10.0.0.1"}, "203.0.113.5"},            // public peer: header ignored
		{"172.18.0.2:1", []string{"6.6.6.6, 203.0.113.9"}, "203.0.113.9"}, // proxy: its own addition only
		{"172.18.0.2:1", []string{"6.6.6.6", "203.0.113.9"}, "203.0.113.9"},
		{"127.0.0.1:1", []string{"pas-une-ip"}, "127.0.0.1"},
		{"172.18.0.2:1", []string{"2001:db8:1:2:aaaa::1"}, "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:bbbb::7]:1", nil, "2001:db8:1:2::/64"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestForgedForwardedForDoesNotResetTheLimit(t *testing.T) {
	h, _ := setupDAV(t)
	for _, peer := range []string{"198.51.100.7:1", "172.18.0.2:1"} {
		tested := 0
		for i := 0; i < 30; i++ {
			req := httptest.NewRequest("PROPFIND", "/dav/", nil)
			req.RemoteAddr = peer
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.%d.%d, 203.0.113.50", i/10, i%10))
			req.SetBasicAuth(testDAVUser, "mauvais")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == 401 {
				tested++
			}
		}
		if tested > 5 {
			t.Errorf("peer %s: %d guesses by rotating X-Forwarded-For", peer, tested)
		}
	}
}

func TestLimiterMemoryIsBounded(t *testing.T) {
	rl := newRateLimiter(5, time.Hour)
	for i := 0; i < limiterMaxKeys+500; i++ {
		rl.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n > limiterMaxKeys {
		t.Fatalf("%d keys kept", n)
	}
}

func TestPlaceholderSecretsRefused(t *testing.T) {
	setupServer(t)
	for _, c := range [][2]string{{"changeme-admin", testAuthToken}, {testAdminPassword, "changeme-token"}, {"", testAuthToken}, {testAdminPassword, " "}} {
		adminPassword, authToken = c[0], c[1]
		if validateSecrets() == nil {
			t.Errorf("started with %q / %q", c[0], c[1])
		}
	}
	adminPassword, authToken = testAdminPassword, testAuthToken
	if err := validateSecrets(); err != nil {
		t.Fatal(err)
	}
	// An empty token never matches an empty secret.
	adminPassword = ""
	if isAdminSecret("") {
		t.Fatal("empty bearer accepted")
	}
}

func TestDAVLocksAreBounded(t *testing.T) {
	h, _ := setupDAV(t)
	body := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
	rec := davDo(t, h, "LOCK", "/dav/neuf.txt", body, "Timeout", "Infinite")
	expectStatus(t, rec, 201)
	if !strings.Contains(rec.Body.String(), "<D:timeout>Second-3600</D:timeout>") {
		t.Fatalf("lock not capped at an hour: %s", rec.Body.String())
	}

	ls := newBoundedLocks()
	now := time.Now()
	for i := 0; i < davMaxLocks; i++ {
		if _, err := ls.Create(now, webdav.LockDetails{Root: fmt.Sprintf("/f%d", i), Duration: time.Minute, ZeroDepth: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ls.Create(now, webdav.LockDetails{Root: "/de-trop", Duration: time.Minute, ZeroDepth: true}); err == nil {
		t.Fatal("no bound on the number of locks")
	}
	if _, err := ls.Create(now.Add(2*time.Minute), webdav.LockDetails{Root: "/apres", Duration: time.Minute, ZeroDepth: true}); err != nil {
		t.Fatalf("expired locks still counted: %v", err)
	}
}

func TestDAVHostileXML(t *testing.T) {
	h, _ := setupDAV(t)
	writeFile(t, "f.txt", "x")
	n := (maxDAVXMLBytes - 300) / 7
	bodies := map[string][2]string{
		"deep PROPFIND":  {"PROPFIND", `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>` + strings.Repeat("<a>", n/2) + strings.Repeat("</a>", n/2) + `</D:prop></D:propfind>`},
		"deep PROPPATCH": {"PROPPATCH", `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><Z:p xmlns:Z="urn:z">` + strings.Repeat("<a>", n) + strings.Repeat("</a>", n) + `</Z:p></D:prop></D:set></D:propertyupdate>`},
		"entities":       {"PROPFIND", `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><D:propfind xmlns:D="DAV:"><D:prop><D:x>&b;</D:x></D:prop></D:propfind>`},
		"too big":        {"PROPFIND", strings.Repeat(" ", maxDAVXMLBytes+10)},
	}
	for name, b := range bodies {
		start := time.Now()
		rec := davDo(t, h, b[0], "/dav/f.txt", b[1], "Depth", "0")
		if rec.Code < 300 && rec.Code != 207 || time.Since(start) > 3*time.Second {
			t.Errorf("%s: %d in %v", name, rec.Code, time.Since(start))
		}
		if rec.Code == 207 && strings.Contains(rec.Body.String(), "aaaaaaaaaa") {
			t.Errorf("%s: entities expanded", name)
		}
	}
}

func TestDAVDestinationVariants(t *testing.T) {
	h, _ := setupDAV(t)
	expectStatus(t, davDo(t, h, "MKCOL", "/dav/a", ""), 201)
	for _, d := range []string{
		"http://example.com/dav/a/../a/b",
		"http://example.com/dav/./a/b",
		"http://example.com/dav//a/b",
		"http://example.com/dav/a%2Fb",
		"http://example.com/davx/a",
		"/dav/a/b",
	} {
		if rec := davDo(t, h, "COPY", "/dav/a", "", "Destination", d); rec.Code < 300 {
			t.Errorf("COPY into itself through %s: %d", d, rec.Code)
		}
	}
	if rec := davDo(t, h, "COPY", "/dav/a", "", "Destination", "http://example.com/dav/../../etc/x"); rec.Code < 300 {
		if _, err := os.Stat(filepath.Join(filesDir, "etc", "x")); err != nil {
			t.Fatal("copy reported but not inside the root")
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filesDir), "etc")); err == nil {
		t.Fatal("COPY escaped the root")
	}
	entries, _ := os.ReadDir(filepath.Join(filesDir, "a"))
	if len(entries) != 0 {
		t.Fatalf("something was copied into a: %v", entries)
	}
}

func TestDAVDiskSpace(t *testing.T) {
	h, _ := setupDAV(t)
	writeFile(t, "a.txt", "0123456789")
	freeBytes = func(string) (int64, error) { return davReserveBytes + 5, nil }
	expectStatus(t, davDo(t, h, "PUT", "/dav/b.txt", "0123456789"), http.StatusInsufficientStorage)
	expectStatus(t, davDo(t, h, "COPY", "/dav/a.txt", "", "Destination", "/dav/c.txt"), http.StatusInsufficientStorage)
	expectStatus(t, davDo(t, h, "PUT", "/dav/d.txt", "0123"), 201)
	freeBytes = func(string) (int64, error) { return 0, os.ErrPermission }
	expectStatus(t, davDo(t, h, "PUT", "/dav/e.txt", "x"), 201) // unreadable: the write decides
}

func TestDAVRoot(t *testing.T) {
	setupDAV(t)
	writeFile(t, "prive.txt", "SECRET")
	davRoot = "iji"
	h := newServer()
	expectStatus(t, davDo(t, h, "PUT", "/dav/a.txt", "a"), 201)
	if readFile(t, "iji/a.txt") != "a" {
		t.Fatal("not under DAV_ROOT")
	}
	for _, target := range []string{"/dav/../prive.txt", "/dav/prive.txt"} {
		if rec := davDo(t, newDAVHandler(), "GET", target, ""); rec.Code == 200 || strings.Contains(rec.Body.String(), "SECRET") {
			t.Fatalf("%s reached outside DAV_ROOT", target)
		}
	}
	if strings.Contains(davDo(t, h, "PROPFIND", "/dav/", "", "Depth", "1").Body.String(), "prive") {
		t.Fatal("listing shows files outside DAV_ROOT")
	}
	// Records stay keyed from filesDir.
	fileSlug, _ := publishAndShare(t, h, "iji/a.txt")
	expectStatus(t, davDo(t, h, "MOVE", "/dav/a.txt", "", "Destination", "/dav/b.txt"), 201)
	if countRows(t, "slugs", "iji/b.txt") != 1 || do(t, h, call{method: "GET", target: "/f/" + fileSlug}).Body.String() != "a" {
		t.Fatal("records did not follow under DAV_ROOT")
	}
	expectStatus(t, davDo(t, h, "DELETE", "/dav/b.txt", ""), 204)
	if countRows(t, "slugs", "iji/b.txt") != 0 {
		t.Fatal("records left under DAV_ROOT")
	}

	// A DAV_ROOT through a link is refused.
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(filesDir, "lien"))
	davRoot = "lien"
	expectStatus(t, davDo(t, newServer(), "PROPFIND", "/dav/", "", "Depth", "0"), 404)
}

func TestActiveContentIsSandboxed(t *testing.T) {
	h := setupServer(t)
	writeFile(t, "site.html", "<script>alert(1)</script>")
	writeFile(t, "logo.svg", "<svg/>")
	writeFile(t, "doc.pdf", "%PDF")
	for _, name := range []string{"site.html", "logo.svg", "doc.pdf"} {
		url := decode(t, do(t, h, call{"POST", "/api/publish", jsonBody(t, map[string]string{"path": name}), admin()}))["public_url"].(string)
		slug := url[strings.LastIndex(url, "/")+1:]
		share := decode(t, do(t, h, call{"POST", "/api/share", jsonBody(t, map[string]string{"path": name}), admin()}))["slug"].(string)
		for _, target := range []string{"/f/" + slug, "/f/" + slug + "/preview", "/s/" + share + "/preview"} {
			rec := do(t, h, call{method: "GET", target: target})
			expectStatus(t, rec, 200)
			csp := rec.Header().Get("Content-Security-Policy")
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("%s %s: no nosniff", name, target)
			}
			active := name != "doc.pdf"
			if active != strings.Contains(csp, "sandbox") {
				t.Errorf("%s %s: CSP %q", name, target, csp)
			}
			// Mini-sites keep their scripts, in an opaque origin; a share only displays.
			published := strings.HasPrefix(target, "/f/")
			if active && published != strings.Contains(csp, "allow-scripts") {
				t.Errorf("%s %s: CSP %q", name, target, csp)
			}
			if strings.Contains(csp, "allow-same-origin") {
				t.Errorf("%s %s: same origin kept", name, target)
			}
		}
	}
}

func TestContentDispositionKeepsNamesInside(t *testing.T) {
	h := setupServer(t)
	name := "rapport\"; filename=evil.html; x=\"é.txt"
	writeFile(t, name, "x")
	public := decode(t, do(t, h, call{"POST", "/api/publish", jsonBody(t, map[string]string{"path": name}), admin()}))["public_url"].(string)
	slug := public[strings.LastIndex(public, "/")+1:]
	for _, target := range []string{"/f/" + slug + "/dl", "/f/" + slug, "/api/download?path=" + url.QueryEscape(name)} {
		hdrs := admin()
		rec := do(t, h, call{"GET", target, nil, hdrs})
		disp, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
		if err != nil || (disp != "attachment" && disp != "inline") || params["filename"] != name {
			t.Errorf("%s: %q -> %v %v", target, rec.Header().Get("Content-Disposition"), params, err)
		}
	}
}

func TestAINameIsSanitized(t *testing.T) {
	cases := map[[2]string]string{
		{"facture_mars.pdf", "scan.pdf"}:                   "facture_mars.pdf",
		{"résumé été.docx", "x.docx"}:                      "résumé_été.docx",
		{"../../etc/passwd", "a.txt"}:                      "etcpasswd.txt",
		{"<img src=x onerror=alert(1)>.html", "photo.jpg"}: "img_srcx_onerroralert1.jpg",
		{"\"';!.exe", "a.txt"}:                             "",
		{"rapport.html", "rapport.txt"}:                    "rapport.txt",
	}
	for in, want := range cases {
		if got := sanitizeAIName(in[0], in[1]); got != want {
			t.Errorf("%q from %q: %q, want %q", in[0], in[1], got, want)
		}
	}
	if got := sanitizeAIName(strings.Repeat("a", 500)+".txt", "x.txt"); len(got) > 130 {
		t.Errorf("not bounded: %d", len(got))
	}
}

func TestAnalysisSkipsFilesGoneMeanwhile(t *testing.T) {
	setupServer(t)
	anthropicKey = "cle-de-test"
	t.Cleanup(func() { anthropicKey = ""; anthropicCall = callAnthropic })
	writeFile(t, "docs/a.txt", "a")
	reply := `{"description":"d","tags":["t"],"ai_name":"<b>nouveau</b>.exe"}`

	anthropicCall = func(string, int, []map[string]interface{}) (string, error) { return reply, nil }
	analyzeFile("docs//./a.txt")
	var aiName string
	if err := db.QueryRow(`SELECT ai_name FROM file_meta WHERE path = 'docs/a.txt'`).Scan(&aiName); err != nil {
		t.Fatalf("meta not stored under the listing's key: %v", err)
	}
	if aiName != "bnouveaub.txt" {
		t.Fatalf("ai_name %q", aiName)
	}

	writeFile(t, "docs/b.txt", "b")
	anthropicCall = func(string, int, []map[string]interface{}) (string, error) {
		os.Remove(filepath.Join(filesDir, "docs", "b.txt"))
		return reply, nil
	}
	analyzeFile("docs/b.txt")
	if countRows(t, "file_meta", "docs/b.txt") != 0 {
		t.Fatal("meta written for a file deleted during the analysis")
	}
}

func TestMetaNeedsAnExistingFile(t *testing.T) {
	h := setupServer(t)
	expectStatus(t, do(t, h, call{"POST", "/api/meta", jsonBody(t, map[string]interface{}{"path": "absent.txt", "tags": []string{"x"}}), admin()}), 404)
	if countRows(t, "file_meta", "absent.txt") != 0 {
		t.Fatal("meta stored for a missing file")
	}
	writeFile(t, "docs/a.txt", "a")
	expectStatus(t, do(t, h, call{"POST", "/api/meta", jsonBody(t, map[string]interface{}{"path": "docs//a.txt", "tags": []string{"x"}}), admin()}), 200)
	if countRows(t, "file_meta", "docs/a.txt") != 1 {
		t.Fatal("meta not stored under the listing's key")
	}
}

// The admin page must not build JavaScript out of data: no inline handler holds an interpolation.
func TestAdminPageHasNoInterpolatedHandlers(t *testing.T) {
	page := string(adminHTML)
	if m := regexp.MustCompile(`\son[a-z]+="[^"]*\$\{`).FindString(page); m != "" {
		t.Fatalf("inline handler built from data: %s", m)
	}
	if regexp.MustCompile(`(^|[^A-Za-z_])esc\(`).MatchString(page) {
		t.Fatal("the JS-string escaper is back")
	}
	for _, m := range regexp.MustCompile(`data-[a-z-]+="\$\{([^}]*)\}"`).FindAllStringSubmatch(page, -1) {
		if !strings.HasPrefix(m[1], "escAttr(") {
			t.Errorf("unescaped attribute: %s", m[0])
		}
	}
}
