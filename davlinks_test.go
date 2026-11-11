package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The link API of the WebDAV user (davlinks.go): create, list, revoke, and the shared folders.

func linkDo(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	return davDo(t, h, method, target, body, "Content-Type", "application/json")
}

func createLink(t *testing.T, h http.Handler, name, expiresIn string, maxUses interface{}) DAVLink {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{"path": name, "expires_in": expiresIn, "max_uses": maxUses})
	rec := linkDo(t, h, "POST", "/api/dav/links", string(b))
	expectStatus(t, rec, http.StatusCreated)
	var link DAVLink
	if err := json.Unmarshal(rec.Body.Bytes(), &link); err != nil {
		t.Fatal(err)
	}
	return link
}

func listLinks(t *testing.T, h http.Handler, name string) []DAVLink {
	t.Helper()
	rec := linkDo(t, h, "GET", "/api/dav/links?path="+url.QueryEscape(name), "")
	expectStatus(t, rec, 200)
	var out struct{ Links []DAVLink }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Links
}

func sharedFolders(t *testing.T, h http.Handler) []string {
	t.Helper()
	rec := linkDo(t, h, "GET", "/api/dav/shared-folders", "")
	expectStatus(t, rec, 200)
	var out struct{ Folders []string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Folders
}

func TestDAVLinks(t *testing.T) {
	h, _ := setupDAV(t)
	writeFile(t, "docs/plan.pdf", "PLAN")

	mail := createLink(t, h, "/docs/plan.pdf", "30d", nil)
	if !regexp.MustCompile(`^https://cloud\.test/s/[0-9a-f]{16}$`).MatchString(mail.URL) || mail.URL != testBaseURL+"/s/"+mail.Slug {
		t.Fatalf("url %q", mail.URL)
	}
	expires, err := time.Parse(time.RFC3339, *mail.ExpiresAt)
	if err != nil || time.Until(expires) < 30*24*time.Hour-time.Minute || time.Until(expires) > 30*24*time.Hour {
		t.Fatalf("expires_at %v", mail.ExpiresAt)
	}
	if mail.Path != "/docs/plan.pdf" || mail.MaxUses != nil || mail.Status != "active" || mail.UsesCount != 0 {
		t.Fatalf("link %+v", mail)
	}

	// A link made here is an ordinary share: its page, its download, its counters.
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + mail.Slug}), 200)
	if rec := do(t, h, call{method: "GET", target: "/s/" + mail.Slug + "/dl"}); rec.Body.String() != "PLAN" {
		t.Fatalf("download %q", rec.Body.String())
	}
	waitFor(t, func() bool { return listLinks(t, h, "docs/plan.pdf")[0].ViewsCount == 1 })
	if got := listLinks(t, h, "docs/plan.pdf")[0]; got.UsesCount != 1 {
		t.Fatalf("counters %+v", got)
	}

	ten := createLink(t, h, "docs/plan.pdf", "never", 2)
	if ten.ExpiresAt != nil || ten.MaxUses == nil || *ten.MaxUses != 2 {
		t.Fatalf("link %+v", ten)
	}
	if links := listLinks(t, h, "/docs/plan.pdf"); len(links) != 2 || links[0].Slug != mail.Slug || links[1].Slug != ten.Slug {
		t.Fatalf("list %+v", links)
	}
	do(t, h, call{method: "GET", target: "/s/" + ten.Slug + "/dl"})
	do(t, h, call{method: "GET", target: "/s/" + ten.Slug + "/dl"})
	if links := listLinks(t, h, "docs/plan.pdf"); links[1].Status != "exhausted" {
		t.Fatalf("status %+v", links[1])
	}
	// The admin page sees them among the shares.
	if shares := decode(t, do(t, h, call{"GET", "/api/shares", nil, admin()}))["shares"].([]interface{}); len(shares) != 2 {
		t.Fatalf("admin shares %v", shares)
	}

	expectStatus(t, linkDo(t, h, "DELETE", "/api/dav/links/"+mail.Slug, ""), 200)
	expectStatus(t, do(t, h, call{method: "GET", target: "/s/" + mail.Slug}), 404)
	expectStatus(t, linkDo(t, h, "DELETE", "/api/dav/links/"+mail.Slug, ""), 404)
	if links := listLinks(t, h, "docs/plan.pdf"); len(links) != 1 || links[0].Slug != ten.Slug {
		t.Fatalf("after revoke %+v", links)
	}

	expectStatus(t, linkDo(t, h, "GET", "/api/dav/links?path=docs", ""), 400)
	expectStatus(t, linkDo(t, h, "GET", "/api/dav/links?path=docs/absent.pdf", ""), 404)
	expectStatus(t, linkDo(t, h, "PUT", "/api/dav/links", ""), 405)
	expectStatus(t, linkDo(t, h, "PUT", "/api/dav/links/"+ten.Slug, ""), 405)
	if rec := linkDo(t, h, "GET", "/api/dav/links/"+ten.Slug, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"exhausted"`) {
		t.Fatalf("one link: %d %s", rec.Code, rec.Body.String())
	}
	expectStatus(t, linkDo(t, h, "GET", "/api/dav/ailleurs", ""), 404)
	expectStatus(t, linkDo(t, h, "GET", "/api/dav", ""), 404)
}

func TestDAVLinksFollowTheFile(t *testing.T) {
	h, _ := setupDAV(t)
	writeFile(t, "a.txt", "a")
	link := createLink(t, h, "a.txt", "7d", nil)
	expectStatus(t, davDo(t, h, "MOVE", "/dav/a.txt", "", "Destination", "/dav/b.txt"), 201)
	if links := listLinks(t, h, "b.txt"); len(links) != 1 || links[0].Slug != link.Slug || links[0].Path != "/b.txt" {
		t.Fatalf("after MOVE %+v", links)
	}
	expectStatus(t, davDo(t, h, "DELETE", "/dav/b.txt", ""), 204)
	expectStatus(t, linkDo(t, h, "DELETE", "/api/dav/links/"+link.Slug, ""), 404)
	if countRows(t, "shares", "b.txt") != 0 {
		t.Fatal("link left after DELETE")
	}
}

func TestDAVSharedFolders(t *testing.T) {
	h, _ := setupDAV(t)
	for _, f := range []string{"Projets/a.txt", "Projets/sous/b.txt", "Photos/c.jpg", "Ancien/d.txt", "Fini/e.txt", "seul.txt"} {
		writeFile(t, f, "x")
	}
	if got := sharedFolders(t, h); len(got) != 0 {
		t.Fatalf("nothing shared yet: %v", got)
	}
	expectStatus(t, do(t, h, call{"POST", "/api/share", jsonBody(t, map[string]string{"path": "Projets"}), admin()}), 200)
	expectStatus(t, do(t, h, call{"POST", "/api/share", jsonBody(t, map[string]string{"path": "seul.txt"}), admin()}), 200)
	createLink(t, h, "Photos/c.jpg", "never", nil)
	db.Exec(`INSERT INTO shares (slug, path, filename, created_at) VALUES ('ancien0000000001', 'Ancien', 'Ancien', 'now')`)
	db.Exec(`INSERT INTO shares (slug, path, filename, created_at, is_folder, expires_at) VALUES ('fini000000000001', 'Fini', 'Fini', 'now', 1, '2020-01-01T00:00:00Z')`)
	if got := strings.Join(sharedFolders(t, h), ","); got != "/Ancien,/Projets" {
		t.Fatalf("shared folders %q: a live folder share only, an old one by the disk", got)
	}

	davRoot = "Projets"
	h = newServer()
	if got := strings.Join(sharedFolders(t, h), ","); got != "/" {
		t.Fatalf("a share of the root itself: %q", got)
	}
	davRoot = "Projets/sous"
	h = newServer()
	if got := strings.Join(sharedFolders(t, h), ","); got != "/" {
		t.Fatalf("a share above the root: %q", got)
	}
	db.Exec(`DELETE FROM shares WHERE path = 'Projets'`)
	if got := sharedFolders(t, h); len(got) != 0 {
		t.Fatalf("outside the root: %v", got)
	}
	db.Exec(`INSERT INTO shares (slug, path, filename, created_at, is_folder) VALUES ('racine0000000001', '.', 'files', 'now', 1)`)
	if got := strings.Join(sharedFolders(t, h), ","); got != "/" {
		t.Fatalf("the whole files dir shared: %q", got)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}
