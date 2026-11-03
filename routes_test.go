package main

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestExistingRoutes pins the behaviour of every route that existed before WebDAV:
// the admin page and its API must answer exactly as they did.
func TestExistingRoutes(t *testing.T) {
	h := setupServer(t)
	if entries, _ := os.ReadDir(filepath.Dir(dbPath)); len(entries) == 0 {
		t.Fatal("no database file")
	} else {
		for _, e := range entries {
			if strings.Contains(e.Name(), "?") {
				t.Fatalf("DSN options leaked into the file name: %s", e.Name())
			}
		}
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database not at DB_PATH: %v", err)
	}

	t.Run("admin page and health", func(t *testing.T) {
		rec := do(t, h, call{method: "GET", target: "/"})
		expectStatus(t, rec, 200)
		if rec.Body.String() != string(adminHTML) {
			t.Fatal("admin page changed")
		}
		for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy"} {
			if rec.Header().Get(hdr) == "" {
				t.Errorf("missing security header %s", hdr)
			}
		}
		expectStatus(t, do(t, h, call{method: "GET", target: "/inconnu"}), 404)
		rec = do(t, h, call{method: "GET", target: "/up"})
		expectStatus(t, rec, 200)
		if rec.Body.String() != `{"status":"ok"}` {
			t.Fatalf("/up body %q", rec.Body.String())
		}
		rec = do(t, h, call{method: "GET", target: "/api/health"})
		expectStatus(t, rec, 200)
		if decode(t, rec)["status"] != "ok" {
			t.Fatal("/api/health status")
		}
	})

	t.Run("CORS preflight", func(t *testing.T) {
		rec := do(t, h, call{method: "OPTIONS", target: "/api/files", headers: map[string]string{"Origin": "moz-extension://abc"}})
		expectStatus(t, rec, 204)
		if rec.Header().Get("Access-Control-Allow-Origin") != "moz-extension://abc" {
			t.Fatal("CORS origin not reflected")
		}
	})

	t.Run("auth", func(t *testing.T) {
		expectStatus(t, do(t, h, call{"POST", "/api/auth", jsonBody(t, map[string]string{"password": testAdminPassword}), nil}), 200)
		expectStatus(t, do(t, h, call{"POST", "/api/auth", nil, map[string]string{"Authorization": "Bearer " + testAuthToken}}), 200)
		expectStatus(t, do(t, h, call{"POST", "/api/auth", jsonBody(t, map[string]string{"password": "faux"}), nil}), 401)
		expectStatus(t, do(t, h, call{"GET", "/api/auth", nil, nil}), 405)
		// Five attempts per IP and per quarter of an hour, successful or not.
		expectStatus(t, do(t, h, call{"POST", "/api/auth", jsonBody(t, map[string]string{"password": "faux"}), nil}), 401)
		expectStatus(t, do(t, h, call{"POST", "/api/auth", jsonBody(t, map[string]string{"password": testAdminPassword}), nil}), 429)
	})

	t.Run("admin API refuses without token", func(t *testing.T) {
		for _, target := range []string{"/api/files", "/api/upload", "/api/download", "/api/delete", "/api/rename",
			"/api/search", "/api/storage", "/api/mkdir", "/api/publish", "/api/share", "/api/analyze", "/api/meta",
			"/api/shares", "/api/shares/", "/api/suggest"} {
			expectStatus(t, do(t, h, call{method: "GET", target: target}), 401)
		}
		// /api/suggest only takes AUTH_TOKEN, never the admin password.
		expectStatus(t, do(t, h, call{"POST", "/api/suggest", nil, admin()}), 401)
	})

	t.Run("upload, list, download, mkdir", func(t *testing.T) {
		rec := uploadFile(t, h, "docs", "hello.txt", "hello")
		expectStatus(t, rec, 200)
		out := decode(t, rec)
		if out["path"] != "docs/hello.txt" || out["public_url"] != "" || out["success"] != true {
			t.Fatalf("upload answer %v", out)
		}
		rec = do(t, h, call{"GET", "/api/files?path=docs", nil, admin()})
		expectStatus(t, rec, 200)
		out = decode(t, rec)
		items := out["items"].([]interface{})
		if len(items) != 1 || out["current_path"] != "docs" {
			t.Fatalf("listing %v", out)
		}
		item := items[0].(map[string]interface{})
		if item["name"] != "hello.txt" || item["type"] != "file" || item["size"].(float64) != 5 || item["mimetype"] != "text/plain" {
			t.Fatalf("item %v", item)
		}
		rec = do(t, h, call{"GET", "/api/download?path=docs/hello.txt", nil, admin()})
		expectStatus(t, rec, 200)
		if rec.Body.String() != "hello" || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
			t.Fatalf("download %q %q", rec.Body.String(), rec.Header().Get("Content-Disposition"))
		}
		expectStatus(t, do(t, h, call{"GET", "/api/download?path=docs/absent.txt", nil, admin()}), 404)
		expectStatus(t, do(t, h, call{"POST", "/api/mkdir", jsonBody(t, map[string]string{"path": "photos/2026"}), admin()}), 200)
		if fi, err := os.Stat(filepath.Join(filesDir, "photos", "2026")); err != nil || !fi.IsDir() {
			t.Fatal("mkdir did not create the folder")
		}
		expectStatus(t, do(t, h, call{"GET", "/api/upload", nil, admin()}), 405)
	})

	t.Run("meta and tags", func(t *testing.T) {
		expectStatus(t, do(t, h, call{"POST", "/api/meta", jsonBody(t, map[string]interface{}{
			"path": "docs/hello.txt", "description": "un salut", "tags": []string{"salut", "test"}}), admin()}), 200)
		item := decode(t, do(t, h, call{"GET", "/api/files?path=docs", nil, admin()}))["items"].([]interface{})[0].(map[string]interface{})
		if item["description"] != "un salut" || len(item["tags"].([]interface{})) != 2 {
			t.Fatalf("meta not listed: %v", item)
		}
		expectStatus(t, do(t, h, call{"POST", "/api/analyze", jsonBody(t, map[string]string{"path": "docs/hello.txt"}), admin()}), 503)
		expectStatus(t, do(t, h, call{"POST", "/api/suggest", jsonBody(t, map[string]string{}), map[string]string{"Authorization": "Bearer " + testAuthToken}}), 503)
	})

	var fileSlug, shareSlug string

	t.Run("publish /f/", func(t *testing.T) {
		rec := do(t, h, call{"POST", "/api/publish", jsonBody(t, map[string]string{"path": "docs/hello.txt"}), admin()})
		expectStatus(t, rec, 200)
		url := decode(t, rec)["public_url"].(string)
		if !regexp.MustCompile(`^https://cloud\.test/f/[0-9a-f]{10}$`).MatchString(url) {
			t.Fatalf("public url %q", url)
		}
		fileSlug = strings.TrimPrefix(url, testBaseURL+"/f/")
		rec = do(t, h, call{method: "GET", target: "/f/" + fileSlug})
		expectStatus(t, rec, 200)
		if rec.Body.String() != "hello" || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "inline") {
			t.Fatal("/f/ inline")
		}
		rec = do(t, h, call{method: "GET", target: "/f/" + fileSlug + "/dl"})
		if rec.Body.String() != "hello" || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
			t.Fatal("/f/dl")
		}
		expectStatus(t, do(t, h, call{method: "GET", target: "/f/0000000000"}), 404)
		expectStatus(t, do(t, h, call{"POST", "/api/publish", jsonBody(t, map[string]string{"path": "photos"}), admin()}), 400)
	})

	t.Run("share /s/", func(t *testing.T) {
		rec := do(t, h, call{"POST", "/api/share", jsonBody(t, map[string]interface{}{
			"path": "docs/hello.txt", "expires_in": "1d", "max_uses": 2, "label": "pour toi"}), admin()})
		expectStatus(t, rec, 200)
		out := decode(t, rec)
		if !regexp.MustCompile(`^https://cloud\.test/s/[0-9a-f]{16}$`).MatchString(out["url"].(string)) || out["expires_at"] == nil {
			t.Fatalf("share %v", out)
		}
		shareSlug = out["slug"].(string)
		rec = do(t, h, call{method: "GET", target: "/s/" + shareSlug})
		expectStatus(t, rec, 200)
		if !strings.Contains(rec.Body.String(), "hello.txt") || !strings.Contains(rec.Body.String(), "pour toi") {
			t.Fatal("share page content")
		}
		rec = do(t, h, call{method: "GET", target: "/s/" + shareSlug + "/dl"})
		if rec.Body.String() != "hello" {
			t.Fatal("share download")
		}
		expectStatus(t, do(t, h, call{"POST", "/api/share", jsonBody(t, map[string]string{"path": "docs", "expires_in": "bientot"}), admin()}), 400)
		for _, target := range []string{"/api/shares", "/api/shares/"} {
			shares := decode(t, do(t, h, call{"GET", target, nil, admin()}))["shares"].([]interface{})
			if len(shares) != 1 || shares[0].(map[string]interface{})["uses_count"].(float64) != 1 {
				t.Fatalf("shares list %v", shares)
			}
		}
	})

	t.Run("rename keeps links, meta and shares", func(t *testing.T) {
		rec := do(t, h, call{"PUT", "/api/rename", jsonBody(t, map[string]string{"old_path": "docs/hello.txt", "new_name": "bonjour.txt"}), admin()})
		expectStatus(t, rec, 200)
		if decode(t, rec)["new_path"] != "docs/bonjour.txt" {
			t.Fatal("new_path")
		}
		if do(t, h, call{method: "GET", target: "/f/" + fileSlug}).Body.String() != "hello" {
			t.Fatal("/f/ lost after rename")
		}
		if !strings.Contains(do(t, h, call{method: "GET", target: "/s/" + shareSlug}).Body.String(), "bonjour.txt") {
			t.Fatal("share filename not updated")
		}
		if countRows(t, "file_meta", "docs/bonjour.txt") != 1 {
			t.Fatal("meta lost after rename")
		}
		uploadFile(t, h, "docs", "autre.txt", "x")
		expectStatus(t, do(t, h, call{"PUT", "/api/rename", jsonBody(t, map[string]string{"old_path": "docs/autre.txt", "new_name": "bonjour.txt"}), admin()}), 409)
	})

	t.Run("search and storage", func(t *testing.T) {
		out := decode(t, do(t, h, call{"GET", "/api/search?q=BONJ", nil, admin()}))
		if out["count"].(float64) != 1 {
			t.Fatalf("search %v", out)
		}
		expectStatus(t, do(t, h, call{"GET", "/api/search", nil, admin()}), 400)
		rec := do(t, h, call{"GET", "/api/storage", nil, admin()})
		expectStatus(t, rec, 200)
		if decode(t, rec)["storage"].(map[string]interface{})["total"].(float64) <= 0 {
			t.Fatal("storage total")
		}
	})

	t.Run("unpublish, delete share, delete file", func(t *testing.T) {
		expectStatus(t, do(t, h, call{"DELETE", "/api/shares/" + shareSlug, nil, admin()}), 200)
		expectStatus(t, do(t, h, call{"DELETE", "/api/shares/" + shareSlug, nil, admin()}), 404)
		expectStatus(t, do(t, h, call{"DELETE", "/api/publish?path=docs/bonjour.txt", nil, admin()}), 200)
		expectStatus(t, do(t, h, call{method: "GET", target: "/f/" + fileSlug}), 404)
		expectStatus(t, do(t, h, call{"DELETE", "/api/delete?path=docs/bonjour.txt", nil, admin()}), 200)
		if _, err := os.Stat(filepath.Join(filesDir, "docs", "bonjour.txt")); !os.IsNotExist(err) {
			t.Fatal("file still there")
		}
		if countRows(t, "file_meta", "docs/bonjour.txt") != 0 {
			t.Fatal("meta not cleaned")
		}
		expectStatus(t, do(t, h, call{"GET", "/api/delete?path=docs", nil, admin()}), http.StatusMethodNotAllowed)
	})
}
