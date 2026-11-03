package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed admin.html
var adminHTML []byte

//go:embed file_page.html
var filePageHTML string

// ─── Config ───────────────────────────────────────────────────────────────────

var (
	adminPassword string
	authToken     string
	baseURL       string
	filesDir      string
	dbPath        string
	port          string
	anthropicKey  string
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── Database ─────────────────────────────────────────────────────────────────

var db *sql.DB

func initDB() error {
	var err error
	// Without a busy timeout a write that meets another (e.g. the async view counter of /s/)
	// fails at once with "database is locked" instead of waiting its turn.
	db, err = sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	if _, err = db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return err
	}
	if _, err = db.Exec(`
CREATE TABLE IF NOT EXISTS slugs (
    slug TEXT PRIMARY KEY,
    path TEXT UNIQUE NOT NULL,
    created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
    slug TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL DEFAULT 0,
    mimetype TEXT NOT NULL DEFAULT 'application/octet-stream',
    expires_at DATETIME,
    max_uses INTEGER,
    uses_count INTEGER NOT NULL DEFAULT 0,
    label TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);
`); err != nil {
		return err
	}
	// Add is_folder column if it doesn't exist yet (ignore error if already present)
	db.Exec(`ALTER TABLE shares ADD COLUMN is_folder INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE shares ADD COLUMN views_count INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE shares ADD COLUMN last_viewed_at DATETIME`)
	db.Exec(`ALTER TABLE shares ADD COLUMN last_downloaded_at DATETIME`)
	// File metadata table for AI analysis
	if _, err = db.Exec(`
CREATE TABLE IF NOT EXISTS file_meta (
    path TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    ai_name TEXT NOT NULL DEFAULT '',
    analyzed_at DATETIME
);`); err != nil {
		return err
	}
	// Clean expired shares at startup
	_, err = db.Exec(`DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at < datetime('now')`)
	return err
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
	window  time.Duration
	max     int
}

func newRateLimiter(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string][]time.Time),
		window:  window,
		max:     max,
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			for k, ts := range rl.entries {
				var fresh []time.Time
				for _, t := range ts {
					if now.Sub(t) < rl.window {
						fresh = append(fresh, t)
					}
				}
				if len(fresh) == 0 {
					delete(rl.entries, k)
				} else {
					rl.entries[k] = fresh
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	ts := rl.entries[ip]
	var fresh []time.Time
	for _, t := range ts {
		if now.Sub(t) < rl.window {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= rl.max {
		rl.entries[ip] = fresh
		return false
	}
	fresh = append(fresh, now)
	rl.entries[ip] = fresh
	return true
}

var (
	generalRL = newRateLimiter(120, time.Minute)
	authRL    = newRateLimiter(5, 15*time.Minute)
	uploadRL  = newRateLimiter(20, time.Minute)
)

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx]
	}
	return ip
}

// ─── Security middleware ──────────────────────────────────────────────────────

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS — allow browser extensions and configured origins
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:")
		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(rl *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r)) {
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// adminAuth accepts either ADMIN_PASSWORD or AUTH_TOKEN as Bearer.
func adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !generalRL.Allow(clientIP(r)) {
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		token := extractBearer(r)
		if token != "" && (token == adminPassword || token == authToken) {
			next(w, r)
			return
		}
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// tokenAuth accepts only AUTH_TOKEN (Firefox extension compatibility).
func tokenAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !generalRL.Allow(clientIP(r)) {
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		token := extractBearer(r)
		if token != "" && token == authToken {
			next(w, r)
			return
		}
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": msg})
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// safePath constructs a safe absolute path under base, preventing path traversal.
func safePath(base, rel string) (string, error) {
	if rel == "" || rel == "." {
		return base, nil
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	target := base
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		target = filepath.Join(target, p)
	}
	absBase, _ := filepath.Abs(base)
	absTarget, _ := filepath.Abs(target)
	if !strings.HasPrefix(absTarget, absBase+string(os.PathSeparator)) && absTarget != absBase {
		return "", fmt.Errorf("path traversal detected")
	}
	return target, nil
}

// generateSlug generates n random bytes encoded as hex (n bytes → 2n hex chars).
func generateSlug(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// getOrCreateSlug returns an existing slug for relPath or creates a new one (5 bytes = 10 hex chars).
func getOrCreateSlug(relPath string) (string, error) {
	var slug string
	err := db.QueryRow(`SELECT slug FROM slugs WHERE path = ?`, relPath).Scan(&slug)
	if err == nil {
		return slug, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	for i := 0; i < 10; i++ {
		s, err := generateSlug(5)
		if err != nil {
			return "", err
		}
		var count int
		db.QueryRow(`SELECT COUNT(*) FROM slugs WHERE slug = ?`, s).Scan(&count)
		if count == 0 {
			_, err = db.Exec(`INSERT INTO slugs (slug, path, created_at) VALUES (?, ?, ?)`,
				s, relPath, time.Now().UTC().Format(time.RFC3339))
			if err == nil {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("could not generate unique slug")
}

// getSlug returns the existing slug for relPath, or "" if none exists (no creation).
func getSlug(relPath string) string {
	var slug string
	err := db.QueryRow(`SELECT slug FROM slugs WHERE path = ?`, relPath).Scan(&slug)
	if err != nil {
		return ""
	}
	return slug
}

func fmtSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func mimeFromExt(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	mimes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".bmp":  "image/bmp",
		".ico":  "image/x-icon",
		".pdf":  "application/pdf",
		".txt":  "text/plain",
		".md":   "text/markdown",
		".json": "application/json",
		".xml":  "application/xml",
		".csv":  "text/csv",
		".zip":  "application/zip",
		".rar":  "application/x-rar-compressed",
		".7z":   "application/x-7z-compressed",
		".tar":  "application/x-tar",
		".gz":   "application/gzip",
		".mp4":  "video/mp4",
		".webm": "video/webm",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",
		".mkv":  "video/x-matroska",
		".mp3":  "audio/mpeg",
		".ogg":  "audio/ogg",
		".wav":  "audio/wav",
		".flac": "audio/flac",
		".aac":  "audio/aac",
		".html": "text/html",
		".css":  "text/css",
		".js":   "application/javascript",
		".ts":   "application/typescript",
		".doc":  "application/msword",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xls":  "application/vnd.ms-excel",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".ppt":  "application/vnd.ms-powerpoint",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	}
	if m, ok := mimes[ext]; ok {
		return m
	}
	return "application/octet-stream"
}

func isImageMime(mime string) bool {
	return strings.HasPrefix(mime, "image/")
}

func toRelPath(full string) string {
	rel, err := filepath.Rel(filesDir, full)
	if err != nil {
		return full
	}
	return filepath.ToSlash(rel)
}

// ─── Templates ────────────────────────────────────────────────────────────────

// FilePageData is used for /f/{slug} pages.
type FilePageData struct {
	Filename    string
	Filesize    string
	Mimetype    string
	IsImage     bool
	IsFolder    bool
	PreviewURL  string
	DownloadURL string
	CreatedAt   string
	Error       string
	// Share-specific (unused for file pages, present for shared template)
	Label     string
	ExpiresAt string
	UsesLeft  string
	IsShare   bool
}

// SharePageData reuses FilePageData with IsShare=true.
type SharePageData = FilePageData

var fileTmpl *template.Template

func initTemplates() error {
	var err error
	fileTmpl, err = template.New("page").Parse(filePageHTML)
	if err != nil {
		return fmt.Errorf("page template: %w", err)
	}
	return nil
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(adminHTML)
}

func handleUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "message": "Service is running"})
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Bearer token path
	if bearer := extractBearer(r); bearer != "" {
		if bearer == adminPassword || bearer == authToken {
			jsonOK(w, map[string]bool{"ok": true})
			return
		}
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// JSON body path
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Password == adminPassword || body.Password == authToken {
		jsonOK(w, map[string]bool{"ok": true})
		return
	}
	jsonError(w, "Unauthorized", http.StatusUnauthorized)
}

// FileItem is the JSON representation of a file or folder.
type FileItem struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	Modified    float64  `json:"modified"`
	Type        string   `json:"type"`
	ItemCount   int      `json:"item_count"`
	PublicURL   string   `json:"public_url"`
	Mimetype    string   `json:"mimetype"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	AiName      string   `json:"ai_name"`
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	queryPath := r.URL.Query().Get("path")
	dir, err := safePath(filesDir, queryPath)
	if err != nil {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			jsonError(w, "Could not create directory", http.StatusInternalServerError)
			return
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		jsonError(w, "Could not read directory", http.StatusInternalServerError)
		return
	}

	var folders, files []FileItem
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		rel := toRelPath(fullPath)
		item := FileItem{
			Name:     e.Name(),
			Path:     rel,
			Modified: float64(info.ModTime().Unix()),
		}
		if e.IsDir() {
			item.Type = "folder"
			sub, _ := os.ReadDir(fullPath)
			item.ItemCount = len(sub)
			folders = append(folders, item)
		} else {
			item.Type = "file"
			item.Size = info.Size()
			item.Mimetype = mimeFromExt(e.Name())
			// Slugs are opt-in: only return existing slug, do not create
			slug := getSlug(rel)
			if slug != "" {
				item.PublicURL = baseURL + "/f/" + slug
			}
			files = append(files, item)
		}
	}

	// Load AI metadata for files in bulk
	if len(files) > 0 {
		placeholders := make([]string, len(files))
		args := make([]interface{}, len(files))
		for i, f := range files {
			placeholders[i] = "?"
			args[i] = f.Path
		}
		metaRows, err := db.Query(
			fmt.Sprintf("SELECT path, description, tags, ai_name FROM file_meta WHERE path IN (%s)", strings.Join(placeholders, ",")),
			args...,
		)
		if err == nil {
			defer metaRows.Close()
			type metaEntry struct{ Desc, Tags, AiName string }
			metaMap := make(map[string]metaEntry)
			for metaRows.Next() {
				var path, desc, tags, aiName string
				if err := metaRows.Scan(&path, &desc, &tags, &aiName); err == nil {
					metaMap[path] = metaEntry{desc, tags, aiName}
				}
			}
			for i := range files {
				if m, ok := metaMap[files[i].Path]; ok {
					files[i].Description = m.Desc
					var tags []string
					json.Unmarshal([]byte(m.Tags), &tags)
					files[i].Tags = tags
					files[i].AiName = m.AiName
				}
			}
		}
	}

	sort.Slice(folders, func(i, j int) bool {
		return strings.ToLower(folders[i].Name) < strings.ToLower(folders[j].Name)
	})
	sort.Slice(files, func(i, j int) bool {
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})
	items := append(folders, files...)
	if items == nil {
		items = []FileItem{}
	}

	currentPath := ""
	if queryPath != "" {
		currentPath = filepath.ToSlash(filepath.Clean(queryPath))
	}
	jsonOK(w, map[string]interface{}{
		"success":      true,
		"items":        items,
		"count":        len(items),
		"current_path": currentPath,
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !uploadRL.Allow(clientIP(r)) {
		jsonError(w, "Upload rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		jsonError(w, "Could not parse form (file too large?)", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "No file provided (field: 'file')", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(filepath.Clean(header.Filename))
	if filename == "" || filename == "." {
		jsonError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	queryPath := r.URL.Query().Get("path")
	dir, err := safePath(filesDir, queryPath)
	if err != nil {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		jsonError(w, "Could not create directory", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(dir, filename)
	// Extra traversal check on the final path
	absBase, _ := filepath.Abs(filesDir)
	absDest, _ := filepath.Abs(destPath)
	if !strings.HasPrefix(absDest, absBase+string(os.PathSeparator)) {
		jsonError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	out, err := os.Create(destPath)
	if err != nil {
		jsonError(w, "Could not create file", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		os.Remove(destPath)
		jsonError(w, "Could not write file", http.StatusInternalServerError)
		return
	}
	out.Close()

	rel := toRelPath(destPath)
	// Trigger AI analysis asynchronously
	go analyzeFile(rel)
	// Do not auto-create slug on upload — return empty public_url
	jsonOK(w, map[string]interface{}{
		"success":    true,
		"message":    fmt.Sprintf("File \"%s\" uploaded successfully", filename),
		"filename":   filename,
		"path":       rel,
		"public_url": "",
		"slug":       "",
	})
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	queryPath := r.URL.Query().Get("path")
	if queryPath == "" {
		jsonError(w, "Path required", http.StatusBadRequest)
		return
	}
	full, err := safePath(filesDir, queryPath)
	if err != nil {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		jsonError(w, "File not found", http.StatusNotFound)
		return
	}
	mime := mimeFromExt(info.Name())
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, info.Name()))
	http.ServeFile(w, r, full)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	queryPath := r.URL.Query().Get("path")
	if queryPath == "" {
		jsonError(w, "Path required", http.StatusBadRequest)
		return
	}
	full, err := safePath(filesDir, queryPath)
	if err != nil {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	rel := toRelPath(full)
	if err := os.RemoveAll(full); err != nil {
		jsonError(w, "Could not delete", http.StatusInternalServerError)
		return
	}
	db.Exec(`DELETE FROM slugs WHERE path = ?`, rel)
	db.Exec(`DELETE FROM shares WHERE path = ?`, rel)
	db.Exec(`DELETE FROM file_meta WHERE path = ?`, rel)
	jsonOK(w, map[string]interface{}{"success": true, "message": "Deleted successfully"})
}

func handleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		OldPath string `json:"old_path"`
		NewName string `json:"new_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.OldPath == "" || strings.TrimSpace(body.NewName) == "" {
		jsonError(w, "old_path and new_name required", http.StatusBadRequest)
		return
	}
	newName := filepath.Base(filepath.Clean(body.NewName))
	if newName == "" || newName == "." || newName == ".." {
		jsonError(w, "Invalid new name", http.StatusBadRequest)
		return
	}
	oldFull, err := safePath(filesDir, body.OldPath)
	if err != nil {
		jsonError(w, "Invalid old path", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(oldFull); os.IsNotExist(err) {
		jsonError(w, "File or folder not found", http.StatusNotFound)
		return
	}
	newFull := filepath.Join(filepath.Dir(oldFull), newName)
	absBase, _ := filepath.Abs(filesDir)
	absNew, _ := filepath.Abs(newFull)
	if !strings.HasPrefix(absNew, absBase+string(os.PathSeparator)) {
		jsonError(w, "Invalid new path", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(newFull); err == nil {
		jsonError(w, "A file with that name already exists", http.StatusConflict)
		return
	}
	oldRel := toRelPath(oldFull)
	newRel := toRelPath(newFull)
	if err := os.Rename(oldFull, newFull); err != nil {
		jsonError(w, "Could not rename", http.StatusInternalServerError)
		return
	}
	db.Exec(`UPDATE slugs SET path = ? WHERE path = ?`, newRel, oldRel)
	db.Exec(`UPDATE shares SET path = ?, filename = ? WHERE path = ?`, newRel, newName, oldRel)
	db.Exec(`UPDATE file_meta SET path = ? WHERE path = ?`, newRel, oldRel)
	jsonOK(w, map[string]interface{}{"success": true, "message": "Renamed successfully", "new_path": newRel})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if query == "" {
		jsonError(w, "Query required", http.StatusBadRequest)
		return
	}
	var results []FileItem
	filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == filesDir {
			return nil
		}
		if strings.Contains(strings.ToLower(info.Name()), query) {
			rel := toRelPath(path)
			item := FileItem{
				Name:     info.Name(),
				Path:     rel,
				Modified: float64(info.ModTime().Unix()),
			}
			if info.IsDir() {
				item.Type = "folder"
				sub, _ := os.ReadDir(path)
				item.ItemCount = len(sub)
			} else {
				item.Type = "file"
				item.Size = info.Size()
				item.Mimetype = mimeFromExt(info.Name())
				// Slugs are opt-in: only return existing slug, do not create
				slug := getSlug(rel)
				if slug != "" {
					item.PublicURL = baseURL + "/f/" + slug
				}
			}
			results = append(results, item)
		}
		return nil
	})
	if results == nil {
		results = []FileItem{}
	}
	jsonOK(w, map[string]interface{}{"success": true, "items": results, "count": len(results), "query": r.URL.Query().Get("q")})
}

func handleStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(filesDir, &stat); err != nil {
		jsonError(w, "Could not get disk info", http.StatusInternalServerError)
		return
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bavail) * int64(stat.Bsize)
	used := total - free
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	jsonOK(w, map[string]interface{}{
		"success": true,
		"storage": map[string]interface{}{
			"total":         total,
			"used":          used,
			"free":          free,
			"total_fmt":     fmtSize(total),
			"used_fmt":      fmtSize(used),
			"free_fmt":      fmtSize(free),
			"usage_percent": fmt.Sprintf("%.1f", pct),
		},
	})
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Path) == "" {
		jsonError(w, "Path required", http.StatusBadRequest)
		return
	}
	full, err := safePath(filesDir, body.Path)
	if err != nil {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(full, 0755); err != nil {
		jsonError(w, "Could not create directory", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"success": true, "message": "Directory created", "path": toRelPath(full)})
}

// handlePublish handles POST (create slug) and DELETE (remove slug) for /api/publish.
func handlePublish(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
			jsonError(w, "Path required", http.StatusBadRequest)
			return
		}
		full, err := safePath(filesDir, body.Path)
		if err != nil {
			jsonError(w, "Invalid path", http.StatusBadRequest)
			return
		}
		info, err := os.Stat(full)
		if err != nil {
			jsonError(w, "File not found", http.StatusNotFound)
			return
		}
		if info.IsDir() {
			jsonError(w, "Cannot publish a directory", http.StatusBadRequest)
			return
		}
		rel := toRelPath(full)
		slug, err := getOrCreateSlug(rel)
		if err != nil {
			jsonError(w, "Could not create slug", http.StatusInternalServerError)
			return
		}
		publicURL := baseURL + "/f/" + slug
		jsonOK(w, map[string]interface{}{
			"success":    true,
			"public_url": publicURL,
			"slug":       slug,
		})

	case http.MethodDelete:
		path := r.URL.Query().Get("path")
		if path == "" {
			jsonError(w, "Path required", http.StatusBadRequest)
			return
		}
		full, err := safePath(filesDir, path)
		if err != nil {
			jsonError(w, "Invalid path", http.StatusBadRequest)
			return
		}
		rel := toRelPath(full)
		db.Exec(`DELETE FROM slugs WHERE path = ?`, rel)
		jsonOK(w, map[string]interface{}{"success": true})

	default:
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleCreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Path            string `json:"path"`
		ExpiresIn       string `json:"expires_in"`
		ExpiresAtCustom string `json:"expires_at_custom"`
		MaxUses         int    `json:"max_uses"`
		Label           string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Path == "" {
		jsonError(w, "Path required", http.StatusBadRequest)
		return
	}
	full, err := safePath(filesDir, body.Path)
	if err != nil {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(full)
	if err != nil {
		jsonError(w, "File or folder not found", http.StatusNotFound)
		return
	}

	var expiresAt *time.Time
	switch body.ExpiresIn {
	case "1h":
		t := time.Now().UTC().Add(1 * time.Hour)
		expiresAt = &t
	case "6h":
		t := time.Now().UTC().Add(6 * time.Hour)
		expiresAt = &t
	case "12h":
		t := time.Now().UTC().Add(12 * time.Hour)
		expiresAt = &t
	case "1d":
		t := time.Now().UTC().Add(24 * time.Hour)
		expiresAt = &t
	case "7d":
		t := time.Now().UTC().Add(7 * 24 * time.Hour)
		expiresAt = &t
	case "30d":
		t := time.Now().UTC().Add(30 * 24 * time.Hour)
		expiresAt = &t
	case "never", "":
		expiresAt = nil
	case "custom":
		if body.ExpiresAtCustom == "" {
			jsonError(w, "expires_at_custom required", http.StatusBadRequest)
			return
		}
		var t time.Time
		var parseErr error
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04"} {
			t, parseErr = time.Parse(layout, body.ExpiresAtCustom)
			if parseErr == nil {
				break
			}
		}
		if parseErr != nil {
			jsonError(w, "Invalid expires_at_custom format (use 2026-03-25T18:00)", http.StatusBadRequest)
			return
		}
		t = t.UTC()
		expiresAt = &t
	default:
		jsonError(w, "Invalid expires_in value", http.StatusBadRequest)
		return
	}

	slug, err := generateSlug(8) // 8 bytes = 16 hex chars
	if err != nil {
		jsonError(w, "Could not generate slug", http.StatusInternalServerError)
		return
	}

	rel := toRelPath(full)

	var filename string
	var filesize int64
	var mime string
	var isFolder int

	if info.IsDir() {
		isFolder = 1
		filename = info.Name()
		filesize = 0
		mime = "application/zip"
	} else {
		isFolder = 0
		filename = info.Name()
		filesize = info.Size()
		mime = mimeFromExt(info.Name())
	}

	var expiresAtVal interface{}
	var expiresAtResp string
	if expiresAt != nil {
		expiresAtVal = expiresAt.Format(time.RFC3339)
		expiresAtResp = expiresAt.Format(time.RFC3339)
	}
	var maxUsesVal interface{}
	if body.MaxUses > 0 {
		maxUsesVal = body.MaxUses
	}

	_, err = db.Exec(`INSERT INTO shares (slug, path, filename, filesize, mimetype, expires_at, max_uses, uses_count, label, created_at, is_folder)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		slug, rel, filename, filesize, mime, expiresAtVal, maxUsesVal, body.Label,
		time.Now().UTC().Format(time.RFC3339), isFolder,
	)
	if err != nil {
		jsonError(w, "Could not create share", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"slug":     slug,
		"url":      baseURL + "/s/" + slug,
		"max_uses": body.MaxUses,
		"label":    body.Label,
	}
	if expiresAtResp != "" {
		resp["expires_at"] = expiresAtResp
	}
	jsonOK(w, resp)
}

type ShareItem struct {
	Slug             string `json:"slug"`
	Path             string `json:"path"`
	Filename         string `json:"filename"`
	Filesize         int64  `json:"filesize"`
	ExpiresAt        string `json:"expires_at"`
	MaxUses          *int   `json:"max_uses"`
	UsesCount        int    `json:"uses_count"`
	ViewsCount       int    `json:"views_count"`
	LastViewedAt     string `json:"last_viewed_at"`
	LastDownloadedAt string `json:"last_downloaded_at"`
	Label            string `json:"label"`
	URL              string `json:"url"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at"`
}

func handleListShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := db.Query(`SELECT slug, path, filename, filesize,
		COALESCE(expires_at,''), COALESCE(max_uses,-1), uses_count, label, created_at,
		COALESCE(views_count,0), COALESCE(last_viewed_at,''), COALESCE(last_downloaded_at,'')
		FROM shares ORDER BY created_at DESC`)
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var shares []ShareItem
	for rows.Next() {
		var s ShareItem
		var maxUses int
		if err := rows.Scan(&s.Slug, &s.Path, &s.Filename, &s.Filesize,
			&s.ExpiresAt, &maxUses, &s.UsesCount, &s.Label, &s.CreatedAt,
			&s.ViewsCount, &s.LastViewedAt, &s.LastDownloadedAt); err != nil {
			continue
		}
		if maxUses >= 0 {
			s.MaxUses = &maxUses
		}
		s.URL = baseURL + "/s/" + s.Slug
		s.Status = "active"
		if s.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, s.ExpiresAt); err == nil && time.Now().After(t) {
				s.Status = "expired"
			}
		}
		if s.MaxUses != nil && *s.MaxUses > 0 && s.UsesCount >= *s.MaxUses {
			s.Status = "exhausted"
		}
		shares = append(shares, s)
	}
	if shares == nil {
		shares = []ShareItem{}
	}
	jsonOK(w, map[string]interface{}{"shares": shares})
}

func handleDeleteShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.TrimPrefix(r.URL.Path, "/api/shares/")
	slug = strings.Trim(slug, "/")
	if slug == "" {
		jsonError(w, "Slug required", http.StatusBadRequest)
		return
	}
	res, err := db.Exec(`DELETE FROM shares WHERE slug = ?`, slug)
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, "Share not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]interface{}{"success": true, "message": "Share deleted"})
}

// ─── Public file routes ────────────────────────────────────────────────────────

func renderPage(w http.ResponseWriter, data FilePageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if data.Error != "" {
		w.WriteHeader(http.StatusNotFound)
	}
	fileTmpl.Execute(w, data)
}

func handleFileSlug(w http.ResponseWriter, r *http.Request) {
	// Paths: /f/{slug}  /f/{slug}/dl  /f/{slug}/preview
	trimmed := strings.TrimPrefix(r.URL.Path, "/f/")
	parts := strings.SplitN(trimmed, "/", 2)
	slug := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	var filePath, createdAt string
	err := db.QueryRow(`SELECT path, created_at FROM slugs WHERE slug = ?`, slug).Scan(&filePath, &createdAt)
	if err == sql.ErrNoRows {
		renderPage(w, FilePageData{Error: "Ce fichier n'existe pas ou a été supprimé."})
		return
	}
	if err != nil {
		renderPage(w, FilePageData{Error: "Erreur interne."})
		return
	}

	full, err := safePath(filesDir, filePath)
	if err != nil {
		renderPage(w, FilePageData{Error: "Chemin invalide."})
		return
	}
	info, err := os.Stat(full)
	if err != nil {
		renderPage(w, FilePageData{Error: "Ce fichier n'existe plus sur le serveur."})
		return
	}
	mime := mimeFromExt(info.Name())

	switch action {
	case "dl":
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, info.Name()))
		http.ServeFile(w, r, full)
	case "preview", "":
		// Both bare /f/{slug} and /f/{slug}/preview serve inline
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, info.Name()))
		http.ServeFile(w, r, full)
	default:
		http.NotFound(w, r)
	}
}

var frMonths = [...]string{
	"janvier", "février", "mars", "avril", "mai", "juin",
	"juillet", "août", "septembre", "octobre", "novembre", "décembre",
}

func fmtFrDate(t time.Time) string {
	return fmt.Sprintf("%d %s %d à %02d:%02d",
		t.Day(), frMonths[t.Month()-1], t.Year(), t.Hour(), t.Minute())
}

func handleShareSlug(w http.ResponseWriter, r *http.Request) {
	// Paths: /s/{slug}  /s/{slug}/dl  /s/{slug}/preview
	trimmed := strings.TrimPrefix(r.URL.Path, "/s/")
	parts := strings.SplitN(trimmed, "/", 2)
	slug := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	var (
		filePath  string
		filename  string
		filesize  int64
		mime      string
		expiresAt sql.NullString
		maxUses   sql.NullInt64
		usesCount int
		label     string
		createdAt string
		isFolder  int
	)
	err := db.QueryRow(`SELECT path, filename, filesize, mimetype, expires_at, max_uses, uses_count, label, created_at, is_folder
		FROM shares WHERE slug = ?`, slug).
		Scan(&filePath, &filename, &filesize, &mime, &expiresAt, &maxUses, &usesCount, &label, &createdAt, &isFolder)
	if err == sql.ErrNoRows {
		renderPage(w, FilePageData{IsShare: true, Error: "Ce lien de partage n'existe pas ou a été supprimé."})
		return
	}
	if err != nil {
		renderPage(w, FilePageData{IsShare: true, Error: "Erreur interne."})
		return
	}

	// Check expiry
	if expiresAt.Valid && expiresAt.String != "" {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil && time.Now().After(t) {
			renderPage(w, FilePageData{IsShare: true, Error: "Ce lien de partage a expiré."})
			return
		}
	}
	// Check max uses
	if maxUses.Valid && maxUses.Int64 > 0 && int64(usesCount) >= maxUses.Int64 {
		renderPage(w, FilePageData{IsShare: true, Error: "Ce lien de partage a atteint sa limite de téléchargements."})
		return
	}

	// Track view when page is accessed (not for direct downloads)
	if action == "" || action == "preview" {
		go db.Exec(`UPDATE shares SET views_count = views_count + 1, last_viewed_at = ? WHERE slug = ?`,
			time.Now().UTC().Format(time.RFC3339), slug)
	}

	full, err := safePath(filesDir, filePath)
	if err != nil {
		renderPage(w, FilePageData{IsShare: true, Error: "Chemin invalide."})
		return
	}

	switch action {
	case "dl":
		if isFolder == 1 {
			// Serve folder as zip archive
			if _, err := os.Stat(full); err != nil {
				renderPage(w, FilePageData{IsShare: true, Error: "Ce dossier n'existe plus sur le serveur."})
				return
			}
			db.Exec(`UPDATE shares SET uses_count = uses_count + 1, last_downloaded_at = ? WHERE slug = ?`,
				time.Now().UTC().Format(time.RFC3339), slug)
			zipName := filename + ".zip"
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
			zw := zip.NewWriter(w)
			defer zw.Close()
			filepath.Walk(full, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				rel, err := filepath.Rel(full, path)
				if err != nil {
					return nil
				}
				fw, err := zw.Create(filepath.ToSlash(rel))
				if err != nil {
					return nil
				}
				f, err := os.Open(path)
				if err != nil {
					return nil
				}
				defer f.Close()
				io.Copy(fw, f)
				return nil
			})
		} else {
			if _, err := os.Stat(full); err != nil {
				renderPage(w, FilePageData{IsShare: true, Error: "Ce fichier n'existe plus sur le serveur."})
				return
			}
			db.Exec(`UPDATE shares SET uses_count = uses_count + 1, last_downloaded_at = ? WHERE slug = ?`,
				time.Now().UTC().Format(time.RFC3339), slug)
			w.Header().Set("Content-Type", mime)
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
			http.ServeFile(w, r, full)
		}
	case "preview":
		if isFolder == 1 {
			// Folders have no preview — redirect to page
			http.Redirect(w, r, "/s/"+slug, http.StatusFound)
			return
		}
		if _, err := os.Stat(full); err != nil {
			renderPage(w, FilePageData{IsShare: true, Error: "Ce fichier n'existe plus."})
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filename))
		http.ServeFile(w, r, full)
	default:
		expiresStr := ""
		if expiresAt.Valid && expiresAt.String != "" {
			if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
				expiresStr = fmtFrDate(t)
			}
		}
		usesLeft := ""
		if maxUses.Valid && maxUses.Int64 > 0 {
			left := maxUses.Int64 - int64(usesCount)
			if left < 0 {
				left = 0
			}
			if left == 1 {
				usesLeft = "1 téléchargement restant"
			} else {
				usesLeft = fmt.Sprintf("%d téléchargements restants", left)
			}
		}

		// Count folder items for display
		folderItemCount := 0
		if isFolder == 1 {
			if entries, err := os.ReadDir(full); err == nil {
				folderItemCount = len(entries)
			}
			_ = folderItemCount
		}

		renderPage(w, FilePageData{
			IsShare:     true,
			IsFolder:    isFolder == 1,
			Filename:    filename,
			Filesize:    fmtSize(filesize),
			Mimetype:    mime,
			IsImage:     isImageMime(mime),
			PreviewURL:  "/s/" + slug + "/preview",
			DownloadURL: "/s/" + slug + "/dl",
			Label:       label,
			ExpiresAt:   expiresStr,
			UsesLeft:    usesLeft,
		})
	}
}

// ─── AI Analysis ──────────────────────────────────────────────────────────────

func anthropicCall(model string, maxTokens int, messages []map[string]interface{}) (string, error) {
	body := map[string]interface{}{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   messages,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic: %s", result.Error.Message)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("anthropic: empty response")
	}
	return result.Content[0].Text, nil
}

func analyzeFile(relPath string) {
	if anthropicKey == "" {
		return
	}
	full, err := safePath(filesDir, relPath)
	if err != nil {
		return
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return
	}

	mime := mimeFromExt(info.Name())
	filename := info.Name()
	const maxSize = 5 * 1024 * 1024 // 5 MB

	var userContent []interface{}

	if info.Size() <= maxSize {
		if isImageMime(mime) && (mime == "image/jpeg" || mime == "image/png" || mime == "image/gif" || mime == "image/webp") {
			data, err := os.ReadFile(full)
			if err == nil {
				userContent = append(userContent, map[string]interface{}{
					"type": "image",
					"source": map[string]interface{}{
						"type":       "base64",
						"media_type": mime,
						"data":       base64.StdEncoding.EncodeToString(data),
					},
				})
			}
		} else if mime == "application/pdf" {
			data, err := os.ReadFile(full)
			if err == nil {
				userContent = append(userContent, map[string]interface{}{
					"type": "document",
					"source": map[string]interface{}{
						"type":       "base64",
						"media_type": "application/pdf",
						"data":       base64.StdEncoding.EncodeToString(data),
					},
				})
			}
		} else if strings.HasPrefix(mime, "text/") || mime == "application/json" || mime == "application/xml" {
			data, err := os.ReadFile(full)
			if err == nil {
				text := string(data)
				if len(text) > 8000 {
					text = text[:8000] + "\n[tronqué]"
				}
				userContent = append(userContent, map[string]interface{}{
					"type": "text",
					"text": "Contenu du fichier:\n" + text,
				})
			}
		}
	}

	userContent = append(userContent, map[string]interface{}{
		"type": "text",
		"text": fmt.Sprintf(`Analyse ce fichier nommé "%s" et retourne UNIQUEMENT un objet JSON (sans markdown, sans explication) :
{"description":"description courte","tags":["tag1","tag2","tag3"],"ai_name":"nom_suggere.ext"}
Règles:
- description: 1-2 phrases en français décrivant le contenu
- tags: 3-6 mots-clés pertinents en français, minuscules
- ai_name: nom de fichier propre et descriptif en français avec tirets-bas, en conservant l'extension originale`, filename),
	})

	messages := []map[string]interface{}{
		{"role": "user", "content": userContent},
	}

	text, err := anthropicCall("claude-haiku-4-5-20251001", 512, messages)
	if err != nil {
		log.Printf("analyzeFile %s: %v", relPath, err)
		return
	}

	text = strings.TrimSpace(text)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end == -1 || end <= start {
		log.Printf("analyzeFile %s: no JSON in response", relPath)
		return
	}
	text = text[start : end+1]

	var meta struct {
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		AiName      string   `json:"ai_name"`
	}
	if err := json.Unmarshal([]byte(text), &meta); err != nil {
		log.Printf("analyzeFile %s: JSON parse error: %v", relPath, err)
		return
	}

	tagsJSON, _ := json.Marshal(meta.Tags)
	if _, err := db.Exec(`INSERT OR REPLACE INTO file_meta (path, description, tags, ai_name, analyzed_at) VALUES (?, ?, ?, ?, ?)`,
		relPath, meta.Description, string(tagsJSON), meta.AiName, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("analyzeFile %s: DB error: %v", relPath, err)
	}
}

func handleMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Path        string   `json:"path"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		jsonError(w, "path requis", http.StatusBadRequest)
		return
	}
	tagsJSON, _ := json.Marshal(body.Tags)
	_, err := db.Exec(`INSERT OR REPLACE INTO file_meta (path, description, tags, ai_name, analyzed_at)
		VALUES (?, ?, ?, COALESCE((SELECT ai_name FROM file_meta WHERE path=?), ''), COALESCE((SELECT analyzed_at FROM file_meta WHERE path=?), ?))`,
		body.Path, body.Description, string(tagsJSON), body.Path, body.Path, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"success": true})
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if anthropicKey == "" {
		jsonError(w, "AI non configurée (ANTHROPIC_API_KEY manquante)", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		jsonError(w, "path requis", http.StatusBadRequest)
		return
	}
	go analyzeFile(body.Path)
	jsonOK(w, map[string]interface{}{"success": true, "message": "Analyse en cours..."})
}

type SuggestField struct {
	Label      string `json:"label"`
	Accept     string `json:"accept"`
	NearbyText string `json:"nearbyText"`
	ID         string `json:"id"`
	Name       string `json:"name"`
}

type SuggestRequest struct {
	URL          string         `json:"url"`
	PageTitle    string         `json:"pageTitle"`
	Headings     []string       `json:"headings"`
	UploadFields []SuggestField `json:"uploadFields"`
}

type SuggestResult struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

func handleSuggest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if anthropicKey == "" {
		jsonError(w, "AI non configurée", http.StatusServiceUnavailable)
		return
	}
	var req SuggestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	rows, err := db.Query(`SELECT path, description, tags, ai_name FROM file_meta WHERE description != ''`)
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type fileEntry struct {
		Path, Description, AiName string
		Tags                      []string
	}
	var entries []fileEntry
	for rows.Next() {
		var e fileEntry
		var tagsJSON string
		if err := rows.Scan(&e.Path, &e.Description, &tagsJSON, &e.AiName); err != nil {
			continue
		}
		json.Unmarshal([]byte(tagsJSON), &e.Tags)
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		jsonOK(w, map[string]interface{}{"success": true, "suggestions": []SuggestResult{}})
		return
	}

	var sb strings.Builder
	sb.WriteString("Tu es un système de recommandation de fichiers. Voici le contexte d'une page web :\n\n")
	sb.WriteString(fmt.Sprintf("URL: %s\n", req.URL))
	sb.WriteString(fmt.Sprintf("Titre: %s\n", req.PageTitle))
	if len(req.Headings) > 0 {
		sb.WriteString(fmt.Sprintf("Titres: %s\n", strings.Join(req.Headings, " | ")))
	}
	if len(req.UploadFields) > 0 {
		sb.WriteString("\nChamps d'upload détectés:\n")
		for i, f := range req.UploadFields {
			sb.WriteString(fmt.Sprintf("  %d. label=\"%s\" formats=\"%s\" contexte=\"%s\"\n",
				i+1, f.Label, f.Accept, f.NearbyText))
		}
	}
	sb.WriteString("\nFichiers disponibles:\n")
	for i, e := range entries {
		sb.WriteString(fmt.Sprintf("%d. \"%s\" — %s — tags: [%s]\n",
			i+1, filepath.Base(e.Path), e.Description, strings.Join(e.Tags, ", ")))
	}
	sb.WriteString("\nRetourne UNIQUEMENT un tableau JSON des fichiers pertinents (score > 40), sans markdown:\n")
	sb.WriteString(`[{"path":"chemin/fichier","reason":"raison courte en français","score":95}]`)
	sb.WriteString("\nScore de 0 à 100. Maximum 5 résultats. Si rien n'est pertinent, retourne [].")

	messages := []map[string]interface{}{
		{"role": "user", "content": []interface{}{
			map[string]interface{}{"type": "text", "text": sb.String()},
		}},
	}

	text, err := anthropicCall("claude-haiku-4-5-20251001", 1024, messages)
	if err != nil {
		jsonError(w, "AI error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	text = strings.TrimSpace(text)
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start == -1 || end == -1 {
		jsonOK(w, map[string]interface{}{"success": true, "suggestions": []SuggestResult{}})
		return
	}

	var results []SuggestResult
	if err := json.Unmarshal([]byte(text[start:end+1]), &results); err != nil {
		jsonOK(w, map[string]interface{}{"success": true, "suggestions": []SuggestResult{}})
		return
	}
	for i := range results {
		results[i].Name = filepath.Base(results[i].Path)
	}

	jsonOK(w, map[string]interface{}{"success": true, "suggestions": results})
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func loadConfig() {
	adminPassword = getenv("ADMIN_PASSWORD", "changeme-admin")
	authToken = getenv("AUTH_TOKEN", "changeme-token")
	baseURL = strings.TrimRight(getenv("BASE_URL", "https://cloud.robin-borg.dev"), "/")
	filesDir = getenv("FILES_DIR", "/data/files")
	dbPath = getenv("DB_PATH", "/data/cloud.db")
	port = getenv("PORT", "8080")
	anthropicKey = getenv("ANTHROPIC_API_KEY", "")
}

// newServer builds every route behind the security middleware; main and the tests share it.
func newServer() http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/up", handleUp)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/auth", rateLimitMiddleware(authRL, handleAuth))
	mux.HandleFunc("/f/", handleFileSlug)
	mux.HandleFunc("/s/", handleShareSlug)

	// Admin API (adminAuth = password or token)
	mux.HandleFunc("/api/files", adminAuth(handleFiles))
	mux.HandleFunc("/api/upload", adminAuth(handleUpload))
	mux.HandleFunc("/api/download", adminAuth(handleDownload))
	mux.HandleFunc("/api/delete", adminAuth(handleDelete))
	mux.HandleFunc("/api/rename", adminAuth(handleRename))
	mux.HandleFunc("/api/search", adminAuth(handleSearch))
	mux.HandleFunc("/api/storage", adminAuth(handleStorage))
	mux.HandleFunc("/api/mkdir", adminAuth(handleMkdir))
	mux.HandleFunc("/api/publish", adminAuth(handlePublish))
	mux.HandleFunc("/api/share", adminAuth(handleCreateShare))
	mux.HandleFunc("/api/analyze", adminAuth(handleAnalyze))
	mux.HandleFunc("/api/meta", adminAuth(handleMeta))
	mux.HandleFunc("/api/suggest", tokenAuth(handleSuggest))
	mux.HandleFunc("/api/shares/", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		// /api/shares/ (list) or /api/shares/{slug} (delete)
		path := strings.TrimPrefix(r.URL.Path, "/api/shares/")
		path = strings.Trim(path, "/")
		if path == "" {
			handleListShares(w, r)
		} else {
			handleDeleteShare(w, r)
		}
	}))
	mux.HandleFunc("/api/shares", adminAuth(handleListShares))

	return securityHeaders(mux)
}

func main() {
	loadConfig()

	if err := os.MkdirAll(filesDir, 0755); err != nil {
		log.Fatalf("Could not create files dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Could not create db dir: %v", err)
	}
	if err := initDB(); err != nil {
		log.Fatalf("Database init error: %v", err)
	}
	defer db.Close()
	if err := initTemplates(); err != nil {
		log.Fatalf("Template init error: %v", err)
	}

	handler := newServer()
	log.Printf("Cloud server listening on :%s (base: %s, files: %s)", port, baseURL, filesDir)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
