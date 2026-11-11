package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The link API of the WebDAV user, under /api/dav/: what iji needs to share a file of its WebDAV folder by a link,
// and to keep away from folders that are already public. The WebDAV credentials open it, never ADMIN_PASSWORD nor
// AUTH_TOKEN, and it sees only the WebDAV root (DAV_ROOT): a path is a WebDAV name, resolved as WebDAV does (no way
// out, no symbolic link). It makes download links (/s/) to files only, and lists or revokes only those it made.

const (
	davLinksPrefix   = "/api/dav/"
	davLinkBodyBytes = 4 << 10
	davLinkMaxUses   = 1000
	// davMaxLinks bounds the live links the WebDAV user holds at once (expired ones do not count).
	davMaxLinks = 1000
)

var (
	// davLinkWrites bounds creations and revocations per client, on top of davRL.
	davLinkWrites   = newRateLimiter(60, time.Minute)
	davLinkSlug     = regexp.MustCompile(`^[0-9a-f]{16}$`)
	davLinkLifetime = map[string]time.Duration{"1d": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "never": 0}

	errNotAFile = errors.New("not a file")
)

func isDAVLinksPath(p string) bool {
	return p == strings.TrimSuffix(davLinksPrefix, "/") || strings.HasPrefix(p, davLinksPrefix)
}

// davCreator marks the shares made through this API: it never lists nor revokes another one. It does not name
// the WebDAV user, so that renaming DAV_USER keeps them its own.
func davCreator() string { return "dav" }

// DAVLink is a share made through this API. Path is its WebDAV name.
type DAVLink struct {
	Slug       string  `json:"slug"`
	URL        string  `json:"url"`
	Path       string  `json:"path"`
	ExpiresAt  *string `json:"expires_at"`
	MaxUses    *int    `json:"max_uses"`
	UsesCount  int     `json:"uses_count"`
	ViewsCount int     `json:"views_count"`
	Status     string  `json:"status"`
	CreatedAt  string  `json:"created_at"`
}

func newDAVLinksHandler() http.Handler {
	fs, err := newDAVFS()
	if err != nil {
		// newDAVHandler logs why
		return http.HandlerFunc(http.NotFound)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if davPassHash == nil {
			http.NotFound(w, r)
			return
		}
		// A JSON answer, and no WWW-Authenticate: a browser neither prompts nor reuses a WebDAV login here.
		switch davAuthenticate(r) {
		case davAuthRefused:
			jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		case davAuthBlocked:
			w.Header().Set("Retry-After", "900")
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		case davAuthBusy:
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		switch p := r.URL.Path; {
		case p == davLinksPrefix+"links" && r.Method == http.MethodGet:
			listDAVLinks(fs, w, r)
		case p == davLinksPrefix+"links" && r.Method == http.MethodPost:
			createDAVLink(fs, w, r)
		case strings.HasPrefix(p, davLinksPrefix+"links/") && r.Method == http.MethodGet:
			getDAVLink(fs, w, strings.TrimPrefix(p, davLinksPrefix+"links/"))
		case strings.HasPrefix(p, davLinksPrefix+"links/") && r.Method == http.MethodDelete:
			revokeDAVLink(fs, w, r, strings.TrimPrefix(p, davLinksPrefix+"links/"))
		case p == davLinksPrefix+"shared-folders" && r.Method == http.MethodGet:
			listSharedFolders(fs, w)
		case p == davLinksPrefix+"links" || strings.HasPrefix(p, davLinksPrefix+"links/") || p == davLinksPrefix+"shared-folders":
			jsonError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		default:
			jsonError(w, "Not Found", http.StatusNotFound)
		}
	})
}

// davLinkTargetError answers for a path that is not a file of the root; outside, through a link or missing all look
// the same.
func davLinkTargetError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNotAFile) {
		jsonError(w, "Not a file", http.StatusBadRequest)
		return
	}
	jsonError(w, "File not found", http.StatusNotFound)
}

// listDAVLinks gives the links this API made for a file, live or not, each with its status.
func listDAVLinks(fs *davFS, w http.ResponseWriter, r *http.Request) {
	rel, err := fs.linkTarget(r.URL.Query().Get("path"))
	if err != nil {
		davLinkTargetError(w, err)
		return
	}
	rows, err := db.Query(`SELECT slug, path, COALESCE(expires_at,''), COALESCE(max_uses,-1), uses_count,
		COALESCE(views_count,0), created_at FROM shares WHERE path = ? AND created_by = ? AND is_folder = 0
		ORDER BY rowid`, rel, davCreator())
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	links := []DAVLink{}
	for rows.Next() {
		link, err := scanDAVLink(fs, rows)
		if err != nil {
			jsonError(w, "Database error", http.StatusInternalServerError)
			return
		}
		links = append(links, link)
	}
	if rows.Err() != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"links": links})
}

// createDAVLink makes a download link (/s/) to a file of the root: a lifetime from a closed list, at most 1000
// downloads or none, an address drawn at random. A JSON body only: a cross-site form cannot post here.
func createDAVLink(fs *davFS, w http.ResponseWriter, r *http.Request) {
	if !davLinkWrites.Allow(clientIP(r)) {
		jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		jsonError(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Path      string `json:"path"`
		ExpiresIn string `json:"expires_in"`
		MaxUses   *int   `json:"max_uses"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, davLinkBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	lifetime, ok := davLinkLifetime[body.ExpiresIn]
	if !ok {
		jsonError(w, "expires_in must be 1d, 7d, 30d or never", http.StatusBadRequest)
		return
	}
	if body.MaxUses != nil && (*body.MaxUses < 1 || *body.MaxUses > davLinkMaxUses) {
		jsonError(w, "max_uses must be 1 to 1000, or null", http.StatusBadRequest)
		return
	}
	rel, err := fs.linkTarget(body.Path)
	if err != nil {
		davLinkTargetError(w, err)
		return
	}
	info, err := os.Lstat(filepath.Join(filesDir, filepath.FromSlash(rel)))
	if err != nil || !info.Mode().IsRegular() {
		jsonError(w, "File not found", http.StatusNotFound)
		return
	}
	now := time.Now().UTC()
	var expiresAt, maxUses interface{}
	if lifetime > 0 {
		expiresAt = now.Add(lifetime).Format(time.RFC3339)
	}
	if body.MaxUses != nil {
		maxUses = *body.MaxUses
	}
	slug, err := insertDAVLink(rel, info, expiresAt, maxUses, now)
	if errors.Is(err, errTooManyLinks) {
		jsonError(w, "Too many links", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		jsonError(w, "Could not create link", http.StatusInternalServerError)
		return
	}
	link, err := scanDAVLink(fs, db.QueryRow(`SELECT slug, path, COALESCE(expires_at,''), COALESCE(max_uses,-1),
		uses_count, COALESCE(views_count,0), created_at FROM shares WHERE slug = ?`, slug))
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(link)
}

var errTooManyLinks = errors.New("too many links")

// insertDAVLink counts the live links and inserts in one statement, so parallel creations cannot pass the bound.
func insertDAVLink(rel string, info os.FileInfo, expiresAt, maxUses interface{}, now time.Time) (string, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var slug string
		if slug, err = generateSlug(8); err != nil {
			return "", err
		}
		var res sql.Result
		res, err = db.Exec(`INSERT INTO shares (slug, path, filename, filesize, mimetype, expires_at, max_uses,
			uses_count, label, created_at, is_folder, created_by)
			SELECT ?, ?, ?, ?, ?, ?, ?, 0, '', ?, 0, ?
			WHERE (SELECT COUNT(*) FROM shares WHERE created_by = ? AND (expires_at IS NULL OR expires_at > ?)) < ?`,
			slug, rel, info.Name(), info.Size(), mimeFromExt(info.Name()), expiresAt, maxUses,
			now.Format(time.RFC3339), davCreator(), davCreator(), now.Format(time.RFC3339), davMaxLinks)
		if err != nil {
			continue // a slug already taken: draw another
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return "", errTooManyLinks
		}
		return slug, nil
	}
	return "", err
}

var errNotManaged = errors.New("not managed here")

// ownDAVLink finds a link this API made, in the WebDAV root. A slug no share has is sql.ErrNoRows; a share it did not
// make, or now outside the root, is errNotManaged: it is still live, the client must not take it for gone.
func ownDAVLink(fs *davFS, slug string) (string, error) {
	if !davLinkSlug.MatchString(slug) {
		return "", sql.ErrNoRows
	}
	var rel, createdBy string
	var isFolder int
	err := db.QueryRow(`SELECT path, created_by, is_folder FROM shares WHERE slug = ?`, slug).Scan(&rel, &createdBy, &isFolder)
	if err != nil {
		return "", err
	}
	if _, inside := fs.davName(rel); !inside || createdBy != davCreator() || isFolder != 0 {
		return "", errNotManaged
	}
	return rel, nil
}

func ownDAVLinkError(w http.ResponseWriter, err error) {
	switch {
	case err == sql.ErrNoRows:
		jsonError(w, "Link not found", http.StatusNotFound)
	case errors.Is(err, errNotManaged):
		jsonError(w, "Link not managed here", http.StatusConflict)
	default:
		jsonError(w, "Database error", http.StatusInternalServerError)
	}
}

// getDAVLink gives one link this API made, wherever its file is now in the root.
func getDAVLink(fs *davFS, w http.ResponseWriter, slug string) {
	if _, err := ownDAVLink(fs, slug); err != nil {
		ownDAVLinkError(w, err)
		return
	}
	link, err := scanDAVLink(fs, db.QueryRow(`SELECT slug, path, COALESCE(expires_at,''), COALESCE(max_uses,-1),
		uses_count, COALESCE(views_count,0), created_at FROM shares WHERE slug = ?`, slug))
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, link)
}

// revokeDAVLink deletes a link this API made for a file of the root.
func revokeDAVLink(fs *davFS, w http.ResponseWriter, r *http.Request, slug string) {
	if !davLinkWrites.Allow(clientIP(r)) {
		jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	rel, err := ownDAVLink(fs, slug)
	if err != nil {
		ownDAVLinkError(w, err)
		return
	}
	res, err := db.Exec(`DELETE FROM shares WHERE slug = ? AND created_by = ? AND path = ?`, slug, davCreator(), rel)
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		jsonError(w, "Link not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]interface{}{"success": true})
}

// listSharedFolders gives the WebDAV names of the folders a live share opens to anyone, whoever made it ("/" when
// the root or a folder above it is shared): what is put there later becomes public too.
func listSharedFolders(fs *davFS, w http.ResponseWriter) {
	rows, err := db.Query(`SELECT path, COALESCE(expires_at,''), COALESCE(max_uses,-1), uses_count, is_folder FROM shares`)
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	type share struct {
		rel    string
		folder bool
	}
	var live []share
	now := time.Now()
	for rows.Next() {
		var rel, expiresAt string
		var maxUses, usesCount, isFolder int
		if err := rows.Scan(&rel, &expiresAt, &maxUses, &usesCount, &isFolder); err != nil {
			rows.Close()
			jsonError(w, "Database error", http.StatusInternalServerError)
			return
		}
		if shareStatus(expiresAt, maxUses, usesCount, now) == "active" {
			live = append(live, share{rel, isFolder == 1})
		}
	}
	failed := rows.Err() != nil
	rows.Close()
	if failed {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}
	seen := map[string]bool{}
	for _, s := range live {
		if fs.coversRoot(s.rel) {
			seen["/"] = true
			continue
		}
		name, inside := fs.davName(s.rel)
		if !inside {
			continue
		}
		// Shares made before is_folder existed say 0 for a folder too: the disk decides.
		if !s.folder {
			fi, err := os.Lstat(filepath.Join(filesDir, filepath.FromSlash(s.rel)))
			if err != nil || !fi.IsDir() {
				continue
			}
		}
		seen[name] = true
	}
	folders := make([]string, 0, len(seen))
	for name := range seen {
		folders = append(folders, name)
	}
	sort.Strings(folders)
	jsonOK(w, map[string]interface{}{"folders": folders})
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanDAVLink(fs *davFS, row rowScanner) (DAVLink, error) {
	var link DAVLink
	var rel, expiresAt string
	var maxUses int
	if err := row.Scan(&link.Slug, &rel, &expiresAt, &maxUses, &link.UsesCount, &link.ViewsCount, &link.CreatedAt); err != nil {
		return DAVLink{}, err
	}
	link.URL = baseURL + "/s/" + link.Slug
	link.Path, _ = fs.davName(rel)
	if expiresAt != "" {
		link.ExpiresAt = &expiresAt
	}
	if maxUses > 0 {
		link.MaxUses = &maxUses
	}
	link.Status = shareStatus(expiresAt, maxUses, link.UsesCount, time.Now())
	return link, nil
}
