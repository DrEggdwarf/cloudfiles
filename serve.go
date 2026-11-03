package main

import (
	"mime"
	"path/filepath"
	"strings"
	"unicode"
)

// contentDisposition builds the header with mime.FormatMediaType, which quotes or
// RFC 2231-encodes the name: a quote, a semicolon or a newline in a file name stays a name.
func contentDisposition(kind, filename string) string {
	if v := mime.FormatMediaType(kind, map[string]string{"filename": filename}); v != "" {
		return v
	}
	return kind
}

// isActiveMime tells whether a browser would run the content as a page of the site.
func isActiveMime(m string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.SplitN(m, ";", 2)[0])) {
	case "text/html", "application/xhtml+xml", "image/svg+xml", "application/xml", "text/xml",
		"application/javascript", "text/javascript":
		return true
	}
	return false
}

// A published page (/api/publish, the mini-sites) keeps its scripts, forms and pop-ups but
// runs in an opaque origin: it cannot read the admin page's storage nor call the API as it.
const publishedCSP = baseCSP + "; sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads"

// A file seen through a share link is only displayed: no script runs.
const sharedCSP = baseCSP + "; sandbox"

// sanitizeAIName keeps a suggested name to letters, digits, '-' and '_' and gives it back
// the original extension: the admin page offers it for a rename.
func sanitizeAIName(suggested, original string) string {
	stem := strings.TrimSuffix(suggested, filepath.Ext(suggested))
	var b strings.Builder
	n := 0
	for _, r := range stem {
		if n >= 120 {
			break
		}
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '.':
			b.WriteRune('_')
		default:
			continue
		}
		n++
	}
	clean := strings.Trim(b.String(), "_-")
	if clean == "" {
		return ""
	}
	return clean + filepath.Ext(original)
}
