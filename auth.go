package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// secretEqual compares fixed-size digests, so neither the length of the secret nor the
// position of the first wrong byte shows in the response time.
func secretEqual(got, want string) bool {
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// isAdminSecret accepts ADMIN_PASSWORD or AUTH_TOKEN; both are always compared.
func isAdminSecret(s string) bool {
	if s == "" {
		return false
	}
	a := secretEqual(s, adminPassword)
	b := secretEqual(s, authToken)
	return a || b
}

// validateSecrets refuses to start on the placeholder secrets main falls back to.
func validateSecrets() error {
	for name, v := range map[string]string{"ADMIN_PASSWORD": adminPassword, "AUTH_TOKEN": authToken} {
		if strings.TrimSpace(v) == "" || strings.HasPrefix(v, "changeme") {
			return errors.New(name + " is not set (or still a changeme placeholder)")
		}
	}
	return nil
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// guardBearer lets a request through when accept(token) holds, counting wrong tokens per client.
func guardBearer(accept func(string) bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if !generalRL.Allow(key) {
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		token := extractBearer(r)
		ok, blocked := adminFails.Check(key, func() bool { return accept(token) })
		if blocked {
			jsonError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		if !ok {
			jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// adminAuth accepts either ADMIN_PASSWORD or AUTH_TOKEN as Bearer.
func adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return guardBearer(isAdminSecret, next)
}

// tokenAuth accepts only AUTH_TOKEN (Firefox extension compatibility).
func tokenAuth(next http.HandlerFunc) http.HandlerFunc {
	return guardBearer(func(t string) bool { return t != "" && secretEqual(t, authToken) }, next)
}
