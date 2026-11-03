package main

import (
	"hash/fnv"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Who is asking ─────────────────────────────────────────────────────────────

// clientIP names the client for the rate limiters. Only a peer on a private or loopback
// network (kamal-proxy, on the Docker network) is trusted for X-Forwarded-For, and then only
// for the last address, the one the proxy appended: anything before it came from the client.
// IPv6 clients are grouped by /64, the block one subscriber usually gets.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if fwd := lastForwardedFor(r); fwd != nil {
			ip = fwd
		}
	}
	if ip == nil {
		return host
	}
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}

func lastForwardedFor(r *http.Request) net.IP {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return nil
	}
	parts := strings.Split(values[len(values)-1], ",")
	return net.ParseIP(strings.TrimSpace(parts[len(parts)-1]))
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

// limiterMaxKeys bounds the memory of each limiter; past it, an arbitrary key is forgotten.
const limiterMaxKeys = 10000

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
			rl.pruneAll(time.Now())
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) fresh(key string, now time.Time) []time.Time {
	var fresh []time.Time
	for _, t := range rl.entries[key] {
		if now.Sub(t) < rl.window {
			fresh = append(fresh, t)
		}
	}
	return fresh
}

func (rl *RateLimiter) pruneAll(now time.Time) {
	for k := range rl.entries {
		if f := rl.fresh(k, now); len(f) == 0 {
			delete(rl.entries, k)
		} else {
			rl.entries[k] = f
		}
	}
}

func (rl *RateLimiter) store(key string, ts []time.Time, now time.Time) {
	if _, known := rl.entries[key]; !known && len(rl.entries) >= limiterMaxKeys {
		rl.pruneAll(now)
		for k := range rl.entries {
			if len(rl.entries) < limiterMaxKeys {
				break
			}
			delete(rl.entries, k)
		}
	}
	rl.entries[key] = ts
}

// Allow spends one request of key's quota, or reports that it is used up.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	fresh := rl.fresh(key, now)
	if len(fresh) >= rl.max {
		rl.store(key, fresh, now)
		return false
	}
	rl.store(key, append(fresh, now), now)
	return true
}

// Exceeded tells whether key already used its quota, without spending a request.
func (rl *RateLimiter) Exceeded(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.fresh(key, time.Now())) >= rl.max
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

// ─── Failed attempts ──────────────────────────────────────────────────────────

// FailGuard counts wrong credentials only. Attempts from one client run one at a time,
// so parallel guesses cannot all pass the check before the first failure is recorded.
type FailGuard struct {
	failures *RateLimiter
	stripes  [64]sync.Mutex
}

func newFailGuard(max int, window time.Duration) *FailGuard {
	return &FailGuard{failures: newRateLimiter(max, window)}
}

// Check runs verify unless key is locked out, and records a failure when it returns false.
func (g *FailGuard) Check(key string, verify func() bool) (ok, blocked bool) {
	h := fnv.New32a()
	h.Write([]byte(key))
	stripe := &g.stripes[h.Sum32()%uint32(len(g.stripes))]
	stripe.Lock()
	defer stripe.Unlock()
	if g.failures.Exceeded(key) {
		return false, true
	}
	if verify() {
		return true, false
	}
	g.failures.Allow(key)
	return false, false
}

// Blocked tells whether key is locked out, without trying anything.
func (g *FailGuard) Blocked(key string) bool {
	return g.failures.Exceeded(key)
}

var (
	generalRL = newRateLimiter(120, time.Minute)
	authRL    = newRateLimiter(5, 15*time.Minute)
	uploadRL  = newRateLimiter(20, time.Minute)
	// adminFails counts wrong tokens on the admin API; the page sends two calls per load.
	adminFails = newFailGuard(20, 15*time.Minute)
)
