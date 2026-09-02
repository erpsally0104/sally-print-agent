package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"
)

/*
Security model
──────────────

The agent listens on loopback, which means it is unreachable from the network
but reachable from *every website the user visits*. That is the threat: not an
attacker on the LAN, but an ordinary malicious page in the user's browser
spooling a thousand sheets to their invoice printer.

Four controls, in order of how much work they actually do:

 1. Loopback bind. The listener is 127.0.0.1, never 0.0.0.0, so nothing off the
    machine can open a connection at all.

 2. Origin allowlist — the real gate. Every /v1 call must carry an `Origin` the
    config permits. A browser sets `Origin` itself and a page cannot forge it,
    so this alone stops hostile sites.

 3. A non-simple request shape. Both privileged endpoints require the
    `X-Sally-Token` header, and printing requires `Content-Type: application/pdf`.
    Neither is a CORS-safelisted value, so the browser must send a preflight
    first — and the preflight fails control 2. This matters because CORS on its
    own only stops an attacker *reading the response*: a simple POST would still
    have arrived and printed. Forcing a preflight stops the request landing.

 4. The token. Sally receives it automatically from /v1/ping (only allowlisted
    origins can read that response) so there is no pairing step for the user.
    It guards against non-browser callers on the machine that don't know it.
    It is not the primary control — a process running as the user can read the
    config file — which is exactly why controls 1–3 exist.

Two more limits below the auth line: a byte cap on uploads and a rate limit on
jobs, so that even an authorised bug cannot exhaust memory or a paper tray.
*/

// tokenHeader is deliberately custom: its presence forces a CORS preflight.
const tokenHeader = "X-Sally-Token"

// localHeader marks calls from the agent's own status page.
const localHeader = "X-Sally-Local"

// maxUploadBytes caps a print job. Large enough for a few hundred invoice
// pages, small enough that a runaway caller cannot exhaust memory.
const maxUploadBytes = 64 << 20 // 64 MiB

// originAllowed reports whether origin is on the allowlist. Comparison is exact
// (scheme, host and port) and case-insensitive only in the scheme and host,
// which is how browsers serialise an origin anyway.
func originAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	o := strings.ToLower(strings.TrimSpace(origin))
	for _, a := range allowed {
		if o == strings.ToLower(strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

// tokenMatches compares in constant time. The comparison is not really a
// timing-attack target over loopback, but the cost of doing it properly is nil.
func tokenMatches(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// corsMiddleware enforces the origin allowlist and answers preflights.
//
// A request with no Origin at all is not from a browser (fetch always sets it
// cross-origin). Those are allowed through to the token check, so curl can be
// used for debugging, but they can never reach a privileged endpoint without
// the token from the config file.
func (s *server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" {
			if !originAllowed(origin, s.cfg.AllowedOrigins) {
				s.logf("refused %s %s from origin %q", r.Method, r.URL.Path, origin)
				writeJSONError(w, http.StatusForbidden, "origin not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", tokenHeader+", "+localHeader+", Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")

			// Chrome preflights requests from a public page to a private
			// (loopback) address and requires this header on the response, or
			// the real request is never sent.
			if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
				w.Header().Set("Access-Control-Allow-Private-Network", "true")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// requireToken gates the endpoints that can see or use the user's printers.
func (s *server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatches(r.Header.Get(tokenHeader), s.cfg.Token) {
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}
		next(w, r)
	}
}

// requireLocalPage guards the status page's own actions (currently Quit).
// It accepts only a request with no Origin or the agent's own origin — never a
// web page, even an allowlisted one, so a bug in Sally can't stop the agent.
func (s *server) requireLocalPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != s.selfOrigin() {
			writeJSONError(w, http.StatusForbidden, "not permitted from a web page")
			return
		}
		if r.Header.Get(localHeader) != "1" {
			writeJSONError(w, http.StatusForbidden, "missing local marker")
			return
		}
		next(w, r)
	}
}

// rateLimiter caps print jobs over a rolling window. A print job costs paper and
// toner, so the ceiling is low on purpose: a stuck retry loop in the browser
// should waste a few sheets, not a ream.
type rateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	times  []time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window}
}

// allow records an attempt and reports whether it may proceed.
func (r *rateLimiter) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := now.Add(-r.window)
	kept := r.times[:0]
	for _, t := range r.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.times = kept

	if len(r.times) >= r.limit {
		return false
	}
	r.times = append(r.times, now)
	return true
}
