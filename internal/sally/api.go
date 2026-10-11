// Package sally is the HTTPS client for the Sally Desktop side of Sally's
// /api/agent/* routes: pairing, heartbeat, and stack uploads. The wire
// contract is erp-sally docs/signed-copies/p1-desktop-api.md.
//
// Ported in part from sally-tally-connector's internal/sally, keeping only
// what a scanner needs: JSON calls and presigned S3 PUTs, no multipart.
package sally

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// headerCompany names the one company the device was approved for.
const headerCompany = "x-active-company-id"

// Client calls Sally. Safe for concurrent use.
type Client struct {
	baseURL   string
	userAgent string
	http      *http.Client
	s3        *http.Client

	// pollEvery overrides the pairing poll interval (tests only).
	pollEvery time.Duration

	mu        sync.RWMutex
	token     string
	companyID string
}

// NewClient returns a client for baseURL (e.g. https://sallyerp.in).
func NewClient(baseURL, userAgent string) *Client {
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		userAgent: userAgent,
		http:      &http.Client{Timeout: 30 * time.Second},
		// A page is about a megabyte; a slow shop uplink needs time.
		s3: &http.Client{Timeout: 3 * time.Minute},
	}
}

// BaseURL is where the client points.
func (c *Client) BaseURL() string { return c.baseURL }

// SetAuth sets the device token and the approved company.
func (c *Client) SetAuth(token, companyID string) {
	c.mu.Lock()
	c.token, c.companyID = token, companyID
	c.mu.Unlock()
}

// Paired reports whether the client has a token and company.
func (c *Client) Paired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token != "" && c.companyID != ""
}

// APIError is a non-2xx answer from Sally.
type APIError struct {
	Method string
	Path   string
	Status int
	// Code is the {code} of a 403 (NOT_SCAN_DEVICE, COMPANY_NOT_APPROVED,
	// OWNER_LOST_ACCESS, PLAN).
	Code    string
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if e.Code != "" {
		msg = e.Code + ": " + msg
	}
	return fmt.Sprintf("sally %s %s: %d %s", e.Method, e.Path, e.Status, msg)
}

// ErrNotPaired is returned by device calls made before pairing.
var ErrNotPaired = errors.New("sally: this PC is not connected to Sally")

// StatusOf returns the HTTP status of an *APIError, or 0.
func StatusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// IsUnauthorized is a 401: the token is unknown or revoked. The agent drops
// it and shows "Connect to Sally".
func IsUnauthorized(err error) bool { return StatusOf(err) == http.StatusUnauthorized }

// IsForbidden is a 403: the token is fine but the approval no longer holds
// (plan, permission, company). The agent keeps its token and keeps scanning
// into the outbox.
func IsForbidden(err error) bool { return StatusOf(err) == http.StatusForbidden }

// do performs a device-authenticated JSON call.
func (c *Client) do(ctx context.Context, method, path string, in, out any) (int, error) {
	c.mu.RLock()
	token, company := c.token, c.companyID
	c.mu.RUnlock()
	if token == "" || company == "" {
		return 0, ErrNotPaired
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	h.Set(headerCompany, company)
	return c.call(ctx, method, path, h, in, out)
}

func (c *Client) call(ctx context.Context, method, path string, h http.Header, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, err
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
		var eb struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(raw, &eb) == nil {
			ae.Message, ae.Code = eb.Error, eb.Code
		}
		if ae.Message == "" {
			ae.Message = strings.TrimSpace(string(raw))
			if len(ae.Message) > 200 {
				ae.Message = ae.Message[:200]
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return resp.StatusCode, &RateLimitError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")), err: ae}
		}
		return resp.StatusCode, ae
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("sally %s %s: bad reply: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// RateLimitError is a 429; RetryAfter comes from the Retry-After header.
type RateLimitError struct {
	RetryAfter time.Duration
	err        *APIError
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("sally: slow down (retry after %s)", e.RetryAfter)
}

// Unwrap exposes the APIError, so StatusOf sees the 429.
func (e *RateLimitError) Unwrap() error { return e.err }

func parseRetryAfter(v string) time.Duration {
	var secs int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &secs); err == nil && secs >= 0 && secs < 3600 {
		return time.Duration(secs) * time.Second
	}
	return 0
}
