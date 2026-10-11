package sally

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ── Heartbeat ──────────────────────────────────────────────────────────────

// Scanner is the scanner part of a heartbeat.
type Scanner struct {
	Kind      string `json:"kind"` // USB | NETWORK | NONE
	Name      string `json:"name,omitempty"`
	State     string `json:"state"` // IDLE | PROCESSING | STOPPED | JAMMED | OFFLINE | UNKNOWN
	AdfLoaded bool   `json:"adfLoaded"`
	Scanning  bool   `json:"scanning"`
}

// Pause is the PC's pause state.
type Pause struct {
	Paused bool       `json:"paused"`
	Until  *time.Time `json:"until"`
}

// LastStack describes the most recent stack.
type LastStack struct {
	Stack  string    `json:"stack"`
	Sheets int       `json:"sheets"`
	Sides  int       `json:"sides"`
	At     time.Time `json:"at"`
	State  string    `json:"state"` // SAFE | SENDING | SENT
}

// Outbox is what is waiting to go up.
type Outbox struct {
	StacksWaiting int        `json:"stacksWaiting"`
	SidesWaiting  int        `json:"sidesWaiting"`
	BytesWaiting  int64      `json:"bytesWaiting"`
	LastStack     *LastStack `json:"lastStack,omitempty"`
}

// HeartbeatRequest is a SCAN device's heartbeat. Counts only, never content.
type HeartbeatRequest struct {
	AgentVersion string   `json:"agentVersion"`
	Scanner      *Scanner `json:"scanner,omitempty"`
	Pause        *Pause   `json:"pause,omitempty"`
	Outbox       *Outbox  `json:"outbox,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// Command is one instruction delivered on the heartbeat.
type Command struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"` // SCAN_NOW | PAUSE | RESUME | TEST_SCAN
	PauseMinutes *int   `json:"pauseMinutes"`
}

// Settings are the PC's settings, chosen in Sally.
type Settings struct {
	AutoStart     *bool `json:"autoStart"`
	StartDelaySec int   `json:"startDelaySec"`
}

// HeartbeatResponse is Sally's answer.
type HeartbeatResponse struct {
	HeartbeatSec int    `json:"heartbeatSec"`
	CompanyName  string `json:"companyName"`
	// ApprovedByName is the approver's name (optional; a newer Sally
	// sends it).
	ApprovedByName    string    `json:"approvedByName,omitempty"`
	Settings          *Settings `json:"settings"`
	Commands          []Command `json:"commands"`
	MinAgentVersion   *string   `json:"minAgentVersion"`
	UpdateManifestURL string    `json:"updateManifestUrl"`
}

// Heartbeat reports status and collects settings and commands.
func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if _, err := c.do(ctx, http.MethodPost, "/api/agent/heartbeat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Stacks ─────────────────────────────────────────────────────────────────

// SideRef names one side of one sheet.
type SideRef struct {
	Sheet int `json:"sheet"`
	Side  int `json:"side"`
}

// SideDecl declares a side before upload.
type SideDecl struct {
	Sheet  int    `json:"sheet"`
	Side   int    `json:"side"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// UploadTarget is one presigned PUT.
type UploadTarget struct {
	Sheet   int               `json:"sheet"`
	Side    int               `json:"side"`
	Ticket  string            `json:"ticket"`
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}

// AnnounceStack opens (or, for a stack already announced, reopens) the run
// for a stack. received lists the sides Sally already holds.
func (c *Client) AnnounceStack(ctx context.Context, stack string, sheets, sides int, scannedAt time.Time) (string, []SideRef, error) {
	var out struct {
		RunID    string    `json:"runId"`
		Received []SideRef `json:"received"`
	}
	in := map[string]any{"stack": stack, "sheets": sheets, "sides": sides, "scannedAt": scannedAt.UTC().Format(time.RFC3339)}
	if _, err := c.do(ctx, http.MethodPost, "/api/agent/scan/stacks", in, &out); err != nil {
		return "", nil, err
	}
	if out.RunID == "" {
		return "", nil, fmt.Errorf("sally: the stack was accepted without a run id")
	}
	return out.RunID, out.Received, nil
}

// UploadURLs asks for presigned PUTs, at most 25 sides at once.
func (c *Client) UploadURLs(ctx context.Context, runID string, sides []SideDecl) ([]UploadTarget, error) {
	if len(sides) > 25 {
		return nil, fmt.Errorf("sally: at most 25 sides per upload-url call")
	}
	var out struct {
		Uploads []UploadTarget `json:"uploads"`
	}
	path := "/api/agent/scan/stacks/" + url.PathEscape(runID) + "/upload-url"
	if _, err := c.do(ctx, http.MethodPost, path, map[string]any{"sides": sides}, &out); err != nil {
		return nil, err
	}
	return out.Uploads, nil
}

// ConfirmSide tells Sally a side is in S3. Only after this succeeds may the
// local copy go.
func (c *Client) ConfirmSide(ctx context.Context, runID string, sheet, side int, sha256, ticket string) error {
	path := "/api/agent/scan/stacks/" + url.PathEscape(runID) + "/sides"
	in := map[string]any{"sheet": sheet, "side": side, "sha256": sha256, "ticket": ticket}
	_, err := c.do(ctx, http.MethodPost, path, in, nil)
	return err
}

// Done says every side is up and starts the run. Idempotent.
func (c *Client) Done(ctx context.Context, runID string) error {
	path := "/api/agent/scan/stacks/" + url.PathEscape(runID) + "/done"
	_, err := c.do(ctx, http.MethodPost, path, map[string]any{}, nil)
	return err
}

// PutObject uploads a page to a presigned URL with exactly the headers Sally
// gave. The bytes go as they are: never decoded, never re-encoded.
func (c *Client) PutObject(ctx context.Context, t UploadTarget, body []byte) error {
	method := t.Method
	if method == "" {
		method = http.MethodPut
	}
	req, err := http.NewRequestWithContext(ctx, method, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range t.Headers {
		req.Header.Set(k, v)
	}
	req.ContentLength = int64(len(body))
	resp, err := c.s3.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Method: method, Path: "(upload)", Status: resp.StatusCode, Message: string(raw)}
	}
	return nil
}
