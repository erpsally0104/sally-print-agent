package sally

import (
	"bytes"
	"context"
	"encoding/json"
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
	// ID is the scanner in use (sc- + 20 hex), or the chosen one while it is
	// not answering. Omitted when there is none.
	ID string `json:"id,omitempty"`
	// Problem is the scanner's current problem as one of the agent's own
	// fixed sentences, never an error's raw text.
	Problem string `json:"problem,omitempty"`
	// Held says paper is in the feeder and will not start by itself:
	// WHILE_PAUSED, AFTER_STOP or AFTER_STOP_ON_PC.
	Held string `json:"held,omitempty"`
	// Job is the running pile, present only while Scanning.
	Job *ScannerJob `json:"job,omitempty"`
}

// ScannerJob is the running pile.
type ScannerJob struct {
	ID        string    `json:"id"`   // j + UTC yyyymmddThhmmss + - + 4 hex
	Kind      string    `json:"kind"` // AUTO | SCAN_NOW | TEST_SCAN
	StartedAt time.Time `json:"startedAt"`
	Sides     int       `json:"sides"`
	Stopping  bool      `json:"stopping"`
}

// ScannerChoice is one scanner the PC found.
type ScannerChoice struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Via       []string `json:"via"` // USB, NETWORK; USB first
	Detail    string   `json:"detail,omitempty"`
	Answering bool     `json:"answering"`
	Feeder    *bool    `json:"feeder,omitempty"`
	Stable    bool     `json:"stable"`
}

// CommandResult is what the PC did with a command.
type CommandResult struct {
	ID      string `json:"id"`
	Result  string `json:"result"`
	Sides   *int   `json:"sides,omitempty"`
	Sheets  *int   `json:"sheets,omitempty"`
	Stack   string `json:"stack,omitempty"`
	Message string `json:"message,omitempty"`
}

// LocalAction is something a person did on the PC's own status page.
type LocalAction struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"` // STOP | SELECT_SCANNER
	At   time.Time `json:"at"`
	Job  string    `json:"job,omitempty"`
	// ScannerID is set for SELECT_SCANNER only: an sc- id as a JSON
	// string, or the literal null for automatic. Omitted for STOP.
	ScannerID json.RawMessage `json:"scannerId,omitempty"`
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

// WatchedFolder is the watched folder part of a heartbeat: the folder's
// last path element only (never the full path), and counts.
type WatchedFolder struct {
	Name         string `json:"name"`
	FilesWaiting int    `json:"filesWaiting"`
	SentToday    int    `json:"sentToday"`
	LastError    string `json:"lastError,omitempty"`
}

// HeartbeatRequest is a SCAN device's heartbeat. Counts only, never content.
type HeartbeatRequest struct {
	AgentVersion  string         `json:"agentVersion"`
	Scanner       *Scanner       `json:"scanner,omitempty"`
	Pause         *Pause         `json:"pause,omitempty"`
	Outbox        *Outbox        `json:"outbox,omitempty"`
	WatchedFolder *WatchedFolder `json:"watchedFolder,omitempty"`
	Error         string         `json:"error,omitempty"`

	// Features is what this agent supports, the server's only version gate.
	Features []string `json:"features"`
	// Scanners is every scanner found, at most 16; [] when none.
	Scanners []ScannerChoice `json:"scanners"`
	// ChosenScannerID is the scanner picked for this PC; nil (sent as null)
	// means automatic.
	ChosenScannerID *string         `json:"chosenScannerId"`
	Results         []CommandResult `json:"commandResults,omitempty"`
	LocalActions    []LocalAction   `json:"localActions,omitempty"`
}

// Command is one instruction delivered on the heartbeat.
type Command struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"` // SCAN_NOW | PAUSE | RESUME | TEST_SCAN | STOP | SELECT_SCANNER
	PauseMinutes *int   `json:"pauseMinutes"`
	// Job is the pile a STOP is for: the scanner.job.id the person saw.
	Job string `json:"job"`
	// ScannerID is SELECT_SCANNER's scanner: nil when the key is absent,
	// the literal null for automatic, or a JSON string.
	ScannerID json.RawMessage `json:"scannerId"`
	// ByName is who asked (STOP and SELECT_SCANNER), for the status page.
	ByName string `json:"byName"`
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
	if req.Scanners == nil {
		req.Scanners = []ScannerChoice{}
	}
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
// for a stack. received lists the sides Sally already holds. ended
// (STOPPED, JAM or ERROR) is sent only for a pile that ended early; an
// older Sally ignores it.
func (c *Client) AnnounceStack(ctx context.Context, stack string, sheets, sides int, scannedAt time.Time, ended string) (string, []SideRef, error) {
	var out struct {
		RunID    string    `json:"runId"`
		Received []SideRef `json:"received"`
	}
	in := map[string]any{"stack": stack, "sheets": sheets, "sides": sides, "scannedAt": scannedAt.UTC().Format(time.RFC3339)}
	if ended != "" {
		in["ended"] = ended
	}
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
