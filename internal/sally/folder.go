package sally

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ── Watched-folder stacks ──────────────────────────────────────────────────
//
// A stack from the watched folder is one file, or one sub-folder dropped in
// (a "folder drop"). It has no sheets or sides: its files are PDFs and
// pictures, numbered 1…N, and Sally pairs their pages by its own guess,
// never by a declared sheet. The wire contract is erp-sally
// docs/signed-copies/p1-desktop-api.md, "Watched-folder stacks".

// FolderStack announces a watched-folder stack.
type FolderStack struct {
	Stack string
	Files int
	// FileName is set for a single file, FolderName for a folder drop.
	FileName   string
	FolderName string
	ScannedAt  time.Time
}

// FileDecl declares one file of a folder stack before upload.
type FileDecl struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	FolderPath  string `json:"folderPath,omitempty"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"contentType"`
}

// FileTarget is one presigned PUT for a file.
type FileTarget struct {
	Index   int               `json:"index"`
	Ticket  string            `json:"ticket"`
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}

// Upload is the target as a PUT (PutObject takes an UploadTarget).
func (t FileTarget) Upload() UploadTarget {
	return UploadTarget{Ticket: t.Ticket, URL: t.URL, Method: t.Method, Headers: t.Headers}
}

// AnnounceFolder opens (or reopens) the run for a watched-folder stack.
// received lists the SHA-256 of every file Sally already holds.
func (c *Client) AnnounceFolder(ctx context.Context, s FolderStack) (string, []string, error) {
	var out struct {
		RunID         string   `json:"runId"`
		ReceivedFiles []string `json:"receivedFiles"`
	}
	in := map[string]any{"stack": s.Stack, "kind": "FOLDER", "files": s.Files, "scannedAt": s.ScannedAt.UTC().Format(time.RFC3339)}
	if s.FolderName != "" {
		in["folderName"] = s.FolderName
	} else {
		in["fileName"] = s.FileName
	}
	if _, err := c.do(ctx, http.MethodPost, "/api/agent/scan/stacks", in, &out); err != nil {
		return "", nil, err
	}
	if out.RunID == "" {
		return "", nil, fmt.Errorf("sally: the stack was accepted without a run id")
	}
	return out.RunID, out.ReceivedFiles, nil
}

// FileUploadURLs asks for presigned PUTs, at most 25 files at once.
func (c *Client) FileUploadURLs(ctx context.Context, runID string, files []FileDecl) ([]FileTarget, error) {
	if len(files) > 25 {
		return nil, fmt.Errorf("sally: at most 25 files per upload-url call")
	}
	var out struct {
		Uploads []FileTarget `json:"uploads"`
	}
	path := "/api/agent/scan/stacks/" + url.PathEscape(runID) + "/upload-url"
	if _, err := c.do(ctx, http.MethodPost, path, map[string]any{"files": files}, &out); err != nil {
		return nil, err
	}
	return out.Uploads, nil
}

// ConfirmFile tells Sally a file is in S3. Only after this succeeds may the
// local copy go.
func (c *Client) ConfirmFile(ctx context.Context, runID string, f FileDecl, ticket string) error {
	path := "/api/agent/scan/stacks/" + url.PathEscape(runID) + "/files"
	in := map[string]any{"index": f.Index, "name": f.Name, "sha256": f.SHA256, "ticket": ticket}
	if f.FolderPath != "" {
		in["folderPath"] = f.FolderPath
	}
	_, err := c.do(ctx, http.MethodPost, path, in, nil)
	return err
}
