package escl

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// DefaultVersion is sent when the scanner's capabilities name no version.
const DefaultVersion = "2.63"

// Namespaces of the eSCL schema.
const (
	NSPWG  = "http://www.pwg.org/schemas/2010/12/sm"
	NSScan = "http://schemas.hp.com/imaging/escl/2011/05/03"
)

// ErrNotReady is a 503 from NextDocument: the page is still being scanned.
var ErrNotReady = errors.New("escl: next page not ready yet")

// ErrNotJPEG is a page that does not start with the JPEG magic FF D8.
var ErrNotJPEG = errors.New("escl: the page is not a JPEG")

// StatusError is an eSCL reply with an unexpected status.
type StatusError struct {
	Op     string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	b := e.Body
	if len(b) > 200 {
		b = b[:200]
	}
	return fmt.Sprintf("escl: %s answered %d %s", e.Op, e.Status, strings.TrimSpace(b))
}

// Client is an eSCL client for one scanner.
type Client struct {
	D Doer
	// Root is the resource path, "/eSCL" unless mDNS said otherwise.
	Root string
	// Version is what ScannerCapabilities reported (or DefaultVersion).
	Version string
	// Duplex is whether ScannerCapabilities said the feeder scans both
	// sides.
	Duplex bool
}

// NewClient returns a client rooted at root ("eSCL", "/eSCL" or "" for the
// default).
func NewClient(d Doer, root string) *Client {
	root = "/" + strings.Trim(root, "/")
	if root == "/" {
		root = "/eSCL"
	}
	return &Client{D: d, Root: root, Version: DefaultVersion}
}

// Capabilities is the part of ScannerCapabilities the agent uses.
type Capabilities struct {
	Version      string
	MakeAndModel string
	// Duplex: the feeder scans both sides of a sheet in one pass. The eSCL
	// schema says so in either of two places inside scan:Adf:
	//   <scan:AdfDuplexInputCaps>…</scan:AdfDuplexInputCaps>
	//   <scan:AdfOptions><scan:AdfOption>Duplex</scan:AdfOption></scan:AdfOptions>
	// (DetectPaperLoaded, the other common AdfOption, says nothing about
	// sides.) A scanner that says neither is simplex.
	Duplex bool
	// SerialNumber and UUID are pwg:SerialNumber and scan:UUID, as the
	// scanner sent them (trimmed, otherwise raw). They name the device for
	// the scanner list's stable id (internal/desktop/identity.go).
	SerialNumber string
	UUID         string
	// Feeder: the capabilities list a document feeder (scan:Adf).
	Feeder bool
}

// Capabilities reads ScannerCapabilities and remembers the version for the
// scan settings.
func (c *Client) Capabilities(ctx context.Context) (*Capabilities, error) {
	resp, err := c.D.Do(ctx, &Request{Method: http.MethodGet, Path: c.Root + "/ScannerCapabilities"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "ScannerCapabilities", Status: resp.StatusCode, Body: string(resp.Body)}
	}
	caps := ParseCapabilities(resp.Body)
	c.Version, c.Duplex = caps.Version, caps.Duplex
	return caps, nil
}

// ParseCapabilities reads pwg:Version, pwg:MakeAndModel, pwg:SerialNumber,
// scan:UUID, whether there is a feeder and whether it is duplex. A missing
// or odd version falls back to DefaultVersion.
//
// Version, MakeAndModel, SerialNumber and UUID count only as direct children
// of ScannerCapabilities, and the first one wins: the HP N4000 nests
// Certifications/Certification/Version 1.3 after its pwg:Version 2.9, and a
// job posted with 1.3 is not what the scanner speaks.
func ParseCapabilities(b []byte) *Capabilities {
	out := &Capabilities{Version: DefaultVersion}
	seen := map[string]bool{}
	walk(b, func(local, text string, depth int) {
		if depth == 2 {
			switch local {
			case "Version", "MakeAndModel", "SerialNumber", "UUID":
				if seen[local] {
					return
				}
				seen[local] = true
			}
			switch local {
			case "Version":
				if validVersion(text) {
					out.Version = text
				}
			case "MakeAndModel":
				out.MakeAndModel = text
			case "SerialNumber":
				out.SerialNumber = text
			case "UUID":
				out.UUID = text
			}
		}
		switch local {
		case "Adf":
			out.Feeder = true
		case "AdfDuplexInputCaps":
			out.Duplex = true
		case "AdfOption":
			if text == "Duplex" {
				out.Duplex = true
			}
		}
	})
	return out
}

var versionRe = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,3}$`)

func validVersion(v string) bool { return versionRe.MatchString(v) }

// Status is the part of ScannerStatus the agent uses.
type Status struct {
	// State is pwg:State: Idle, Processing, Stopped, Testing or Down.
	State string
	// AdfState is scan:AdfState, e.g. ScannerAdfLoaded, ScannerAdfEmpty,
	// ScannerAdfJam. Empty when the scanner did not report one.
	AdfState string
}

// Idle reports whether the scanner is idle.
func (s Status) Idle() bool { return s.State == "Idle" }

// Loaded reports whether there is paper in the feeder.
func (s Status) Loaded() bool { return s.AdfState == "ScannerAdfLoaded" }

// Empty reports a feeder the scanner says is empty.
func (s Status) Empty() bool { return s.AdfState == "ScannerAdfEmpty" }

// FeederClear reports a feeder with nothing in it: empty, or a scanner that
// reports no feeder state at all.
func (s Status) FeederClear() bool { return s.Empty() || s.AdfState == "" }

// Jammed reports a feeder problem that needs a person: a jam, a mispick, a
// double feed, an open door.
func (s Status) Jammed() bool {
	a := s.AdfState
	for _, k := range []string{"Jam", "Mispick", "Multipick", "PageTooShort", "PageTooLong", "TrayFailed", "Overloaded"} {
		if strings.Contains(a, k) {
			return true
		}
	}
	return false
}

// DoorOpen reports an open feeder door or hatch.
func (s Status) DoorOpen() bool {
	return strings.Contains(s.AdfState, "DoorOpen") || strings.Contains(s.AdfState, "HatchOpen")
}

// Status reads ScannerStatus.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	resp, err := c.D.Do(ctx, &Request{Method: http.MethodGet, Path: c.Root + "/ScannerStatus"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "ScannerStatus", Status: resp.StatusCode, Body: string(resp.Body)}
	}
	st := ParseStatus(resp.Body)
	return &st, nil
}

// ParseStatus reads pwg:State and scan:AdfState. Job entries inside the
// status carry their own pwg:JobState, which is a different element and is
// ignored; only the scanner-level State counts.
func ParseStatus(b []byte) Status {
	var st Status
	walk(b, func(local, text string, _ int) {
		switch local {
		case "State":
			if st.State == "" {
				st.State = text
			}
		case "AdfState":
			if st.AdfState == "" {
				st.AdfState = text
			}
		}
	})
	return st
}

// walk calls fn with the local name, text and depth (the root is 1) of
// every element as it ends.
func walk(b []byte, fn func(local, text string, depth int)) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	var stack []string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if len(stack) > 0 {
				fn(stack[len(stack)-1], strings.TrimSpace(text.String()), len(stack))
				stack = stack[:len(stack)-1]
			}
			text.Reset()
		}
	}
}

// StartJob posts the scan settings and returns the job's path
// ("/eSCL/ScanJobs/1234").
func (c *Client) StartJob(ctx context.Context, settings []byte) (string, error) {
	resp, err := c.D.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   c.Root + "/ScanJobs",
		Header: http.Header{"Content-Type": {"text/xml"}},
		Body:   settings,
	})
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", &StatusError{Op: "ScanJobs", Status: resp.StatusCode, Body: string(resp.Body)}
	}
	p, err := JobPath(resp.Header.Get("Location"), c.Root)
	if err != nil {
		return "", err
	}
	return p, nil
}

// JobPath turns a Location header, absolute URL or path, into a path.
func JobPath(location, root string) (string, error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return "", errors.New("escl: the scanner created a job but gave no Location")
	}
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("escl: bad job Location %q", location)
	}
	p := u.Path
	if p == "" {
		return "", fmt.Errorf("escl: bad job Location %q", location)
	}
	if !strings.HasPrefix(p, "/") {
		// Relative to the root: "ScanJobs/12".
		p = strings.TrimRight(root, "/") + "/" + p
	}
	return strings.TrimRight(p, "/"), nil
}

// NextDocument fetches the next page of a job. It returns (page, false, nil)
// for a page, (nil, true, nil) when the job has no more pages (404), and
// ErrNotReady for a 503.
func (c *Client) NextDocument(ctx context.Context, jobPath string) ([]byte, bool, error) {
	resp, err := c.D.Do(ctx, &Request{Method: http.MethodGet, Path: jobPath + "/NextDocument"})
	if err != nil {
		return nil, false, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if !IsJPEG(resp.Body) {
			return nil, false, ErrNotJPEG
		}
		return resp.Body, false, nil
	case http.StatusNotFound:
		return nil, true, nil
	case http.StatusServiceUnavailable:
		return nil, false, ErrNotReady
	default:
		return nil, false, &StatusError{Op: "NextDocument", Status: resp.StatusCode, Body: string(resp.Body)}
	}
}

// CancelJob asks the scanner to drop a job. Best effort: it returns the
// DELETE's HTTP status (0 when there was no answer) for the log.
func (c *Client) CancelJob(ctx context.Context, jobPath string) (int, error) {
	resp, err := c.D.Do(ctx, &Request{Method: http.MethodDelete, Path: jobPath})
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

// IsJPEG checks the JPEG start-of-image marker. Pages are never decoded on
// the PC: scanners often end a JPEG a row or two short, which Go's decoder
// rejects, and the bytes go up exactly as the scanner made them.
func IsJPEG(b []byte) bool { return len(b) >= 2 && b[0] == 0xFF && b[1] == 0xD8 }
