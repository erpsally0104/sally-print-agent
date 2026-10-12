package main

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/desktop"
)

/*
Scanning: the status page's controls.

Every route here sits behind requireLocalControl (or requireLocalRead for the
status JSON) in security.go. None of them is under /v1, none answers CORS,
and no web page, Sally included, can call them. A scan never starts from a
browser: it starts when paper sits in the feeder, from a command on the
server heartbeat, or from the Scan now button on this page.
*/

// scanDesk is what the status page needs from the scanning agent.
type scanDesk interface {
	Snapshot() desktop.View
	Pause(minutes int)
	Resume()
	ScanNow()
	Connect()
	SetSounds(on bool)
	SetKeepCopies(on bool)
	SetScannerAddress(addr string) error
	SetWatchedFolder(path string) error
}

func (s *server) scanRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/status.json", s.requireLocalRead(s.handleStatusJSON))
	mux.HandleFunc("/scan/pause", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		switch r.FormValue("minutes") {
		case "15":
			d.Pause(15)
		case "60":
			d.Pause(60)
		case "0":
			d.Pause(0)
		default:
			return errBadRequest("pause for 15, 60 or 0 (until resumed) minutes")
		}
		return nil
	})))
	mux.HandleFunc("/scan/resume", s.requireLocalControl(s.withDesk(func(d scanDesk, _ *http.Request) error {
		d.Resume()
		return nil
	})))
	mux.HandleFunc("/scan/now", s.requireLocalControl(s.withDesk(func(d scanDesk, _ *http.Request) error {
		d.ScanNow()
		return nil
	})))
	mux.HandleFunc("/scan/connect", s.requireLocalControl(s.withDesk(func(d scanDesk, _ *http.Request) error {
		d.Connect()
		return nil
	})))
	mux.HandleFunc("/scan/sounds", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		d.SetSounds(r.FormValue("on") == "true")
		return nil
	})))
	mux.HandleFunc("/scan/keep", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		d.SetKeepCopies(r.FormValue("on") == "true")
		return nil
	})))
	mux.HandleFunc("/scan/scanner", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		if err := d.SetScannerAddress(r.FormValue("address")); err != nil {
			return errBadRequest(err.Error())
		}
		return nil
	})))
	// The watched folder: a full path, or "" to stop watching (Clear).
	mux.HandleFunc("/scan/folder", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		if err := d.SetWatchedFolder(r.FormValue("path")); err != nil {
			return errBadRequest(err.Error())
		}
		return nil
	})))
}

type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }

func (s *server) withDesk(fn func(d scanDesk, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.desk == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "scanning is not running in this copy of Sally Desktop")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad form")
			return
		}
		if err := fn(s.desk, r); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logf("status page: %s", r.URL.Path)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// handleStatusJSON is what the page polls to know when to refresh itself.
// Counts and states only: never page content, never a token.
func (s *server) handleStatusJSON(w http.ResponseWriter, _ *http.Request) {
	noFraming(w)
	if s.desk == nil {
		writeJSON(w, http.StatusOK, map[string]any{"scanning": false, "stamp": "off"})
		return
	}
	v := s.desk.Snapshot()
	body := map[string]any{
		"scanning":    v.Scanning,
		"paired":      v.Paired,
		"companyName": v.CompanyName,
		"scanner": map[string]any{
			"kind": v.ScannerKind, "name": v.ScannerName, "state": v.ScannerState,
			"adfLoaded": v.AdfLoaded, "scanning": v.ScanRunning, "sides": v.ScanSides,
		},
		"paused": v.Paused,
		"outbox": map[string]any{
			"stacksWaiting": v.StacksWaiting, "sidesWaiting": v.SidesWaiting,
			"sendingTotal": v.SendingTotal, "sendingSent": v.SendingSent,
		},
		"held": v.Held,
		// Counts only: the folder's path is not in this reply.
		"watchedFolder": map[string]any{
			"watching": v.WatchedFolder != "", "waiting": v.FolderWaiting,
			"sentToday": v.FolderSentToday, "error": v.FolderError != "",
		},
		"receipt": v.Receipt,
		"problem": v.Problem,
		"stamp":   statusStamp(v),
	}
	if v.PausedUntil != nil {
		body["pausedUntil"] = v.PausedUntil.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, body)
}

// statusStamp changes whenever anything shown on the scanner card changes,
// so the page reloads only then.
func statusStamp(v desktop.View) string {
	b := []byte{}
	add := func(x string) { b = append(b, x...); b = append(b, '|') }
	add(strconv.FormatBool(v.Paired))
	add(strconv.FormatBool(v.NeedsConnect))
	add(v.CompanyName)
	add(v.Denied)
	add(v.Offline)
	if v.Pairing != nil {
		add(v.Pairing.UserCode + v.Pairing.Err + strconv.FormatBool(v.Pairing.Waiting))
	}
	add(v.ScannerKind + v.ScannerName + v.ScannerState)
	add(strconv.FormatBool(v.AdfLoaded) + strconv.FormatBool(v.ScanRunning) + strconv.Itoa(v.ScanSides))
	add(strconv.FormatBool(v.Paused) + strconv.FormatBool(v.HeldWhilePaused) + v.Pending)
	add(strconv.FormatBool(v.AutoStart) + strconv.Itoa(v.StartDelaySec))
	add(v.Receipt + v.Problem)
	add(strconv.Itoa(v.StacksWaiting) + "/" + strconv.Itoa(v.SidesWaiting) + "/" + strconv.Itoa(v.SendingSent) + "/" + strconv.Itoa(v.SendingTotal))
	for _, r := range v.Recent {
		add(r.Stack + r.State + r.Refused)
	}
	for _, r := range v.Refused {
		add(r.Stack + r.Refused)
	}
	add(strconv.Itoa(v.Held))
	add(v.ApproverName + v.PCName + strconv.Itoa(v.TodayStacks) + "/" + strconv.Itoa(v.TodaySheets))
	add(strconv.FormatBool(v.SoundsOn) + strconv.FormatBool(v.KeepCopies) + v.ScannerAddress)
	add(v.WatchedFolder + "/" + strconv.Itoa(v.FolderWaiting) + "/" + strconv.Itoa(v.FolderSentToday) + "/" + v.FolderError)
	h := fnv.New64a()
	h.Write(b)
	return strconv.FormatUint(h.Sum64(), 36)
}

// openBrowser opens Sally's pairing page. Only an http(s) URL is ever
// handed to the OS, and it goes as one argument, never through a shell.
func openBrowser(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errBadRequest("not a web address")
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()).Start()
	case "darwin":
		return exec.Command("open", u.String()).Start()
	default:
		return exec.Command("xdg-open", u.String()).Start()
	}
}

// scanCard is the Scanner card of the status page, in words.
type scanCard struct {
	desktop.View
	Available   bool
	Unavailable string
	ShowConnect bool
	ReceiptWhen string
	SendingLine string
	SendingPct  int
	Dot         string
	ScannerLine string
	AutoLine    string
	PausedLine  string
	Rows        []string
	// RefusedRows are stacks Sally refused, in words.
	RefusedRows []string
	// HeldLine counts stacks scanned for another company.
	HeldLine string
	// ConnectedLine is "Connected as <approver> · <PC>", or the PC alone.
	ConnectedLine string
	// TodayLine counts today's stacks and sheets and the pages waiting.
	TodayLine string
	// FolderLine counts the watched folder's files waiting and sent
	// today; FolderErrorWhen is when its last problem was.
	FolderLine      string
	FolderErrorWhen string
}

func clock(t time.Time) string {
	return strings.ToLower(t.Local().Format("3:04 PM"))
}

func (s *server) scanCard() scanCard {
	if s.desk == nil {
		msg := "Scanning is not running."
		if s.deskErr != "" {
			msg = "Scanning is not running: " + s.deskErr
		}
		return scanCard{Unavailable: msg}
	}
	v := s.desk.Snapshot()
	c := scanCard{View: v, Available: true}
	if !v.Scanning {
		c.Available = false
		c.Unavailable = "Another copy of Sally Desktop on this PC is driving the scanner. Its status page is on another port (17777 to 17780)."
		return c
	}
	c.ShowConnect = !v.Paired && (v.Pairing == nil || !v.Pairing.Waiting)
	if v.ApproverName != "" {
		c.ConnectedLine = "Connected as " + v.ApproverName + " · " + v.PCName
	} else {
		c.ConnectedLine = v.PCName
	}
	c.TodayLine = fmt.Sprintf("Today: %d %s · %d %s · %d %s waiting to go up",
		v.TodayStacks, plural2(v.TodayStacks, "stack", "stacks"),
		v.TodaySheets, plural2(v.TodaySheets, "sheet", "sheets"),
		v.SidesWaiting, pagesWord(v.SidesWaiting))
	if !v.ReceiptAt.IsZero() {
		c.ReceiptWhen = clock(v.ReceiptAt)
	}
	if v.WatchedFolder != "" {
		c.FolderLine = fmt.Sprintf("%d %s waiting · %d sent today",
			v.FolderWaiting, plural2(v.FolderWaiting, "file", "files"), v.FolderSentToday)
	}
	if v.FolderError != "" && !v.FolderErrorAt.IsZero() {
		c.FolderErrorWhen = clock(v.FolderErrorAt)
	}

	switch {
	case v.SendingTotal > 0 && v.SendingSent < v.SendingTotal:
		c.SendingLine = fmt.Sprintf("Sending %d %s to Sally · %d sent", v.SendingTotal, pagesWord(v.SendingTotal), v.SendingSent)
		c.SendingPct = v.SendingSent * 100 / v.SendingTotal
		if !v.Paired {
			c.SendingLine = fmt.Sprintf("%d %s waiting to go to Sally", v.SidesWaiting, pagesWord(v.SidesWaiting))
		}
	case len(v.Recent) > 0:
		c.SendingLine = "Everything scanned is with Sally."
	}

	kind := map[string]string{"USB": "USB", "NETWORK": "network"}[v.ScannerKind]
	state := ""
	c.Dot = "warn"
	switch {
	case v.ScannerKind == "NONE" || v.ScannerKind == "":
		state = "No scanner found. Connect it by USB, or type a network scanner's address below."
		c.Dot = ""
	case v.ScanRunning:
		state = fmt.Sprintf("Scanning · %d %s so far", v.ScanSides, pagesWord(v.ScanSides))
		c.Dot = "ok"
	case v.ScannerState == "IDLE":
		state = "Ready for the next stack"
		if v.AdfLoaded {
			state = "Paper in the feeder"
		}
		c.Dot = "ok"
	case v.ScannerState == "JAMMED":
		state = "Paper jam or cover open"
	case v.ScannerState == "PROCESSING":
		state = "Busy"
		c.Dot = "ok"
	case v.ScannerState == "OFFLINE":
		state = "Not answering"
	default:
		state = "Checking…"
	}
	if v.ScannerName != "" {
		c.ScannerLine = v.ScannerName + " · " + kind + " · " + state
	} else {
		c.ScannerLine = state
	}

	if v.AutoStart {
		c.AutoLine = fmt.Sprintf("Starts by itself when paper sits in the feeder for %d seconds.", v.StartDelaySec)
	} else {
		c.AutoLine = "Starting by itself is off in Sally. Use Scan now."
	}
	if v.Paused {
		c.PausedLine = "Paused until you resume."
		if v.PausedUntil != nil {
			c.PausedLine = "Paused until " + clock(*v.PausedUntil) + "."
		}
		c.PausedLine += " Paper put in now isn't sent to Sally."
	} else if v.HeldWhilePaused {
		c.AutoLine += " The paper in the feeder went in while paused: take it out and put it back, or press Scan now."
	}

	for _, r := range v.Recent {
		state := map[string]string{"SAFE": "safe on this PC", "SENDING": "sending", "SENT": "sent"}[r.State]
		row := fmt.Sprintf("%s · %d %s · %s", clock(r.At), r.Sheets, plural2(r.Sheets, "sheet", "sheets"), state)
		if r.Problem != "" {
			row += " · stopped early"
		}
		if r.Refused != "" {
			row += " · refused by Sally"
		}
		c.Rows = append(c.Rows, row)
	}
	if v.Held > 0 {
		c.HeldLine = fmt.Sprintf("%d %s scanned for another company %s kept on this PC.",
			v.Held, plural2(v.Held, "stack", "stacks"), plural2(v.Held, "is", "are"))
	}
	for _, r := range v.Refused {
		c.RefusedRows = append(c.RefusedRows, fmt.Sprintf("Stack %s: Sally refused it — %s; its pages are kept on this PC.", clock(r.At), r.Refused))
	}
	return c
}

func pagesWord(n int) string { return plural2(n, "page", "pages") }

func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
