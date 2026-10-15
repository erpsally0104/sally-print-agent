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
	// StopPile stops the running pile job after the current sheet;
	// SelectScanner chooses the scanner ("" = automatic); LookAgain
	// refreshes the scanner list.
	StopPile(job string) error
	SelectScanner(id string) error
	LookAgain()
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
	// Stop this pile: the job id the page showed. A pile that is not the
	// running one answers 400 "That pile has already finished."
	mux.HandleFunc("/scan/stop", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		if err := d.StopPile(r.FormValue("job")); err != nil {
			return errBadRequest(err.Error())
		}
		return nil
	})))
	// The scanner choice: an id from the list, or "" for automatic.
	mux.HandleFunc("/scan/select", s.requireLocalControl(s.withDesk(func(d scanDesk, r *http.Request) error {
		if err := d.SelectScanner(r.FormValue("id")); err != nil {
			return errBadRequest(err.Error())
		}
		return nil
	})))
	mux.HandleFunc("/scan/look", s.requireLocalControl(s.withDesk(func(d scanDesk, _ *http.Request) error {
		d.LookAgain()
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
		// What changes during a pile, updated in place without a reload.
		"live": map[string]any{
			"jobId": v.JobID, "sides": v.ScanSides, "stopping": v.StopRequested, "line": scannerLine(v),
		},
		"stamp": statusStamp(v),
	}
	if v.PausedUntil != nil {
		body["pausedUntil"] = v.PausedUntil.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, body)
}

// statusStamp changes whenever anything shown on the scanner card changes,
// so the page reloads only then. The side count of a running pile is not
// in it: the page updates that line in place from status.json's live part.
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
	add(strconv.FormatBool(v.AdfLoaded) + strconv.FormatBool(v.ScanRunning) + v.JobID)
	add(strconv.FormatBool(v.Paused) + strconv.FormatBool(v.HeldWhilePaused) + v.Pending + strconv.FormatBool(v.PendingFromSally))
	add(v.ScannerID + "/" + v.HoldState + "/" + v.Stopped + "/" + v.StoppedBy)
	add(v.ChosenID + "/" + v.ChosenName + "/" + v.ChosenBy + "/" + strconv.FormatBool(v.ChosenMissing))
	add(v.LinkReason + "/" + v.LinkName)
	for _, r := range v.Scanners {
		add(r.ID + r.Name + r.Kind + r.Detail + strconv.FormatBool(r.Answering) + r.Reason + strconv.FormatBool(r.InUse) + strconv.FormatBool(r.Chosen))
	}
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
	// StoppedLine says who stopped the pile from Sally, and when.
	StoppedLine string
	// HoldLine is the hold after a Stop.
	HoldLine string
	// PendingLine is the note while a Scan now waits for paper.
	PendingLine string
	// ChosenLine says who chose the scanner and when; ScannerRows are the
	// Scanners block's choices.
	ChosenLine  string
	ScannerRows []scannerRow
	// AutoChosen: no scanner is chosen (Automatic).
	AutoChosen bool
}

// scannerRow is one choice in the Scanners block.
type scannerRow struct {
	ID      string
	Name    string
	Tags    string
	Checked bool
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

	c.ScannerLine = scannerLine(v)
	c.Dot = "warn"
	switch {
	case v.ChosenMissing:
	case (v.ScannerKind == "NONE" || v.ScannerKind == "") && v.LinkReason != desktop.ReasonWindows:
		c.Dot = ""
	case v.ScanRunning || v.ScannerState == "IDLE" || v.ScannerState == "PROCESSING":
		c.Dot = "ok"
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

	if v.Stopped != "" && v.StoppedFromSally {
		c.StoppedLine = "Stopped from Sally at " + clock(v.StoppedAt) + "."
		if v.StoppedBy != "" {
			c.StoppedLine = "Stopped from Sally by " + v.StoppedBy + " at " + clock(v.StoppedAt) + "."
		}
	}
	if (v.HoldState == "AFTER_STOP" || v.HoldState == "AFTER_STOP_ON_PC") && v.Stopped == "" {
		c.HoldLine = "The pile was stopped. Take it out, or press Scan now to scan the rest."
	}
	if v.Pending != "" {
		c.PendingLine = "Waiting for paper in the feeder to scan once."
		if v.PendingFromSally {
			c.PendingLine = "Sally asked for a scan. Waiting for paper until " + clock(v.PendingUntil) + "."
		}
	}
	c.AutoChosen = v.ChosenID == ""
	if v.ChosenAt != nil && !c.AutoChosen {
		if v.ChosenBy == "PC" {
			c.ChosenLine = "Chosen on this PC at " + clock(*v.ChosenAt) + "."
		} else if v.ChosenBy != "" {
			c.ChosenLine = "Chosen in Sally by " + v.ChosenBy + " at " + clock(*v.ChosenAt) + "."
		} else {
			c.ChosenLine = "Chosen in Sally at " + clock(*v.ChosenAt) + "."
		}
	}
	for _, r := range v.Scanners {
		var tags []string
		if r.Kind != "" {
			tags = append(tags, r.Kind)
		}
		if r.InUse {
			tags = append(tags, "in use")
		}
		if !r.Answering {
			switch r.Reason {
			case desktop.ReasonNotFound:
				tags = append(tags, "not found on USB")
			case desktop.ReasonWindows:
				tags = append(tags, "USB connection blocked by Windows")
			default:
				tags = append(tags, "not answering")
			}
		}
		if r.Feeder != nil && !*r.Feeder {
			tags = append(tags, "no document feeder")
		}
		if !r.Stable {
			tags = append(tags, "may change after replugging")
		}
		name := r.Name
		if r.Detail != "" {
			name += " (" + r.Detail + ")"
		}
		c.ScannerRows = append(c.ScannerRows, scannerRow{ID: r.ID, Name: name, Tags: strings.Join(tags, " · "), Checked: r.Chosen})
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

// scannerLine is the scanner's line on the card: its name, how it is
// reached and what it is doing, or why it cannot be used.
func scannerLine(v desktop.View) string {
	const waits = " Sally Desktop waits for it and does not switch to another scanner. Choose Automatic to use whichever scanner answers."
	if v.ChosenMissing {
		name := v.ChosenName
		if name == "" {
			name = "The chosen scanner"
		}
		switch v.LinkReason {
		case desktop.ReasonNotFound:
			return name + " is not found on USB. Check that it is plugged in and switched on, or unplug it and plug it back in." + waits
		case desktop.ReasonWindows:
			return windowsHoldsLine(name)
		}
		return name + " is not answering." + waits
	}
	if (v.ScannerKind == "NONE" || v.ScannerKind == "") && v.LinkReason == desktop.ReasonWindows {
		name := v.LinkName
		if name == "" {
			name = "The USB scanner"
		}
		return windowsHoldsLine(name)
	}
	kind := map[string]string{"USB": "USB", "NETWORK": "network"}[v.ScannerKind]
	state := ""
	switch {
	case v.ScannerKind == "NONE" || v.ScannerKind == "":
		state = "No scanner found. Connect it by USB, or type a network scanner's address below."
	case v.ScanRunning:
		state = fmt.Sprintf("Scanning · %d %s so far", v.ScanSides, pagesWord(v.ScanSides))
		if v.StopRequested {
			state += " · stopping after this sheet"
		}
	case v.ScannerState == "IDLE":
		state = "Ready for the next stack"
		if v.AdfLoaded {
			state = "Paper in the feeder"
		}
	case v.ScannerState == "JAMMED":
		state = "Paper jam or cover open"
	case v.ScannerState == "PROCESSING":
		state = "Busy"
	case v.ScannerState == "OFFLINE":
		state = "Not answering"
	default:
		state = "Checking…"
	}
	if v.ScannerName != "" {
		return v.ScannerName + " · " + kind + " · " + state
	}
	return state
}

// windowsHoldsLine says that Windows will not let the agent use a
// scanner's USB connection, with what is known of why.
func windowsHoldsLine(name string) string {
	return name + " is plugged in, but Windows is not letting Sally Desktop use its USB connection: another scan app may be using it, or Windows switched it to its maker's mode. " +
		"Unplug it and plug it back in, or, if it is on your network, choose it there or type its address below."
}

func pagesWord(n int) string { return plural2(n, "page", "pages") }

func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
