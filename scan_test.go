package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/desktop"
	"github.com/sallyerp/sally-print-agent/internal/outbox"
)

type fakeDesk struct {
	calls []string
	view  desktop.View
}

func (f *fakeDesk) Snapshot() desktop.View { return f.view }
func (f *fakeDesk) Pause(m int)            { f.calls = append(f.calls, "pause"+itoa(m)) }
func (f *fakeDesk) Resume()                { f.calls = append(f.calls, "resume") }
func (f *fakeDesk) ScanNow()               { f.calls = append(f.calls, "now") }
func (f *fakeDesk) Connect()               { f.calls = append(f.calls, "connect") }
func (f *fakeDesk) SetSounds(on bool)      { f.calls = append(f.calls, "sounds"+boolStr(on)) }
func (f *fakeDesk) SetKeepCopies(on bool)  { f.calls = append(f.calls, "keep"+boolStr(on)) }
func (f *fakeDesk) SetScannerAddress(a string) error {
	f.calls = append(f.calls, "addr:"+a)
	return nil
}
func (f *fakeDesk) SetWatchedFolder(p string) error {
	if p != "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, ":\\") {
		return errBadRequest("type the folder's full path")
	}
	f.calls = append(f.calls, "folder:"+p)
	return nil
}

func (f *fakeDesk) StopPile(job string) error {
	if job != f.view.JobID || job == "" {
		return errBadRequest("That pile has already finished.")
	}
	f.calls = append(f.calls, "stop:"+job)
	return nil
}
func (f *fakeDesk) SelectScanner(id string) error {
	if id != "" && !strings.HasPrefix(id, "sc-") {
		return errBadRequest("That scanner is not on this PC's list.")
	}
	f.calls = append(f.calls, "select:"+id)
	return nil
}
func (f *fakeDesk) LookAgain() { f.calls = append(f.calls, "look") }

func itoa(n int) string {
	return map[int]string{0: "0", 15: "15", 60: "60"}[n]
}
func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func scanServer(t *testing.T) (*server, *fakeDesk) {
	s, _ := newTestServer(t, nil, nil)
	d := &fakeDesk{view: desktop.View{
		JobID:    "j20261014T091502-3f9a",
		Scanning: true, Paired: true, CompanyName: "Alpha Traders",
		ScannerKind: "USB", ScannerName: "HP ScanJet Pro N4000 snw1", ScannerState: "IDLE",
		Receipt: "Got 48 sheets. Safe on this PC.", SendingTotal: 65, SendingSent: 31, StacksWaiting: 1, SidesWaiting: 34,
		AutoStart: true, StartDelaySec: 3, SoundsOn: true, KeepCopies: true,
		Recent: []outbox.LastStack{{Stack: "s1", Sheets: 48, Sides: 96, State: "SENDING"}},
	}}
	s.desk = d
	return s, d
}

// control builds a request the status page itself would send.
func control(s *server, path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = "127.0.0.1:17777"
	req.Header.Set("Origin", "http://127.0.0.1:17777")
	req.Header.Set(localHeader, "1")
	req.Header.Set(csrfHeader, s.csrf)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func serve(s *server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

func TestScannerControlsWorkFromTheStatusPage(t *testing.T) {
	s, d := scanServer(t)
	for _, c := range []struct{ path, body, want string }{
		{"/scan/pause", "minutes=15", "pause15"},
		{"/scan/pause", "minutes=0", "pause0"},
		{"/scan/resume", "", "resume"},
		{"/scan/now", "", "now"},
		{"/scan/connect", "", "connect"},
		{"/scan/sounds", "on=false", "soundsoff"},
		{"/scan/keep", "on=true", "keepon"},
		{"/scan/scanner", "address=192.168.1.20", "addr:192.168.1.20"},
		{"/scan/folder", "path=C%3A%5CUsers%5CAsha%5CScans", "folder:C:\\Users\\Asha\\Scans"},
		{"/scan/folder", "path=", "folder:"},
		{"/scan/stop", "job=j20261014T091502-3f9a", "stop:j20261014T091502-3f9a"},
		{"/scan/select", "id=sc-0123456789abcdef0123", "select:sc-0123456789abcdef0123"},
		{"/scan/select", "id=", "select:"},
		{"/scan/look", "", "look"},
	} {
		rec := serve(s, control(s, c.path, c.body))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.path, rec.Code, rec.Body)
		}
		if got := d.calls[len(d.calls)-1]; got != c.want {
			t.Fatalf("%s: called %q, want %q", c.path, got, c.want)
		}
	}
	// localhost is the same page.
	req := control(s, "/scan/now", "")
	req.Host = "localhost:17777"
	req.Header.Set("Origin", "http://localhost:17777")
	if rec := serve(s, req); rec.Code != http.StatusOK {
		t.Fatalf("localhost: %d", rec.Code)
	}
	if rec := serve(s, control(s, "/scan/pause", "minutes=7")); rec.Code != http.StatusBadRequest {
		t.Fatalf("odd pause: %d", rec.Code)
	}
}

func TestNoWebPageCanUseTheScannerControls(t *testing.T) {
	s, d := scanServer(t)
	cases := map[string]func(*http.Request){
		"Sally itself":           func(r *http.Request) { r.Header.Set("Origin", "https://sallyerp.in") },
		"a hostile site":         func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"DNS rebinding":          func(r *http.Request) { r.Host = "evil.example:17777"; r.Header.Del("Origin") },
		"another port":           func(r *http.Request) { r.Host = "127.0.0.1:17778" },
		"no page token":          func(r *http.Request) { r.Header.Del(csrfHeader) },
		"a wrong page token":     func(r *http.Request) { r.Header.Set(csrfHeader, "guess") },
		"no local marker":        func(r *http.Request) { r.Header.Del(localHeader) },
		"a GET":                  func(r *http.Request) { r.Method = http.MethodGet },
		"a token in a form only": func(r *http.Request) { r.Header.Del(csrfHeader); r.URL.RawQuery = "X-Sally-CSRF=" + s.csrf },
	}
	paths := map[string]string{
		"/scan/pause": "minutes=15", "/scan/resume": "", "/scan/now": "", "/scan/connect": "",
		"/scan/sounds": "on=true", "/scan/keep": "on=true", "/scan/scanner": "address=192.168.1.20",
		"/scan/folder": "path=%2Ftmp", "/scan/stop": "job=j20261014T091502-3f9a",
		"/scan/select": "id=sc-0123456789abcdef0123", "/scan/look": "",
	}
	for name, mutate := range cases {
		for path, body := range paths {
			t.Run(name+" "+path, func(t *testing.T) {
				req := control(s, path, body)
				mutate(req)
				rec := serve(s, req)
				if rec.Code == http.StatusOK {
					t.Fatalf("accepted (%d)", rec.Code)
				}
				if rec.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("scanner routes must never answer CORS")
				}
			})
		}
	}
	if len(d.calls) != 0 {
		t.Fatalf("a refused request reached the scanner: %v", d.calls)
	}

	// A preflight from Sally gets nothing either: the /v1 CORS rules do not
	// extend to scanning.
	req := httptest.NewRequest(http.MethodOptions, "/scan/now", nil)
	req.Host = "127.0.0.1:17777"
	req.Header.Set("Origin", "https://sallyerp.in")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := serve(s, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("preflight answered %d %v", rec.Code, rec.Header())
	}
}

func TestStatusJSONIsLocalAndCountsOnly(t *testing.T) {
	s, _ := scanServer(t)
	get := func(mutate func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/status.json", nil)
		req.Host = "127.0.0.1:17777"
		req.Header.Set(localHeader, "1")
		if mutate != nil {
			mutate(req)
		}
		return serve(s, req)
	}
	rec := get(nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"stamp"`) || !strings.Contains(body, `"sidesWaiting":34`) {
		t.Fatalf("body %s", body)
	}
	if strings.Contains(body, "test-token") || strings.Contains(body, s.csrf) {
		t.Fatal("the status JSON must not carry a token")
	}
	for name, m := range map[string]func(*http.Request){
		"foreign origin":  func(r *http.Request) { r.Header.Set("Origin", "https://sallyerp.in") },
		"rebinding":       func(r *http.Request) { r.Host = "evil.example:17777" },
		"no local marker": func(r *http.Request) { r.Header.Del(localHeader) },
		"POST":            func(r *http.Request) { r.Method = http.MethodPost },
	} {
		if rec := get(m); rec.Code == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStatusPageShowsTheScannerCard(t *testing.T) {
	s, _ := scanServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:17777"
	rec := serve(s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d", rec.Code)
	}
	page := rec.Body.String()
	for _, want := range []string{
		"<title>Sally Desktop: printing and scanning</title>",
		`<meta name="sally-csrf" content="` + s.csrf + `">`,
		"Files into", "Alpha Traders",
		"Got 48 sheets. Safe on this PC.",
		"Sending 65 pages to Sally · 31 sent",
		"HP ScanJet Pro N4000 snw1 · USB · Ready for the next stack",
		"Pause 15 min", "Pause 1 hour", "Pause until resumed",
		"Play sounds", "Keep a copy",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	// Opened under another name (DNS rebinding): refused, token not shown.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "evil.example:17777"
	rec = serve(s, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), s.csrf) {
		t.Fatalf("rebinding: %d", rec.Code)
	}
}

func TestStatusPageWithoutScanning(t *testing.T) {
	s, _ := newTestServer(t, nil, nil)
	s.deskErr = "turned off"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:17777"
	rec := serve(s, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Scanning is not running: turned off") {
		t.Fatalf("%d", rec.Code)
	}
	if rec := serve(s, control(s, "/scan/now", "")); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("control without scanning: %d", rec.Code)
	}
}

func TestResolveSallyURL(t *testing.T) {
	for _, c := range []struct{ flag, env, cfg, want string }{
		{"", "", "", "https://sallyerp.in"},
		{"", "", "https://staging.sallyerp.in/", "https://staging.sallyerp.in"},
		{"", "http://localhost:3000", "https://x.in", "http://localhost:3000"},
		{"https://flag.in", "http://localhost:3000", "", "https://flag.in"},
	} {
		got, err := resolveSallyURL(c.flag, c.env, c.cfg)
		if err != nil || got != c.want {
			t.Errorf("%+v → %q %v", c, got, err)
		}
	}
	for _, bad := range []string{"http://sallyerp.in", "ftp://x", "https://u:p@x.in", "nonsense"} {
		if _, err := resolveSallyURL(bad, "", ""); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestStatusPageCannotBeFramed(t *testing.T) {
	s, _ := scanServer(t)
	get := func(path, dest string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:17777"
		req.Header.Set(localHeader, "1")
		if dest != "" {
			req.Header.Set("Sec-Fetch-Dest", dest)
		}
		return serve(s, req)
	}
	for _, path := range []string{"/", "/status.json"} {
		rec := get(path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" {
			t.Fatalf("%s: framing headers missing: %v", path, rec.Header())
		}
	}
	if rec := get("/", "document"); rec.Code != http.StatusOK {
		t.Fatalf("a top-level visit must work: %d", rec.Code)
	}
	for _, dest := range []string{"iframe", "frame", "IFRAME"} {
		rec := get("/", dest)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), s.csrf) {
			t.Errorf("Sec-Fetch-Dest %s: %d", dest, rec.Code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("Sec-Fetch-Dest %s: no X-Frame-Options on the refusal", dest)
		}
	}
}

func TestStatusPageShowsARefusedStack(t *testing.T) {
	s, d := scanServer(t)
	d.view.Refused = []outbox.LastStack{{Stack: "s0", Sheets: 2, Sides: 4, Refused: "That stack is not yours."}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:17777"
	page := serve(s, req).Body.String()
	if !strings.Contains(page, "Sally refused it — That stack is not yours.; its pages are kept on this PC.") {
		t.Fatal("the refused stack is not on the page")
	}
}

func TestStatusPageCountsStacksForAnotherCompany(t *testing.T) {
	s, d := scanServer(t)
	d.view.Held = 2
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:17777"
	if page := serve(s, req).Body.String(); !strings.Contains(page, "2 stacks scanned for another company are kept on this PC.") {
		t.Fatal("the held stacks are not on the page")
	}
}

func TestStatusPageSaysWhoAndToday(t *testing.T) {
	s, d := scanServer(t)
	d.view.ApproverName, d.view.PCName = "Asha Rao", "FRONT-DESK"
	d.view.TodayStacks, d.view.TodaySheets = 2, 61
	d.view.SignedCopiesURL = "https://sallyerp.in/invoices/acknowledgments"
	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1:17777"
		return serve(s, req).Body.String()
	}
	page := get()
	for _, want := range []string{
		"Connected as Asha Rao · FRONT-DESK",
		"Today: 2 stacks · 61 sheets · 34 pages waiting to go up",
		`<a href="https://sallyerp.in/invoices/acknowledgments" target="_blank" rel="noopener noreferrer">Open Signed copies</a>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	d.view.ApproverName = ""
	if page := get(); strings.Contains(page, "Connected as") || !strings.Contains(page, ">FRONT-DESK</p>") {
		t.Error("without an approver only the PC name shows")
	}
}

func TestTheWatchedFolderIsChosenOnlyFromTheStatusPage(t *testing.T) {
	s, d := scanServer(t)
	if rec := serve(s, control(s, "/scan/folder", "path=Scans")); rec.Code != http.StatusBadRequest {
		t.Fatalf("a relative path: %d", rec.Code)
	}
	for name, mutate := range map[string]func(*http.Request){
		"Sally itself":       func(r *http.Request) { r.Header.Set("Origin", "https://sallyerp.in") },
		"a hostile site":     func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"DNS rebinding":      func(r *http.Request) { r.Host = "evil.example:17777"; r.Header.Del("Origin") },
		"no page token":      func(r *http.Request) { r.Header.Del(csrfHeader) },
		"a wrong page token": func(r *http.Request) { r.Header.Set(csrfHeader, "guess") },
		"no local marker":    func(r *http.Request) { r.Header.Del(localHeader) },
		"a GET":              func(r *http.Request) { r.Method = http.MethodGet },
	} {
		t.Run(name, func(t *testing.T) {
			req := control(s, "/scan/folder", "path=%2Ftmp%2Fevil")
			mutate(req)
			rec := serve(s, req)
			if rec.Code == http.StatusOK {
				t.Fatalf("accepted (%d)", rec.Code)
			}
			if rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("the folder route must never answer CORS")
			}
		})
	}
	if len(d.calls) != 0 {
		t.Fatalf("a refused request changed the folder: %v", d.calls)
	}
}

func TestStatusPageShowsTheWatchedFolder(t *testing.T) {
	s, d := scanServer(t)
	page := func() string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1:17777"
		return serve(s, req).Body.String()
	}
	if p := page(); !strings.Contains(p, "Watched folder") || !strings.Contains(p, "Choose the folder your scanner") || strings.Contains(p, `id="folder-clear"`) {
		t.Fatal("the empty folder card is missing or offers Clear")
	}
	d.view.WatchedFolder = `C:\Users\Asha\Scans`
	d.view.FolderWaiting, d.view.FolderSentToday = 2, 3
	d.view.FolderError = "scan.pdf could not be moved to Sent to Sally yet"
	p := page()
	for _, want := range []string{`Watching <code>C:\Users\Asha\Scans</code>`, "2 files waiting · 3 sent today", "could not be moved", `id="folder-clear"`} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The status JSON carries counts, never the path.
	req := httptest.NewRequest(http.MethodGet, "/status.json", nil)
	req.Host = "127.0.0.1:17777"
	req.Header.Set(localHeader, "1")
	body := serve(s, req).Body.String()
	if strings.Contains(body, "Asha") || !strings.Contains(body, `"sentToday":3`) {
		t.Fatalf("status JSON %s", body)
	}
}

func TestAStopForAnotherPileAnswers400(t *testing.T) {
	s, d := scanServer(t)
	rec := serve(s, control(s, "/scan/stop", "job=j20261014T091502-0000"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "That pile has already finished.") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := serve(s, control(s, "/scan/select", "id=nonsense")); rec.Code != http.StatusBadRequest {
		t.Fatalf("select: %d", rec.Code)
	}
	if len(d.calls) != 0 {
		t.Fatalf("%v", d.calls)
	}
}

func page(s *server) string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:17777"
	return serve(s, req).Body.String()
}

func TestTheStatusPageStopAndScannerList(t *testing.T) {
	s, d := scanServer(t)
	if strings.Contains(page(s), `data-post="/scan/stop"`) {
		t.Fatal("Stop shows only while a pile scans")
	}
	d.view.ScanRunning, d.view.ScanSides, d.view.StopRequested = true, 7, true
	p := page(s)
	for _, want := range []string{
		`data-post="/scan/stop" data-job="j20261014T091502-3f9a">Stop this pile</button>`,
		"Press again to stop. The sheets already scanned are kept.",
		"Scanning · 7 pages so far · stopping after this sheet",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The list: names escaped, tags, the choice.
	at := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	no := false
	d.view.ScanRunning = false
	d.view.Scanners = []desktop.ScannerRow{
		{ID: "sc-0123456789abcdef0123", Name: "Front desk <script>alert(1)</script>", Kind: "USB and network", Answering: true, Stable: true, InUse: true, Chosen: true},
		{ID: "sc-aaaaaaaaaaaaaaaaaaaa", Name: "Back office", Detail: "Back office [0B0B0B]", Kind: "network", Feeder: &no},
	}
	d.view.ChosenID, d.view.ChosenBy, d.view.ChosenAt = "sc-0123456789abcdef0123", "Dana Field", &at
	p = page(s)
	if strings.Contains(p, "<script>alert(1)") || !strings.Contains(p, "Front desk &lt;script&gt;") {
		t.Fatal("a scanner name must be escaped")
	}
	for _, want := range []string{
		"Scanners", "Automatic: the USB scanner first",
		`value="sc-0123456789abcdef0123" checked`, "USB and network · in use",
		"Back office (Back office [0B0B0B])", "network · not answering · no document feeder · may change after replugging",
		"Use this scanner", "Look again", "Chosen in Sally by Dana Field at ",
		"Add a network scanner by its address", "Add this address",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	d.view.ChosenBy = "PC"
	if !strings.Contains(page(s), "Chosen on this PC at ") {
		t.Error("a choice made here says so")
	}
	// A chosen scanner that is not answering.
	d.view.ChosenMissing, d.view.ChosenName = true, "Back office"
	if !strings.Contains(page(s), "Back office is not answering. Sally Desktop waits for it and does not switch to another scanner.") {
		t.Error("the missing-scanner words")
	}
}

func TestTheStopWordsAreAWarningNotAReceipt(t *testing.T) {
	s, d := scanServer(t)
	d.view.Receipt = ""
	d.view.Stopped = "Stopped after 2 sheets. They are safe on this PC. Put every sheet after them back on the pile; if you are not sure, put back a few more: Sally sets aside any sheet it already has. Then press Scan now to scan the rest, or take the pile out."
	d.view.StoppedFromSally, d.view.StoppedBy, d.view.StoppedAt = true, "Dana Field", time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	p := page(s)
	if !strings.Contains(p, `<p class="problem" id="stopped-line">Stopped after 2 sheets.`) || !strings.Contains(p, "Stopped from Sally by Dana Field at ") {
		t.Fatal("the Stop words")
	}
	if strings.Contains(p, `class="receipt"`) || strings.Contains(p, "You can take the paper out") {
		t.Fatal("the Stop words must not look like a receipt")
	}
	d.view.Stopped, d.view.HoldState = "", "AFTER_STOP_ON_PC"
	if !strings.Contains(page(s), "The pile was stopped. Take it out, or press Scan now to scan the rest.") {
		t.Fatal("the hold line")
	}
	d.view.Pending, d.view.PendingFromSally, d.view.PendingUntil = "SCAN_NOW", true, time.Date(2026, 10, 14, 9, 32, 0, 0, time.UTC)
	if !strings.Contains(page(s), "Sally asked for a scan. Waiting for paper until ") {
		t.Fatal("the Sally-asked note")
	}
}

func TestTheStampIgnoresTheSideCountButNotTheList(t *testing.T) {
	v := desktop.View{ScanRunning: true, JobID: "j1", ScanSides: 3, Scanners: []desktop.ScannerRow{{ID: "sc-1", Answering: true}}}
	base := statusStamp(v)
	v.ScanSides = 9
	if statusStamp(v) != base {
		t.Fatal("the side count must not reload the page")
	}
	v.Scanners = []desktop.ScannerRow{{ID: "sc-1", Answering: false}}
	if statusStamp(v) == base {
		t.Fatal("an answering flag must change the stamp")
	}
	v.Scanners[0].Answering = true
	v.ChosenID = "sc-1"
	if statusStamp(v) == base {
		t.Fatal("the choice must change the stamp")
	}

	s, d := scanServer(t)
	d.view.ScanRunning, d.view.ScanSides = true, 5
	req := httptest.NewRequest(http.MethodGet, "/status.json", nil)
	req.Host = "127.0.0.1:17777"
	req.Header.Set(localHeader, "1")
	body := serve(s, req).Body.String()
	if !strings.Contains(body, `"live":{"jobId":"j20261014T091502-3f9a","line":`) || !strings.Contains(body, `"sides":5,"stopping":false}`) {
		t.Fatalf("live %s", body)
	}
}
