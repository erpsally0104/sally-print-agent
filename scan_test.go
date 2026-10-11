package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := control(s, "/scan/now", "")
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
		"Pause 15 min", "Pause 1 hour", "Pause until I resume",
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
