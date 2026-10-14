package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/autoscan"
	"github.com/sallyerp/sally-print-agent/internal/escl"
	"github.com/sallyerp/sally-print-agent/internal/sound"
)

func init() { sound.SetEnabled(false) }

func newAgent(t *testing.T, baseURL string, disc Discoverer) *Agent {
	t.Helper()
	a, err := New(Options{
		Dir: t.TempDir(), BaseURL: baseURL, Version: "1.1.0-test",
		Discover: disc, PollEvery: 10 * time.Millisecond, Scanning: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	a.local.SoundsOff = true
	return a
}

func pairedAgent(t *testing.T, baseURL string, disc Discoverer) *Agent {
	a := newAgent(t, baseURL, disc)
	if err := a.tokens.Set("tok"); err != nil {
		t.Fatal(err)
	}
	a.local.CompanyID, a.local.CompanyName, a.local.DeviceID = "co-1", "Alpha Traders", "dev-1"
	a.client.SetAuth("tok", "co-1")
	a.store.SetOwner("co-1", "dev-1")
	a.paired, a.needs = true, false
	return a
}

func TestHeartbeatAppliesSettingsAndCommandsInOrder(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/heartbeat" || r.Header.Get("x-active-company-id") != "co-1" {
			w.WriteHeader(404)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"heartbeatSec":15,"companyName":"Alpha Traders Pvt","settings":{"autoStart":false,"startDelaySec":5},
		 "commands":[{"id":"1","kind":"PAUSE","pauseMinutes":15},{"id":"2","kind":"RESUME"},{"id":"3","kind":"PAUSE","pauseMinutes":null},
		             {"id":"4","kind":"SCAN_NOW"},{"id":"5","kind":"SELF_DESTRUCT"}]}`)
	}))
	defer srv.Close()
	a := pairedAgent(t, srv.URL, nil)
	a.heartbeatOnce(context.Background())

	if got["agentVersion"] != "1.1.0-test" || got["pause"] == nil || got["outbox"] == nil || got["scanner"] == nil {
		t.Fatalf("heartbeat body %v", got)
	}
	v := a.Snapshot()
	if !v.Paused || v.PausedUntil != nil {
		t.Fatalf("the last PAUSE (until resumed) should hold: %+v %v", v.Paused, v.PausedUntil)
	}
	if v.AutoStart || v.StartDelaySec != 5 || v.CompanyName != "Alpha Traders Pvt" {
		t.Fatalf("settings not applied: %+v", v)
	}
	if v.Pending != string(autoscan.ScanNow) {
		t.Fatalf("SCAN_NOW should be waiting for paper, got %q", v.Pending)
	}
	if a.hbEvery != 15*time.Second {
		t.Fatalf("heartbeat interval %s", a.hbEvery)
	}
	// The pause survives a restart.
	b, err := New(Options{Dir: a.opt.Dir, BaseURL: srv.URL, Version: "x", Scanning: true})
	if err != nil {
		t.Fatal(err)
	}
	if !b.Snapshot().Paused || !b.Snapshot().Paired {
		t.Fatal("pause and pairing should be remembered")
	}
}

func TestHeartbeatReportsThePauseItApplied(t *testing.T) {
	var bodies []map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b)
		first := len(bodies) == 1
		mu.Unlock()
		if first {
			io.WriteString(w, `{"commands":[{"id":"1","kind":"PAUSE","pauseMinutes":60}]}`)
			return
		}
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	a := pairedAgent(t, srv.URL, nil)
	a.heartbeatOnce(context.Background())
	a.heartbeatOnce(context.Background())
	p := bodies[1]["pause"].(map[string]any)
	if p["paused"] != true || p["until"] == nil {
		t.Fatalf("second heartbeat pause %v", p)
	}
}

func TestA401DropsTheTokenAndA403KeepsIt(t *testing.T) {
	code := 403
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		io.WriteString(w, `{"error":"no","code":"PLAN"}`)
	}))
	defer srv.Close()
	a := pairedAgent(t, srv.URL, nil)

	a.heartbeatOnce(context.Background())
	v := a.Snapshot()
	if !v.Paired || v.NeedsConnect || !strings.Contains(v.Denied, "plan") {
		t.Fatalf("403 must keep the token and explain: %+v", v)
	}
	if _, err := a.tokens.Get(); err != nil {
		t.Fatal("the token must stay after a 403")
	}

	code = 401
	a.heartbeatOnce(context.Background())
	v = a.Snapshot()
	if v.Paired || !v.NeedsConnect {
		t.Fatalf("401 must show Connect to Sally: %+v", v)
	}
	if _, err := a.tokens.Get(); err == nil {
		t.Fatal("the token must be dropped after a 401")
	}
	if a.client.Paired() {
		t.Fatal("the client must stop sending the dead token")
	}
}

func TestPairingStoresTheTokenAndCompany(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/pair/start":
			io.WriteString(w, `{"deviceCode":"d","userCode":"WXYZ-1234","verificationUri":"u","verificationUriComplete":"https://sally.test/connect?code=WXYZ-1234","interval":1,"expiresIn":60}`)
		case "/api/agent/pair/poll":
			io.WriteString(w, `{"status":"approved","token":"new-tok","device":{"id":"dev","approvedCompanyIds":["co-9"],"capability":"SCAN"},"companyName":"Riverside Hotels","approvedBy":{"id":"u1","name":"Asha Rao"}}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()
	a := newAgent(t, srv.URL, nil)
	var opened string
	a.opt.OpenBrowser = func(u string) error { opened = u; return nil }
	a.pair(context.Background())
	v := a.Snapshot()
	if !v.Paired || v.NeedsConnect || v.CompanyName != "Riverside Hotels" || v.Pairing != nil || v.ApproverName != "Asha Rao" || v.PCName == "" {
		t.Fatalf("%+v", v)
	}
	if opened != "https://sally.test/connect?code=WXYZ-1234" {
		t.Fatalf("browser opened at %q", opened)
	}
	if tok, _ := a.tokens.Get(); tok != "new-tok" {
		t.Fatalf("token %q", tok)
	}
}

func TestNormaliseAddress(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.20":           "http://192.168.1.20:80,https://192.168.1.20:443",
		"192.168.1.20:8080":      "http://192.168.1.20:8080,https://192.168.1.20:8080",
		"scanner.local:443":      "https://scanner.local:443",
		"https://10.0.0.5":       "https://10.0.0.5",
		" http://10.0.0.5:631/ ": "http://10.0.0.5:631",
	} {
		got, err := NormaliseAddress(in)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%q → %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "file:///etc/passwd", "http://user:pw@10.0.0.1", "10.0.0.1:99999", "a b", "<script>"} {
		if _, err := NormaliseAddress(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// fakeScanner is an eSCL scanner: paper in the feeder until a job takes it.
type fakeScanner struct {
	mu     sync.Mutex
	loaded bool
	jam    bool
	pages  int
	served int
	jobs   int
	jamAt  int // jam after this many pages (0 = never)
	body   string
	// simplex: the capabilities advertise no duplex feeder.
	simplex bool
	// failAt answers NextDocument 500 after this many pages (0 = never).
	failAt  int
	deleted []string
}

func (f *fakeScanner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/eSCL/ScannerCapabilities":
		adf := `<scan:Adf><scan:AdfSimplexInputCaps/><scan:AdfDuplexInputCaps/><scan:AdfOptions><scan:AdfOption>DetectPaperLoaded</scan:AdfOption></scan:AdfOptions></scan:Adf>`
		if f.simplex {
			adf = `<scan:Adf><scan:AdfSimplexInputCaps/><scan:AdfOptions><scan:AdfOption>DetectPaperLoaded</scan:AdfOption></scan:AdfOptions></scan:Adf>`
		}
		fmt.Fprintf(w, `<scan:ScannerCapabilities xmlns:scan="%s" xmlns:pwg="%s"><pwg:Version>2.9</pwg:Version><pwg:MakeAndModel>HP ScanJet Pro N4000 snw1</pwg:MakeAndModel>%s</scan:ScannerCapabilities>`, escl.NSScan, escl.NSPWG, adf)
	case r.URL.Path == "/eSCL/ScannerStatus":
		adf := "ScannerAdfEmpty"
		if f.jam {
			adf = "ScannerAdfJam"
		} else if f.loaded {
			adf = "ScannerAdfLoaded"
		}
		fmt.Fprintf(w, `<scan:ScannerStatus xmlns:scan="%s" xmlns:pwg="%s"><pwg:State>Idle</pwg:State><scan:AdfState>%s</scan:AdfState></scan:ScannerStatus>`, escl.NSScan, escl.NSPWG, adf)
	case r.Method == "POST" && r.URL.Path == "/eSCL/ScanJobs":
		b, _ := io.ReadAll(r.Body)
		f.body = string(b)
		if strings.Contains(f.body, "BlankPage") {
			w.WriteHeader(409)
			return
		}
		f.jobs++
		w.Header().Set("Location", fmt.Sprintf("http://%s/eSCL/ScanJobs/%d", r.Host, f.jobs))
		w.WriteHeader(201)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/eSCL/ScanJobs/"):
		f.deleted = append(f.deleted, r.URL.Path)
	case strings.HasSuffix(r.URL.Path, "/NextDocument"):
		if f.failAt > 0 && f.served == f.failAt {
			w.WriteHeader(500)
			return
		}
		if f.jamAt > 0 && f.served == f.jamAt {
			f.jam, f.loaded = true, false
			w.WriteHeader(404)
			return
		}
		if f.served >= f.pages {
			f.loaded = false
			w.WriteHeader(404)
			return
		}
		f.served++
		p := make([]byte, 3000+f.served)
		p[0], p[1] = 0xFF, 0xD8
		p[len(p)-1] = byte(f.served)
		w.Write(p)
	default:
		w.WriteHeader(404)
	}
}

func discoverAt(url string) Discoverer {
	return func(ctx context.Context, _ string, _ func(string, ...any)) (*Scanner, error) {
		return openBase(ctx, url, "eSCL", "")
	}
}

// fakeSallyAll accepts everything and counts confirmed sides.
type fakeSallyAll struct {
	mu        sync.Mutex
	sides     int
	done      int
	announced []map[string]any
	srv       *httptest.Server
}

func newFakeSallyAll(t *testing.T) *fakeSallyAll {
	f := &fakeSallyAll{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		p := r.URL.Path
		switch {
		case p == "/api/agent/heartbeat":
			io.WriteString(w, `{"heartbeatSec":10}`)
		case p == "/api/agent/scan/stacks":
			f.announced = append(f.announced, in)
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"runId":"run-%s","received":[]}`, in["stack"])
		case strings.HasSuffix(p, "/upload-url"):
			var ups []map[string]any
			for _, x := range in["sides"].([]any) {
				d := x.(map[string]any)
				ups = append(ups, map[string]any{"sheet": d["sheet"], "side": d["side"], "ticket": "t", "url": f.srv.URL + "/s3", "method": "PUT", "headers": map[string]string{"Content-Type": "image/jpeg"}})
			}
			json.NewEncoder(w).Encode(map[string]any{"uploads": ups})
		case p == "/s3":
		case strings.HasSuffix(p, "/sides"):
			f.sides++
			w.WriteHeader(201)
			io.WriteString(w, `{"file":{"id":"f"}}`)
		case strings.HasSuffix(p, "/done"):
			f.done++
			io.WriteString(w, `{"status":"PROCESSING"}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestScanNowScansAStackAndSendsIt(t *testing.T) {
	sc := &fakeScanner{loaded: true, pages: 6}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	sally := newFakeSallyAll(t)
	a := pairedAgent(t, sally.srv.URL, discoverAt(scSrv.URL))
	a.Pause(0) // paused: auto-start must not fire, Scan now still does
	a.ScanNow()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "the stack to reach Sally", func() bool {
		sally.mu.Lock()
		defer sally.mu.Unlock()
		return sally.done == 1
	})
	v := a.Snapshot()
	if v.Receipt != "Got 3 sheets. Safe on this PC." {
		t.Fatalf("receipt %q", v.Receipt)
	}
	sally.mu.Lock()
	if sally.sides != 6 || sally.announced[0]["sheets"] != float64(3) || sally.announced[0]["sides"] != float64(6) {
		t.Fatalf("sides %d announced %v", sally.sides, sally.announced)
	}
	sally.mu.Unlock()
	sc.mu.Lock()
	if sc.jobs != 1 || !strings.Contains(sc.body, "<pwg:Version>2.9</pwg:Version>") || !strings.Contains(sc.body, "<scan:Duplex>true</scan:Duplex>") {
		t.Fatalf("jobs %d body %s", sc.jobs, sc.body)
	}
	sc.mu.Unlock()
}

func TestAJamKeepsThePagesAndStartsAgainOnceCleared(t *testing.T) {
	sc := &fakeScanner{loaded: true, pages: 10, jamAt: 4}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	sally := newFakeSallyAll(t)
	a := pairedAgent(t, sally.srv.URL, discoverAt(scSrv.URL))
	a.local.StartDelaySec = 2

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "the jam", func() bool { return strings.HasPrefix(a.Snapshot().Problem, "Paper jam") })
	if p := a.Snapshot().Problem; !strings.Contains(p, "kept the 2 sheets") {
		t.Fatalf("problem %q", p)
	}
	// The person clears the jam and puts the rest back.
	sc.mu.Lock()
	sc.jam, sc.loaded, sc.jamAt = false, true, 0
	sc.mu.Unlock()
	waitFor(t, "the second stack", func() bool {
		sally.mu.Lock()
		defer sally.mu.Unlock()
		return sally.done == 2
	})
	if a.Snapshot().Problem != "" {
		t.Fatal("the jam note should close once the scanner reports it fixed")
	}
	sally.mu.Lock()
	defer sally.mu.Unlock()
	if sally.sides != 10 || sally.announced[0]["sides"] != float64(4) || sally.announced[1]["sides"] != float64(6) {
		t.Fatalf("sides %d, announced %v", sally.sides, sally.announced)
	}
}

func TestHeartbeatReportsARefusedStack(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	w, err := a.store.NewStack(true)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 100)
	p[0], p[1] = 0xFF, 0xD8
	w.Add(p)
	r, _ := w.Finish("", "")
	if err := a.store.MarkRefused(r.Stack, "it does not know this stack"); err != nil {
		t.Fatal(err)
	}
	if e := a.report().Error; e != "Sally refused 1 stack, kept on this PC: it does not know this stack" {
		t.Fatalf("heartbeat error %q", e)
	}
}

func TestAfterARepairStacksForTheOldCompanyAreHeld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/pair/start":
			io.WriteString(w, `{"deviceCode":"d","userCode":"WXYZ-1234","verificationUriComplete":"https://sally.test/connect","interval":1,"expiresIn":60}`)
		case "/api/agent/pair/poll":
			io.WriteString(w, `{"status":"approved","token":"new-tok","device":{"id":"dev-2","approvedCompanyIds":["co-2"],"capability":"SCAN"},"companyName":"Riverside Hotels"}`)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	a := pairedAgent(t, srv.URL, nil)
	scan := func() string {
		w, err := a.store.NewStack(true)
		if err != nil {
			t.Fatal(err)
		}
		p := make([]byte, 100)
		p[0], p[1] = 0xFF, 0xD8
		w.Add(p)
		r, _ := w.Finish("", "")
		return r.Stack
	}
	scan()        // for co-1 / dev-1
	a.dropToken() // revoked
	unconnected := scan()
	a.pair(context.Background())

	st := a.store.Stacks()
	if len(st) != 1 || st[0].Stack != unconnected || st[0].CompanyID != "co-2" || st[0].DeviceID != "dev-2" {
		t.Fatalf("only the stack scanned while unconnected may go to the new company: %+v", st)
	}
	if v := a.Snapshot(); v.Held != 1 {
		t.Fatalf("held %d", v.Held)
	}
}

func TestAOneSidedScannerScansEachPageAsItsOwnSheet(t *testing.T) {
	sc := &fakeScanner{loaded: true, pages: 3, simplex: true}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	sally := newFakeSallyAll(t)
	a := pairedAgent(t, sally.srv.URL, discoverAt(scSrv.URL))
	a.Pause(0)
	a.ScanNow()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "the stack to reach Sally", func() bool {
		sally.mu.Lock()
		defer sally.mu.Unlock()
		return sally.done == 1
	})
	if v := a.Snapshot(); v.Receipt != "Got 3 sheets. Safe on this PC." {
		t.Fatalf("receipt %q", v.Receipt)
	}
	sally.mu.Lock()
	if sally.announced[0]["sheets"] != float64(3) || sally.announced[0]["sides"] != float64(3) {
		t.Fatalf("announced %v", sally.announced)
	}
	sally.mu.Unlock()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if !strings.Contains(sc.body, "<scan:Duplex>false</scan:Duplex>") {
		t.Fatalf("a simplex scanner was asked for duplex: %s", sc.body)
	}
}

func TestAScanThatStopsIsCancelledAndCalledPartial(t *testing.T) {
	sc := &fakeScanner{loaded: true, pages: 10, failAt: 4}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	sally := newFakeSallyAll(t)
	a := pairedAgent(t, sally.srv.URL, discoverAt(scSrv.URL))
	a.Pause(0)
	a.ScanNow()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	want := "Got 2 sheets before it stopped. They are safe on this PC. Check the feeder and the output tray: put the sheets that weren't scanned back in."
	waitFor(t, "the partial receipt", func() bool { return a.Snapshot().Problem == want })
	if r := a.Snapshot().Receipt; r != "" {
		t.Fatalf("a stopped scan must not say plainly Safe: %q", r)
	}
	sc.mu.Lock()
	if len(sc.deleted) != 1 || sc.deleted[0] != "/eSCL/ScanJobs/1" {
		t.Fatalf("the job was not cancelled: %v", sc.deleted)
	}
	sc.mu.Unlock()
	// What arrived still goes up.
	waitFor(t, "the partial stack to reach Sally", func() bool {
		sally.mu.Lock()
		defer sally.mu.Unlock()
		return sally.done == 1 && sally.sides == 4
	})
}

func TestAScanThatEndsNormallyIsNotCancelled(t *testing.T) {
	sc := &fakeScanner{loaded: true, pages: 2}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	sally := newFakeSallyAll(t)
	a := pairedAgent(t, sally.srv.URL, discoverAt(scSrv.URL))
	a.Pause(0)
	a.ScanNow()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "the receipt", func() bool { return a.Snapshot().Receipt == "Got 1 sheet. Safe on this PC." })
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.deleted) != 0 || a.Snapshot().Problem != "" {
		t.Fatalf("deleted %v problem %q", sc.deleted, a.Snapshot().Problem)
	}
}

func TestHeartbeatNamesTheApproverWhenSallySaysWho(t *testing.T) {
	answer := `{"heartbeatSec":10}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	a := pairedAgent(t, srv.URL, nil)
	a.heartbeatOnce(context.Background())
	if v := a.Snapshot(); v.ApproverName != "" {
		t.Fatalf("no approver yet, got %q", v.ApproverName)
	}
	answer = `{"heartbeatSec":10,"approvedByName":"Asha Rao"}`
	a.heartbeatOnce(context.Background())
	v := a.Snapshot()
	if v.ApproverName != "Asha Rao" || !strings.HasSuffix(v.SignedCopiesURL, "/invoices/acknowledgments") || !strings.HasPrefix(v.SignedCopiesURL, srv.URL) {
		t.Fatalf("%+v", v)
	}
	// An answer without the field keeps what Sally said before.
	answer = `{"heartbeatSec":10}`
	a.heartbeatOnce(context.Background())
	if a.Snapshot().ApproverName != "Asha Rao" {
		t.Fatal("the approver should be remembered")
	}
}
