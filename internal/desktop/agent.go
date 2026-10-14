// Package desktop is the scanning half of Sally Desktop: it watches the
// scanner, starts scans by itself, keeps every page safe in the outbox, sends
// them to Sally, and reports on the heartbeat.
//
// Nothing here is reachable from a web page. Scans start from the scanner's
// own feeder (auto-start), from commands that arrive on the server heartbeat,
// or from the agent's own status page.
package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/autoscan"
	"github.com/sallyerp/sally-print-agent/internal/escl"
	"github.com/sallyerp/sally-print-agent/internal/outbox"
	"github.com/sallyerp/sally-print-agent/internal/sally"
	"github.com/sallyerp/sally-print-agent/internal/secure"
	"github.com/sallyerp/sally-print-agent/internal/sound"
	"github.com/sallyerp/sally-print-agent/internal/watchfolder"
)

// Options configure the agent.
type Options struct {
	// Dir is the agent's per-user config directory.
	Dir     string
	BaseURL string
	Version string
	Logf    func(format string, args ...any)
	// OpenBrowser opens the pairing page.
	OpenBrowser func(url string) error
	// Discover finds a scanner (tests replace it).
	Discover Discoverer
	// PollEvery is the scanner status poll (1 s).
	PollEvery time.Duration
	// Now is the clock (tests replace it).
	Now func() time.Time
	// Scanning is false when another copy of the agent drives the scanner:
	// this copy then neither watches the scanner nor sends the outbox.
	Scanning bool
}

// Agent is the scanning side of Sally Desktop.
type Agent struct {
	opt    Options
	client *sally.Client
	tokens secure.TokenStore
	store  *outbox.Store
	up     *outbox.Uploader
	folder *watchfolder.Watcher

	statePath string
	pcName    string

	mu       sync.Mutex
	local    local
	machine  *autoscan.Machine
	scanner  scannerView
	pairing  *PairingView
	paired   bool
	needs    bool   // show "Connect to Sally"
	denied   string // a 403 from Sally, shown until a heartbeat succeeds
	offline  string // the last network failure talking to Sally
	problem  string // the last scanner problem (jam…)
	jamOpen  bool   // the problem is a jam the scanner has not cleared yet
	receipt  string
	receiptT time.Time
	hbEvery  time.Duration
	lastHB   time.Time

	hbKick   chan struct{}
	scanKick chan struct{}
	ctx      context.Context
}

type scannerView struct {
	Kind      string // USB | NETWORK | NONE
	Name      string
	State     string // IDLE | PROCESSING | STOPPED | JAMMED | OFFLINE | UNKNOWN
	AdfLoaded bool
	Scanning  bool
	Sides     int // sides received in the running job
}

// PairingView is a pairing in progress.
type PairingView struct {
	UserCode string
	URL      string
	Err      string
	Waiting  bool
}

// New prepares the agent: it loads the local state, the token and the
// outbox. Nothing runs until Run.
func New(opt Options) (*Agent, error) {
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Discover == nil {
		opt.Discover = Discover
	}
	if opt.PollEvery <= 0 {
		opt.PollEvery = time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, err
	}
	a := &Agent{
		opt:       opt,
		client:    sally.NewClient(opt.BaseURL, "sally-desktop/"+opt.Version+" ("+runtime.GOOS+")"),
		tokens:    secure.TokenStore{Path: filepath.Join(opt.Dir, "scan-token.dat")},
		statePath: filepath.Join(opt.Dir, "scan.json"),
		machine:   autoscan.New(),
		scanner:   scannerView{Kind: "NONE", State: "UNKNOWN"},
		hbEvery:   10 * time.Second,
		hbKick:    make(chan struct{}, 1),
		scanKick:  make(chan struct{}, 1),
	}
	a.pcName, _ = os.Hostname()
	if a.pcName == "" {
		a.pcName = "This PC"
	}
	l, err := loadLocal(a.statePath)
	if err != nil {
		return nil, err
	}
	a.local = l
	sound.SetEnabled(!l.SoundsOff)

	store, err := outbox.Open(filepath.Join(opt.Dir, "outbox"), outbox.OSSealer{})
	if err != nil {
		return nil, fmt.Errorf("opening the outbox: %w", err)
	}
	store.Now = opt.Now
	store.Keep = func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return !a.local.KeepOff
	}
	a.store = store
	a.up = &outbox.Uploader{
		Store: store,
		API:   a.client,
		Ready: a.client.Paired,
		OnError: func(err error) {
			a.noteSallyError("sending pages", err)
		},
		OnSent: func(stack string) {
			opt.Logf("stack %s is with Sally", stack)
			a.kickHeartbeat()
		},
		OnRefused: func(stack, reason string, err error) {
			opt.Logf("stack %s: Sally refused it (%v); its pages stay in the outbox", stack, err)
			a.kickHeartbeat()
		},
	}

	folder, err := watchfolder.New(watchfolder.Options{
		Folder: func() string {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.local.WatchedFolder
		},
		Journal: filepath.Join(opt.Dir, "watchfolder.json"),
		Store:   store,
		Now:     opt.Now,
		Logf:    opt.Logf,
		OnTaken: func() {
			a.up.Kick()
			a.kickHeartbeat()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("opening the watched folder's journal: %w", err)
	}
	a.folder = folder

	token, err := a.tokens.Get()
	switch {
	case err == nil && l.CompanyID != "":
		a.client.SetAuth(token, l.CompanyID)
		a.paired = true
		if err := store.SetOwner(l.CompanyID, l.DeviceID); err != nil {
			opt.Logf("stamping waiting stacks with the connection failed: %v", err)
		}
	case err != nil && !errors.Is(err, secure.ErrNoToken):
		opt.Logf("could not read the Sally token: %v", err)
		a.needs = true
	default:
		a.needs = true
	}
	return a, nil
}

// Run runs the agent until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	// A second copy of the agent (printing on the next port) leaves the
	// scanner, the outbox and the heartbeat to the first.
	if !a.opt.Scanning {
		return
	}
	run(a.heartbeatLoop)
	run(a.up.Run)
	run(a.scannerLoop)
	run(a.janitorLoop)
	run(func(ctx context.Context) { a.folder.Run(ctx, watchfolder.DefaultPollEvery) })
	wg.Wait()
}

func (a *Agent) logf(format string, args ...any) { a.opt.Logf(format, args...) }

func (a *Agent) saveLocked() {
	if err := saveLocal(a.statePath, a.local); err != nil {
		a.logf("saving scan settings failed: %v", err)
	}
}

func (a *Agent) kickHeartbeat() {
	select {
	case a.hbKick <- struct{}{}:
	default:
	}
}

func (a *Agent) kickScanner() {
	select {
	case a.scanKick <- struct{}{}:
	default:
	}
}

// ── Controls (status page) ────────────────────────────────────────────────

// Pause stops auto-start for minutes (15, 60) or until resumed (0).
func (a *Agent) Pause(minutes int) {
	a.mu.Lock()
	a.local.pause(a.opt.Now(), minutes)
	a.saveLocked()
	a.mu.Unlock()
	a.logf("scanning paused (%d min; 0 = until resumed)", minutes)
	a.kickHeartbeat()
}

// Resume ends a pause.
func (a *Agent) Resume() {
	a.mu.Lock()
	a.local.resume()
	a.saveLocked()
	a.mu.Unlock()
	a.logf("scanning resumed")
	a.kickHeartbeat()
}

// ScanNow scans once as soon as paper is in an idle feeder.
func (a *Agent) ScanNow() {
	a.mu.Lock()
	a.machine.Request(a.opt.Now(), autoscan.ScanNow)
	a.mu.Unlock()
}

// SetSounds switches sounds on or off on this PC.
func (a *Agent) SetSounds(on bool) {
	a.mu.Lock()
	a.local.SoundsOff = !on
	a.saveLocked()
	a.mu.Unlock()
	sound.SetEnabled(on)
}

// SetKeepCopies switches "keep a copy for 7 days" on or off.
func (a *Agent) SetKeepCopies(on bool) {
	a.mu.Lock()
	a.local.KeepOff = !on
	a.saveLocked()
	a.mu.Unlock()
	if !on {
		a.store.Clean()
	}
}

// SetScannerAddress sets (or with "" clears) a network scanner's address.
func (a *Agent) SetScannerAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr != "" {
		if _, err := NormaliseAddress(addr); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.local.ScannerAddress = addr
	a.saveLocked()
	a.mu.Unlock()
	a.kickScanner()
	return nil
}

// SetWatchedFolder chooses (or with "" stops watching) the folder whose
// files are sent to Sally by themselves. It must be an existing folder,
// given in full, and not the agent's own.
func (a *Agent) SetWatchedFolder(path string) error {
	path = strings.TrimSpace(path)
	if path != "" {
		if !filepath.IsAbs(path) {
			return errors.New("type the folder's full path, e.g. C:\\Users\\Asha\\Documents\\Scans")
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return errors.New("that folder was not found on this PC")
		}
		own := filepath.Clean(a.opt.Dir)
		if path == own || strings.HasPrefix(path, own+string(filepath.Separator)) || strings.HasPrefix(own, path+string(filepath.Separator)) {
			return errors.New("choose a folder outside Sally Desktop's own folder")
		}
		if strings.EqualFold(filepath.Base(path), watchfolder.SentFolder) {
			return errors.New("choose the folder the scans are saved in, not its Sent to Sally folder")
		}
	}
	a.mu.Lock()
	a.local.WatchedFolder = path
	a.saveLocked()
	a.mu.Unlock()
	if path == "" {
		a.logf("stopped watching a folder")
	} else {
		a.logf("watching the folder %s", path)
	}
	a.kickHeartbeat()
	return nil
}

// Connect starts pairing with Sally, unless a pairing is already waiting.
func (a *Agent) Connect() {
	if !a.opt.Scanning {
		return
	}
	a.mu.Lock()
	if a.pairing != nil && a.pairing.Waiting {
		a.mu.Unlock()
		return
	}
	a.pairing = &PairingView{Waiting: true}
	ctx := a.ctx
	a.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go a.pair(ctx)
}

func platform() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "mac"
	default:
		return "linux"
	}
}

func (a *Agent) pair(ctx context.Context) {
	req := sally.PairStartRequest{DeviceName: a.pcName, Platform: platform(), AgentVersion: a.opt.Version}
	p, err := a.client.Pair(ctx, req, func(s *sally.PairStartResponse) {
		a.mu.Lock()
		a.pairing = &PairingView{UserCode: s.UserCode, URL: s.VerificationURIComplete, Waiting: true}
		a.mu.Unlock()
		if a.opt.OpenBrowser != nil && s.VerificationURIComplete != "" {
			if err := a.opt.OpenBrowser(s.VerificationURIComplete); err != nil {
				a.logf("could not open the browser: %v", err)
			}
		}
	})
	if err != nil {
		a.logf("connecting to Sally did not finish: %v", err)
		a.mu.Lock()
		if a.pairing == nil {
			a.pairing = &PairingView{}
		}
		a.pairing.Waiting = false
		a.pairing.Err = friendlyPairError(err)
		a.mu.Unlock()
		return
	}
	if err := a.tokens.Set(p.Token); err != nil {
		a.logf("saving the Sally token failed: %v", err)
		a.mu.Lock()
		a.pairing = &PairingView{Err: "Connected, but this PC could not save the connection. Try again."}
		a.mu.Unlock()
		return
	}
	a.mu.Lock()
	a.local.CompanyID, a.local.CompanyName, a.local.DeviceID = p.CompanyID, p.CompanyName, p.DeviceID
	a.local.ApproverName = p.ApprovedBy
	a.saveLocked()
	if err := a.store.SetOwner(p.CompanyID, p.DeviceID); err != nil {
		a.logf("stamping waiting stacks with the connection failed: %v", err)
	}
	a.client.SetAuth(p.Token, p.CompanyID)
	a.paired, a.needs, a.denied, a.pairing = true, false, "", nil
	a.mu.Unlock()
	a.logf("connected to Sally for %s", p.CompanyName)
	a.kickHeartbeat()
	a.up.Kick()
}

func friendlyPairError(err error) string {
	var pe *sally.PairError
	if errors.As(err, &pe) {
		switch pe.Status {
		case "denied":
			return "The connection was refused in Sally."
		case "expired", "not_found", "consumed":
			return "The code expired. Press Connect to Sally again."
		}
	}
	return "Could not reach Sally. Check the internet and press Connect to Sally again."
}

// dropToken forgets a token Sally no longer accepts (401).
func (a *Agent) dropToken() {
	_ = a.tokens.Delete()
	a.client.SetAuth("", "")
	a.mu.Lock()
	a.paired, a.needs = false, true
	a.local.CompanyID, a.local.DeviceID, a.local.ApproverName = "", "", ""
	a.saveLocked()
	_ = a.store.SetOwner("", "")
	a.mu.Unlock()
	a.logf("Sally no longer accepts this PC's connection; pages stay in the outbox until it is connected again")
}

// noteSallyError records a failed call to Sally.
func (a *Agent) noteSallyError(what string, err error) {
	switch {
	case sally.IsUnauthorized(err):
		a.dropToken()
	case sally.IsForbidden(err):
		a.mu.Lock()
		a.denied = deniedText(err)
		a.mu.Unlock()
	default:
		a.mu.Lock()
		a.offline = "Could not reach Sally while " + what + "."
		a.mu.Unlock()
	}
}

func deniedText(err error) string {
	var ae *sally.APIError
	code := ""
	if errors.As(err, &ae) {
		code = ae.Code
	}
	switch code {
	case "PLAN":
		return "Your Sally plan does not include Signed copies. Pages stay safe on this PC."
	case "OWNER_LOST_ACCESS":
		return "The person who connected this PC can no longer file signed copies. Connect it again from an account that can."
	case "COMPANY_NOT_APPROVED":
		return "This PC is not approved for that company any more."
	case "NOT_SCAN_DEVICE":
		return "This connection is not a scanner connection. Connect to Sally again."
	}
	return "Sally refused this PC. Pages stay safe on this PC."
}

// ── Heartbeat ─────────────────────────────────────────────────────────────

func (a *Agent) heartbeatLoop(ctx context.Context) {
	for {
		if a.client.Paired() {
			a.heartbeatOnce(ctx)
		}
		a.mu.Lock()
		every := a.hbEvery
		a.mu.Unlock()
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.hbKick:
			t.Stop()
		case <-t.C:
		}
	}
}

// heartbeatOnce sends one heartbeat and applies the answer.
func (a *Agent) heartbeatOnce(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	resp, err := a.client.Heartbeat(cctx, a.report())
	if err != nil {
		if ctx.Err() == nil {
			a.noteSallyError("reporting status", err)
		}
		return
	}
	a.apply(resp)
}

// report builds the heartbeat body. Counts only.
func (a *Agent) report() sally.HeartbeatRequest {
	c := a.store.Counts()
	fs := a.folder.Status()
	a.mu.Lock()
	defer a.mu.Unlock()
	paused, until := a.local.paused(a.opt.Now())
	req := sally.HeartbeatRequest{
		AgentVersion: a.opt.Version,
		Pause:        &sally.Pause{Paused: paused, Until: until},
		Outbox: &sally.Outbox{
			StacksWaiting: c.StacksWaiting,
			SidesWaiting:  c.SidesWaiting,
			BytesWaiting:  c.BytesWaiting,
		},
	}
	req.Scanner = &sally.Scanner{
		Kind: a.scanner.Kind, Name: a.scanner.Name, State: a.scanner.State,
		AdfLoaded: a.scanner.AdfLoaded, Scanning: a.scanner.Scanning,
	}
	if fs.Folder != "" {
		req.WatchedFolder = &sally.WatchedFolder{
			// The folder's own name only: the full path stays on this PC.
			Name:         short(filepath.Base(fs.Folder)),
			FilesWaiting: fs.Waiting + c.FolderFilesWaiting,
			SentToday:    fs.SentToday,
			LastError:    short(fs.LastError),
		}
	}
	if c.Last != nil {
		req.Outbox.LastStack = &sally.LastStack{
			Stack: c.Last.Stack, Sheets: c.Last.Sheets, Sides: c.Last.Sides, At: c.Last.At, State: c.Last.State,
		}
	}
	var errs []string
	if a.problem != "" {
		errs = append(errs, a.problem)
	}
	if len(c.Refused) > 0 {
		errs = append(errs, fmt.Sprintf("Sally refused %d %s, kept on this PC: %s",
			len(c.Refused), plural(len(c.Refused), "stack", "stacks"), c.Refused[0].Refused))
	}
	if len(errs) > 0 {
		req.Error = short(strings.Join(errs, "; "))
	}
	return req
}

func short(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// apply takes settings and commands from a heartbeat answer.
func (a *Agent) apply(r *sally.HeartbeatResponse) {
	now := a.opt.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.denied, a.offline = "", ""
	a.lastHB = now
	if r.HeartbeatSec >= 5 && r.HeartbeatSec <= 300 {
		a.hbEvery = time.Duration(r.HeartbeatSec) * time.Second
	}
	changed := false
	if r.CompanyName != "" && r.CompanyName != a.local.CompanyName {
		a.local.CompanyName = r.CompanyName
		changed = true
	}
	if n := strings.TrimSpace(r.ApprovedByName); n != "" && n != a.local.ApproverName {
		a.local.ApproverName = short(n)
		changed = true
	}
	if s := r.Settings; s != nil {
		if s.AutoStart != nil && (a.local.AutoStart == nil || *a.local.AutoStart != *s.AutoStart) {
			v := *s.AutoStart
			a.local.AutoStart = &v
			changed = true
		}
		if s.StartDelaySec != 0 && s.StartDelaySec != a.local.StartDelaySec {
			a.local.StartDelaySec = s.StartDelaySec
			changed = true
		}
	}
	for _, c := range r.Commands {
		switch c.Kind {
		case "SCAN_NOW":
			a.machine.Request(now, autoscan.ScanNow)
			a.logf("Sally asked for a scan now (%s)", c.ID)
		case "TEST_SCAN":
			a.machine.Request(now, autoscan.TestScan)
			a.logf("Sally asked for a test scan (%s)", c.ID)
		case "PAUSE":
			minutes := 0
			if c.PauseMinutes != nil {
				minutes = *c.PauseMinutes
			}
			a.local.pause(now, minutes)
			changed = true
			a.logf("Sally paused scanning (%d min; 0 = until resumed)", minutes)
		case "RESUME":
			a.local.resume()
			changed = true
			a.logf("Sally resumed scanning")
		default:
			// Unknown kinds come from a newer Sally; ignore them.
		}
	}
	if changed {
		a.saveLocked()
	}
}

// ── Janitor ───────────────────────────────────────────────────────────────

func (a *Agent) janitorLoop(ctx context.Context) {
	for {
		a.store.Clean()
		t := time.NewTimer(time.Hour)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// ── Status for the page ───────────────────────────────────────────────────

// View is the scanner card on the status page. Counts only, never content.
type View struct {
	Scanning     bool // this copy drives the scanner
	Paired       bool
	NeedsConnect bool
	CompanyName  string
	// ApproverName is who approved this PC (empty when Sally has not
	// said); PCName is this PC's name as Sally knows it.
	ApproverName string
	PCName       string
	// SignedCopiesURL is Sally's Signed copies page, opened in the browser.
	SignedCopiesURL string
	Denied          string
	Offline         string
	Pairing         *PairingView

	ScannerKind  string
	ScannerName  string
	ScannerState string
	AdfLoaded    bool
	ScanRunning  bool
	ScanSides    int

	Paused          bool
	PausedUntil     *time.Time
	HeldWhilePaused bool
	AutoStart       bool
	StartDelaySec   int
	Pending         string // a SCAN_NOW / TEST_SCAN waiting for paper

	Receipt   string
	ReceiptAt time.Time
	Problem   string

	StacksWaiting int
	SidesWaiting  int
	SendingTotal  int
	SendingSent   int
	TodayStacks   int
	TodaySheets   int
	Recent        []outbox.LastStack
	// Refused stacks: Sally will not take them; their pages stay here.
	Refused []outbox.LastStack
	// Held: stacks scanned for another company or device, kept here.
	Held int

	SoundsOn       bool
	KeepCopies     bool
	ScannerAddress string
	Encrypted      bool
	OutboxDir      string

	// The watched folder: its full path ("" when none is chosen), files
	// waiting (in the folder, settling, or on this PC not yet with Sally),
	// files moved to Sent to Sally today, and the last problem.
	WatchedFolder   string
	FolderWaiting   int
	FolderSentToday int
	FolderError     string
	FolderErrorAt   time.Time
}

// Snapshot returns the current view.
func (a *Agent) Snapshot() View {
	c := a.store.Counts()
	fs := a.folder.Status()
	now := a.opt.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	paused, until := a.local.paused(now)
	v := View{
		Scanning:     a.opt.Scanning,
		Paired:       a.paired,
		NeedsConnect: a.needs,
		CompanyName:  a.local.CompanyName,
		ApproverName: a.local.ApproverName,
		PCName:       a.pcName,

		SignedCopiesURL: a.client.BaseURL() + "/invoices/acknowledgments",
		Denied:          a.denied,
		Offline:         a.offline,
		ScannerKind:     a.scanner.Kind,
		ScannerName:     a.scanner.Name,
		ScannerState:    a.scanner.State,
		AdfLoaded:       a.scanner.AdfLoaded,
		ScanRunning:     a.scanner.Scanning,
		ScanSides:       a.scanner.Sides,

		Paused:          paused,
		PausedUntil:     until,
		HeldWhilePaused: a.machine.HeldWhilePaused(),
		AutoStart:       a.local.autoStart(),
		StartDelaySec:   int(a.local.delay() / time.Second),
		Pending:         string(a.machine.Pending(now)),

		Receipt:   a.receipt,
		ReceiptAt: a.receiptT,
		Problem:   a.problem,

		StacksWaiting: c.StacksWaiting,
		SidesWaiting:  c.SidesWaiting,
		SendingTotal:  c.SendingTotal,
		SendingSent:   c.SendingSent,
		TodayStacks:   c.TodayStacks,
		TodaySheets:   c.TodaySheets,
		Recent:        c.Recent,
		Refused:       c.Refused,
		Held:          c.Held,

		SoundsOn:       !a.local.SoundsOff,
		KeepCopies:     !a.local.KeepOff,
		ScannerAddress: a.local.ScannerAddress,
		Encrypted:      secure.Encrypts,
		OutboxDir:      a.store.Dir(),

		WatchedFolder:   fs.Folder,
		FolderWaiting:   fs.Waiting + c.FolderFilesWaiting,
		FolderSentToday: fs.SentToday,
		FolderError:     fs.LastError,
		FolderErrorAt:   fs.ErrorAt,
	}
	if a.pairing != nil {
		p := *a.pairing
		v.Pairing = &p
	}
	return v
}

// ── Scanner ───────────────────────────────────────────────────────────────

func (a *Agent) scannerLoop(ctx context.Context) {
	for ctx.Err() == nil {
		a.mu.Lock()
		addr := a.local.ScannerAddress
		a.mu.Unlock()
		sc, err := a.opt.Discover(ctx, addr, a.logf)
		if err != nil {
			a.logf("looking for a scanner failed: %v", err)
		}
		if sc == nil {
			a.setScanner(scannerView{Kind: "NONE", State: "OFFLINE"})
			if !a.sleep(ctx, 20*time.Second) {
				return
			}
			continue
		}
		a.logf("found %s scanner %s at %s (eSCL %s, %s)", strings.ToLower(sc.Kind), sc.Name, sc.Where, sc.Client.Version,
			map[bool]string{true: "both sides", false: "one side"}[sc.Client.Duplex])
		a.setScanner(scannerView{Kind: sc.Kind, Name: sc.Name, State: "UNKNOWN"})
		a.watch(ctx, sc)
		if sc.Close != nil {
			sc.Close()
		}
	}
}

// sleep waits d, or less if the scanner address changed. False when ctx ends.
func (a *Agent) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-a.scanKick:
		return true
	case <-t.C:
		return true
	}
}

func (a *Agent) setScanner(v scannerView) {
	a.mu.Lock()
	a.scanner = v
	a.mu.Unlock()
}

// stateOf maps eSCL status to the contract's scanner state.
func stateOf(st *escl.Status) string {
	switch {
	case st.Jammed() || st.DoorOpen():
		return "JAMMED"
	case st.State == "Idle":
		return "IDLE"
	case st.State == "Processing" || st.State == "Testing":
		return "PROCESSING"
	case st.State == "Stopped" || st.State == "Down":
		return "STOPPED"
	}
	return "UNKNOWN"
}

// watch polls the scanner about once a second and starts scans. It returns
// when the scanner stops answering or its address changed.
func (a *Agent) watch(ctx context.Context, sc *Scanner) {
	fails := 0
	for ctx.Err() == nil {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		st, err := sc.Client.Status(cctx)
		cancel()
		now := a.opt.Now()
		obs := autoscan.Observation{}
		a.mu.Lock()
		if err != nil {
			fails++
			a.scanner.State = "OFFLINE"
		} else {
			fails = 0
			obs = autoscan.Observation{Reachable: true, Idle: st.Idle(), Loaded: st.Loaded()}
			a.scanner.State = stateOf(st)
			a.scanner.AdfLoaded = st.Loaded()
			if a.jamOpen && !st.Jammed() && !st.DoorOpen() {
				// The note closes by itself when the scanner reports it fixed.
				a.jamOpen = false
				a.problem = ""
			}
		}
		paused, _ := a.local.paused(now)
		set := autoscan.Settings{AutoStart: a.local.autoStart(), Delay: a.local.delay()}
		kind := a.machine.Observe(now, obs, set, paused)
		if kind != autoscan.None {
			a.machine.Started()
		}
		a.mu.Unlock()

		if err != nil && fails >= 5 {
			a.logf("the scanner stopped answering: %v", err)
			return
		}
		if kind != autoscan.None {
			jammed := a.runJob(ctx, sc, kind)
			a.mu.Lock()
			a.machine.Ended()
			if jammed {
				// The job's own last status showed the jam: that counts as
				// "something other than idle with paper", even if the person
				// clears it before the next poll.
				paused, _ := a.local.paused(a.opt.Now())
				a.machine.Observe(a.opt.Now(), autoscan.Observation{Reachable: true, Idle: true}, set, paused)
			}
			a.mu.Unlock()
		}
		t := time.NewTimer(a.opt.PollEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.scanKick:
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// runJob scans one feeder load into one stack (more if a load passes 1000
// sides, or 500 sheets one-sided). Every side goes to disk as it arrives. It reports whether the job
// ended in a jam.
func (a *Agent) runJob(ctx context.Context, sc *Scanner, kind autoscan.Kind) bool {
	a.logf("scan starting (%s)", kind)
	sound.Play(sound.Tick)
	a.mu.Lock()
	a.scanner.Scanning, a.scanner.Sides = true, 0
	a.problem, a.jamOpen = "", false
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.scanner.Scanning = false
		a.mu.Unlock()
		a.up.Kick()
		a.kickHeartbeat()
	}()

	duplex := sc.Client.Duplex
	job, err := sc.Client.StartJob(ctx, escl.ScanSettings(sc.Client.Version, duplex))
	if err != nil {
		a.fail(fmt.Sprintf("The scanner did not start: %v", err), false)
		return false
	}

	var w *outbox.StackWriter
	problem := ""
	// stopped: the job ended other than by the scanner's own "no more
	// pages" (an error, a stall, the agent quitting). The scanner may still
	// be feeding paper, so the job is cancelled, and the receipt says the
	// stack is partial.
	stopped := false
	cancelled := false
	cancelJob := func() {
		if cancelled {
			return
		}
		cancelled = true
		// ctx may be over (the agent is quitting); the scanner must still
		// be told.
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		status, err := sc.Client.CancelJob(cctx, job)
		if err != nil {
			a.logf("scan job %s: the cancel was not answered: %v", job, err)
		} else {
			a.logf("scan job %s cancelled (DELETE answered %d)", job, status)
		}
	}
	jam := false
	var notReadySince time.Time
	total := 0
	for {
		if ctx.Err() != nil {
			problem, stopped = "Sally Desktop stopped during the scan.", true
			break
		}
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		page, done, err := sc.Client.NextDocument(cctx, job)
		cancel()
		if errors.Is(err, escl.ErrNotReady) {
			if notReadySince.IsZero() {
				notReadySince = time.Now()
			}
			if time.Since(notReadySince) > 2*time.Minute {
				problem, stopped = "The scanner stopped sending pages.", true
				break
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		notReadySince = time.Time{}
		if err != nil {
			problem, stopped = fmt.Sprintf("The scan stopped: %v", err), true
			break
		}
		if done {
			break
		}
		if w != nil && w.Full() {
			a.finish(w, "", false)
			w = nil
		}
		if w == nil {
			if w, err = a.store.NewStack(duplex); err != nil {
				problem = fmt.Sprintf("Could not save pages on this PC: %v", err)
				cancelJob()
				break
			}
		}
		if err := w.Add(page); err != nil {
			problem = fmt.Sprintf("Could not save a page on this PC: %v", err)
			cancelJob()
			break
		}
		total++
		a.mu.Lock()
		a.scanner.Sides = total
		a.mu.Unlock()
	}
	if stopped {
		a.logf("scan stopped early: %s", problem)
		cancelJob()
	}

	// A jam usually ends the job early, sometimes as a plain "no more
	// pages". Ask the scanner.
	cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if st, err := sc.Client.Status(cctx); err == nil && (st.Jammed() || st.DoorOpen()) {
		jam = true
	}
	cancel()

	sheets := 0
	saved := true
	if w != nil {
		// A stopped stack gets no "Safe" receipt of its own: the problem
		// line below says what was kept and what to do.
		r, ferr := a.finish(w, problem, stopped && !jam)
		sheets = r.Sheets
		if ferr != nil && problem == "" {
			problem = "Some pages could not be saved on this PC. Scan this stack again."
		}
		if ferr != nil {
			saved = false
			if stopped {
				problem = "The scan stopped and some pages could not be saved on this PC. Scan this stack again."
			}
		}
	}
	switch {
	case jam:
		problem = fmt.Sprintf("Paper jam. Open the cover, take out the stuck sheet and put it back on top of the stack. "+
			"Sally kept the %d %s already scanned and sets aside anything scanned twice.", sheets, plural(sheets, "sheet", "sheets"))
	case stopped && saved && sheets > 0:
		problem = fmt.Sprintf("Got %d %s before it stopped. They are safe on this PC. "+
			"Check the feeder and the output tray: put the sheets that weren't scanned back in.", sheets, plural(sheets, "sheet", "sheets"))
	case stopped && saved:
		problem = "The scanner stopped before sending a page. Check the feeder and the output tray: put the sheets back in."
	}
	if problem != "" {
		a.fail(problem, jam)
	}
	a.logf("scan finished: %d sides", total)
	return jam
}

// finish closes a stack and says "safe" only if every side is on disk.
// quiet leaves the receipt to the caller (a stack the scanner cut short).
func (a *Agent) finish(w *outbox.StackWriter, problem string, quiet bool) (outbox.Receipt, error) {
	r, err := w.Finish(problem)
	if err != nil {
		a.logf("stack %s: %v", r.Stack, err)
	}
	if quiet {
		a.mu.Lock()
		a.receipt, a.receiptT = "", time.Time{}
		a.mu.Unlock()
		return r, err
	}
	if msg := r.Message(); msg != "" {
		a.mu.Lock()
		a.receipt, a.receiptT = msg, a.opt.Now()
		a.mu.Unlock()
		a.logf("stack %s: %s (%d sides)", r.Stack, msg, r.Sides)
		sound.Play(sound.Chime)
	}
	return r, err
}

// fail shows a scanner problem and plays the low tone (again after 30 s if
// a jam is still there).
func (a *Agent) fail(msg string, jam bool) {
	a.logf("scanner problem: %s", msg)
	a.mu.Lock()
	a.problem, a.jamOpen = msg, jam
	a.mu.Unlock()
	go func() {
		time.Sleep(700 * time.Millisecond) // after the chime, if there was one
		sound.Play(sound.Problem)
		if !jam {
			return
		}
		time.Sleep(30 * time.Second)
		a.mu.Lock()
		still := a.jamOpen
		a.mu.Unlock()
		if still {
			sound.Play(sound.Problem)
		}
	}()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
