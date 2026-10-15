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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sallyerp/sally-print-agent/internal/autoscan"
	"github.com/sallyerp/sally-print-agent/internal/escl"
	"github.com/sallyerp/sally-print-agent/internal/outbox"
	"github.com/sallyerp/sally-print-agent/internal/sally"
	"github.com/sallyerp/sally-print-agent/internal/secure"
	"github.com/sallyerp/sally-print-agent/internal/sound"
	"github.com/sallyerp/sally-print-agent/internal/usbscan"
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
	// Discover finds a scanner automatically (tests replace it).
	Discover Discoverer
	// Look lists every scanner, OpenFound opens one of them, and
	// InventoryEvery is how often the list is refreshed (60 s). Tests
	// replace them.
	Look           Looker
	OpenFound      Opener
	InventoryEvery time.Duration
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

	// The running pile: jobSeq counts piles, job is nil when idle, and
	// jobWaiters are the Sally commands it answers.
	jobSeq     uint64
	job        *sally.ScannerJob
	jobWaiters []string
	// A Stop for pile stopFor (0 = none): when it was asked, from where
	// (stopSally or stopPC), by whom, and the STOP commands it answers.
	stopIDs  []string
	stopFor  uint64
	stopAt   time.Time
	stopWall time.Time
	stopFrom string
	stopBy   string
	// stopWait is how long a duplex pile stopped after a front waits for
	// its back (10 s).
	stopWait time.Duration
	// stopped is the Stop words shown after a pile was stopped, with when
	// and by whom (stoppedFrom says whether from Sally).
	stopped     string
	stoppedAt   time.Time
	stoppedBy   string
	stoppedFrom string

	// lastObs is the latest scanner poll; lastJam says it showed a jam or
	// an open door.
	lastObs autoscan.Observation
	lastJam bool
	// scannerOpen: a scanner is open and watched.
	scannerOpen bool
	// inUse is the open scanner as a list entry, and openSkip what the
	// inventory must leave alone while it is open.
	inUse    *Found
	openSkip Skip

	// The scanner list, refreshed by inventoryLoop: invPass is when the
	// latest pass ended; invKick asks for a pass now, invDone says one
	// ended.
	inventory []Found
	invPass   time.Time
	invKick   chan struct{}
	invDone   chan struct{}
	probes    *ProbeCache
	// lookMu keeps two searches from opening the same scanner at once.
	lookMu sync.Mutex
	// knownSeen is when each KnownScanners entry was last seen.
	knownSeen map[string]time.Time

	// lastBeat is when the latest check-in was sent (wall clock), for the
	// one-second floor.
	lastBeat time.Time
	results  *tracker
	actions  []sally.LocalAction

	// play plays a sound (tests replace it).
	play func(sound.Sound)
}

// Where a Stop came from.
const (
	stopSally = "SALLY"
	stopPC    = "PC"
)

type scannerView struct {
	Kind      string // USB | NETWORK | NONE
	Name      string
	ID        string
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
	if opt.Look == nil {
		opt.Look = Look
	}
	if opt.OpenFound == nil {
		opt.OpenFound = OpenFound
	}
	if opt.InventoryEvery <= 0 {
		opt.InventoryEvery = time.Minute
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
		invKick:   make(chan struct{}, 1),
		invDone:   make(chan struct{}, 1),
		probes:    &ProbeCache{},
		knownSeen: map[string]time.Time{},
		results:   newTracker(),
		stopWait:  10 * time.Second,
		play:      sound.Play,
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
	run(a.inventoryLoop)
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

// Pause stops auto-start for minutes (15, 60) or until resumed (0). It
// also cancels a Scan now still waiting for paper.
func (a *Agent) Pause(minutes int) {
	a.mu.Lock()
	a.local.pause(a.opt.Now(), minutes)
	a.saveLocked()
	a.cancelWaitingLocked()
	a.mu.Unlock()
	a.logf("scanning paused (%d min; 0 = until resumed)", minutes)
	a.kickHeartbeat()
}

// cancelWaitingLocked drops a waiting Scan now and reports Sally's as
// failed: a pause cancels a scan that has not started.
func (a *Agent) cancelWaitingLocked() {
	a.machine.Cancel()
	for _, id := range a.machine.TakeCancelled() {
		a.results.record(id, resFailed, nil, nil, "", "The PC was paused before paper went in.")
	}
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

// ScanNow scans once as soon as paper is in an idle feeder, even while
// paused or held after a Stop.
func (a *Agent) ScanNow() {
	a.mu.Lock()
	a.machine.Request(a.opt.Now(), autoscan.ScanNow, "")
	a.mu.Unlock()
	a.kickHeartbeat()
}

// errPileFinished is the status page's answer to a Stop for a pile that is
// not running.
var errPileFinished = errors.New("That pile has already finished.")

// errNotOnList refuses a scanner id the PC has not found.
var errNotOnList = errors.New("That scanner is not on this PC's list.")

// StopPile stops the running pile job after the current sheet, from the
// status page. The sheets already scanned are kept and sent.
func (a *Agent) StopPile(job string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.job == nil || job == "" || job != a.job.ID {
		return errPileFinished
	}
	a.askStopLocked(stopPC, "")
	a.queueActionLocked("STOP", job, nil)
	a.logf("stop asked on this PC for pile %s", job)
	a.kickHeartbeat()
	return nil
}

// askStopLocked marks the running pile to stop. The first Stop decides
// where it came from.
func (a *Agent) askStopLocked(from, by string) {
	if a.stopFor != a.jobSeq {
		a.stopFor, a.stopAt, a.stopWall, a.stopFrom, a.stopBy = a.jobSeq, a.opt.Now(), time.Now(), from, by
	}
	a.job.Stopping = true
}

// stopAsked reports a Stop for pile seq, and how long ago it was asked.
func (a *Agent) stopAsked(seq uint64) (bool, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopFor != seq || seq == 0 {
		return false, 0
	}
	return true, time.Since(a.stopWall)
}

// SelectScanner chooses the scanner this PC uses, from the status page; ""
// means automatic. It takes effect after a running pile.
func (a *Agent) SelectScanner(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var sid *string
	if id != "" {
		sid = &id
	}
	if err := a.chooseLocked(sid, "PC"); err != nil {
		return err
	}
	a.queueActionLocked("SELECT_SCANNER", "", sid)
	a.kickHeartbeat()
	return nil
}

// chooseLocked sets the choice: nil is automatic, otherwise an sc- id on
// the list (or the current choice).
func (a *Agent) chooseLocked(id *string, by string) error {
	now := a.opt.Now().UTC()
	if id == nil {
		was := a.local.ScannerID
		a.local.ScannerID, a.local.ScannerName, a.local.ScannerVia, a.local.ScannerUnstable = "", "", nil, false
		a.local.ScannerChosenBy, a.local.ScannerChosenAt = by, &now
		a.saveLocked()
		a.logf("the scanner is picked automatically now (chosen by %s)", byWho(by))
		if was != "" {
			a.kickScanner()
		}
		return nil
	}
	if !ValidScannerID(*id) {
		return errNotOnList
	}
	name, via, unstable := "", []string(nil), false
	if f, ok := a.foundLocked(*id); ok {
		name, via, unstable = f.Name, f.Via(), !f.Stable
	} else if *id == a.local.ScannerID {
		name, via, unstable = a.local.ScannerName, a.local.ScannerVia, a.local.ScannerUnstable
	} else {
		return errNotOnList
	}
	was := a.local.ScannerID
	a.local.ScannerID, a.local.ScannerName, a.local.ScannerVia, a.local.ScannerUnstable = *id, name, via, unstable
	a.local.ScannerChosenBy, a.local.ScannerChosenAt = by, &now
	a.saveLocked()
	a.logf("scanner %s (%s) chosen by %s", name, *id, byWho(by))
	if was != *id {
		a.kickScanner()
	}
	return nil
}

func byWho(by string) string {
	if by == "PC" {
		return "this PC"
	}
	if by == "" {
		return "Sally"
	}
	return by + " in Sally"
}

// LookAgain refreshes the scanner list now.
func (a *Agent) LookAgain() {
	select {
	case a.invKick <- struct{}{}:
	default:
	}
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
		t := time.NewTimer(a.beatEvery(a.opt.Now()))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.hbKick:
			t.Stop()
		case <-t.C:
		}
		// Never two check-ins less than a second apart: a kick waits, and
		// the kicks that arrive meanwhile ride along.
		a.mu.Lock()
		wait := time.Second - time.Since(a.lastBeat)
		a.mu.Unlock()
		if wait > 0 {
			w := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				w.Stop()
				return
			case <-w.C:
			}
		}
		select {
		case <-a.hbKick:
		default:
		}
	}
}

// activeBeat is the check-in interval while a pile scans, a Scan now waits
// for paper or a Stop is pending.
const activeBeat = 5 * time.Second

// beatEvery is how long until the next check-in: min(heartbeatSec, 5 s)
// while something is happening, heartbeatSec otherwise.
func (a *Agent) beatEvery(now time.Time) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	every := a.hbEvery
	active := a.job != nil || a.machine.Pending(now) != autoscan.None || a.stopFor != 0
	if active && every > activeBeat {
		every = activeBeat
	}
	return every
}

// heartbeatOnce sends one heartbeat and applies the answer. Results and
// status-page actions it carried are dropped only after a 2xx.
func (a *Agent) heartbeatOnce(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, sent := a.report()
	a.mu.Lock()
	a.lastBeat = time.Now()
	a.mu.Unlock()
	resp, err := a.client.Heartbeat(cctx, req)
	if err != nil {
		if ctx.Err() == nil {
			a.noteSallyError("reporting status", err)
		}
		return
	}
	a.mu.Lock()
	a.results.delivered(sent)
	a.actionsDeliveredLocked(req.LocalActions)
	a.mu.Unlock()
	a.apply(resp)
}

// report builds the heartbeat body, and the seq each result in it was sent
// at. Counts only.
func (a *Agent) report() (sally.HeartbeatRequest, map[string]uint64) {
	c := a.store.Counts()
	fs := a.folder.Status()
	now := a.opt.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lapseLocked(now)
	paused, until := a.local.paused(now)
	req := sally.HeartbeatRequest{
		AgentVersion: a.opt.Version,
		Pause:        &sally.Pause{Paused: paused, Until: until},
		Outbox: &sally.Outbox{
			StacksWaiting: c.StacksWaiting,
			SidesWaiting:  c.SidesWaiting,
			BytesWaiting:  c.BytesWaiting,
		},
		Features: append([]string(nil), desktopFeatures...),
		Scanners: a.scannersLocked(),
	}
	if a.local.ScannerID != "" {
		id := a.local.ScannerID
		req.ChosenScannerID = &id
	}
	req.Scanner = &sally.Scanner{
		Kind: a.scanner.Kind, Name: cutRunes(a.scanner.Name, 120), State: a.scanner.State,
		AdfLoaded: a.scanner.AdfLoaded, Scanning: a.scanner.Scanning,
		ID: a.scanner.ID, Problem: problemForSally(a.problem), Held: a.machine.Held(),
	}
	if a.job != nil && a.scanner.Scanning {
		j := *a.job
		j.Sides = a.scanner.Sides
		req.Scanner.Job = &j
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
	results, sent := a.results.snapshot()
	if len(results) > 0 {
		req.Results = results
	}
	if len(a.actions) > 0 {
		req.LocalActions = append([]sally.LocalAction(nil), a.actions...)
	}
	return req, sent
}

// lapseLocked reports each Scan now whose 2 minutes passed without paper:
// NO_PAPER when the scanner answered idle with no jam, otherwise why not.
// It reports whether it recorded anything.
func (a *Agent) lapseLocked(now time.Time) bool {
	ids := a.machine.TakeLapsed(now)
	recorded := false
	for _, id := range ids {
		if id != "" {
			recorded = true
		}
		switch {
		case !a.scannerOpen || !a.lastObs.Reachable:
			a.results.record(id, resFailed, nil, nil, "", "The scanner is not answering.")
		case a.lastJam:
			a.results.record(id, resFailed, nil, nil, "", "Paper jam or cover open.")
		default:
			a.results.record(id, resNoPaper, nil, nil, "", "")
		}
	}
	return recorded
}

// problemForSally is the problem as Sally gets it: at most 200 runes, cut
// at the end of a sentence, so a long one (the jam words after a Stop run
// to 204-207) never reaches Sally cut mid-word.
func problemForSally(p string) string {
	cut := cutRunes(p, 200)
	if cut == cutRunes(p, 1000) {
		return cut
	}
	if i := strings.LastIndex(cut, ". "); i > 0 {
		return cut[:i+1]
	}
	return cut
}

// short cuts s to at most 200 bytes, on a rune boundary.
func short(s string) string {
	if len(s) <= 200 {
		return s
	}
	i := 200
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
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
	recorded := false
	for _, c := range r.Commands {
		if !validCommandID(c.ID) {
			a.logf("Sally sent a command with an id this PC does not take; skipped")
			continue
		}
		recorded = true
		switch c.Kind {
		case "SCAN_NOW", "TEST_SCAN":
			kind := autoscan.ScanNow
			if c.Kind == "TEST_SCAN" {
				kind = autoscan.TestScan
			}
			paused, _ := a.local.paused(now)
			switch {
			case paused:
				a.results.record(c.ID, resFailed, nil, nil, "", "This PC is paused.")
			case a.machine.HoldKind() == autoscan.HoldAfterStopOnPC:
				a.results.record(c.ID, resFailed, nil, nil, "", "Someone stopped this pile on the PC.")
			case !a.scannerOpen && a.local.ScannerID == "":
				a.results.record(c.ID, resFailed, nil, nil, "", "No scanner was found on this PC.")
			case a.job != nil:
				// It joins the running pile.
				a.jobWaiters = append(a.jobWaiters, c.ID)
				a.results.record(c.ID, resScanning, count(a.scanner.Sides), nil, "", "")
			default:
				a.machine.Request(now, kind, c.ID)
				a.results.record(c.ID, resWaitingForPaper, nil, nil, "", "")
			}
			a.logf("Sally asked for a %s (%s)", strings.ToLower(strings.ReplaceAll(c.Kind, "_", " ")), c.ID)
		case "PAUSE":
			minutes := 0
			if c.PauseMinutes != nil {
				minutes = *c.PauseMinutes
			}
			a.local.pause(now, minutes)
			changed = true
			a.cancelWaitingLocked()
			a.results.record(c.ID, resDone, nil, nil, "", "")
			a.logf("Sally paused scanning (%d min; 0 = until resumed)", minutes)
		case "RESUME":
			a.local.resume()
			changed = true
			a.results.record(c.ID, resDone, nil, nil, "", "")
			a.logf("Sally resumed scanning")
		case "STOP":
			switch {
			case c.Job == "":
				a.results.record(c.ID, resNothingToStop, nil, nil, "", "Sally did not say which pile to stop.")
			case a.job != nil && c.Job == a.job.ID:
				a.askStopLocked(stopSally, cutRunes(c.ByName, 80))
				a.stopIDs = append(a.stopIDs, c.ID)
				a.results.record(c.ID, resStopping, nil, nil, "", "")
				a.logf("Sally asked to stop pile %s (%s)", c.Job, c.ID)
			default:
				a.results.record(c.ID, resNothingToStop, nil, nil, "", "That pile had already finished.")
			}
		case "SELECT_SCANNER":
			if c.ScannerID == nil {
				a.results.record(c.ID, resFailed, nil, nil, "", "Sally did not say which scanner.")
				break
			}
			var id *string
			if string(c.ScannerID) != "null" {
				var v string
				if json.Unmarshal(c.ScannerID, &v) != nil {
					a.results.record(c.ID, resFailed, nil, nil, "", "That scanner is not on this PC's list.")
					break
				}
				id = &v
			}
			if err := a.chooseLocked(id, cutRunes(c.ByName, 80)); err != nil {
				a.results.record(c.ID, resFailed, nil, nil, "", "That scanner is not on this PC's list.")
				break
			}
			a.results.record(c.ID, resDone, nil, nil, "", "")
		default:
			// A newer Sally's kind: say so, and change nothing.
			a.results.record(c.ID, resFailed, nil, nil, "", "This version of Sally Desktop does not know that command.")
		}
	}
	if changed {
		a.saveLocked()
	}
	if recorded {
		a.kickHeartbeat()
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
	// ScannerID is the scanner in use (or the chosen one while it is not
	// answering); JobID the running pile; StopRequested says a Stop was
	// asked for it.
	ScannerID     string
	JobID         string
	StopRequested bool
	// HoldState is the hold on auto-start: WHILE_PAUSED, AFTER_STOP,
	// AFTER_STOP_ON_PC or "".
	HoldState string
	// Stopped is the Stop words after a pile was stopped, with when, by
	// whom and whether from Sally.
	Stopped          string
	StoppedAt        time.Time
	StoppedBy        string
	StoppedFromSally bool
	// PendingFromSally: the Scan now waiting for paper came from Sally;
	// PendingUntil is when it gives up.
	PendingFromSally bool
	PendingUntil     time.Time
	// The scanner choice: ChosenID ("" = automatic), its name, who chose it
	// ("PC" or a name from Sally) and when.
	ChosenID   string
	ChosenName string
	ChosenBy   string
	ChosenAt   *time.Time
	// ChosenMissing: a scanner is chosen and it is not answering.
	ChosenMissing bool
	Scanners      []ScannerRow

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

// ScannerRow is one scanner on the status page's list.
type ScannerRow struct {
	ID        string
	Name      string
	Kind      string // USB | NETWORK | USB and network
	Detail    string
	Answering bool
	Feeder    *bool
	Stable    bool
	InUse     bool
	Chosen    bool
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
	v.ScannerID = a.scanner.ID
	if a.job != nil {
		v.JobID, v.StopRequested = a.job.ID, a.job.Stopping
	}
	v.HoldState = a.machine.Held()
	v.Stopped, v.StoppedAt, v.StoppedBy, v.StoppedFromSally = a.stopped, a.stoppedAt, a.stoppedBy, a.stoppedFrom == stopSally
	for _, id := range a.machine.Waiting() {
		if id != "" {
			v.PendingFromSally = true
		}
	}
	if v.Pending != "" {
		v.PendingUntil = a.machine.PendingUntil()
	}
	v.ChosenID, v.ChosenName, v.ChosenBy = a.local.ScannerID, a.local.ScannerName, a.local.ScannerChosenBy
	if a.local.ScannerChosenAt != nil {
		t := *a.local.ScannerChosenAt
		v.ChosenAt = &t
	}
	v.ChosenMissing = a.local.ScannerID != "" && !a.scannerOpen
	inUse := ""
	if a.scannerOpen {
		inUse = a.scanner.ID
	}
	for _, f := range a.orderedLocked() {
		kind := map[string]string{"USB": "USB", "NETWORK": "network"}[f.Kind()]
		if len(f.USB) > 0 && len(f.Net) > 0 {
			kind = "USB and network"
		}
		v.Scanners = append(v.Scanners, ScannerRow{
			ID: f.ID, Name: f.Name, Kind: kind, Detail: safeDetail(f.Detail), Answering: f.Answering,
			Feeder: f.Feeder, Stable: f.Stable, InUse: f.ID == inUse, Chosen: f.ID == a.local.ScannerID,
		})
	}
	return v
}

// ── Scanner ───────────────────────────────────────────────────────────────

// scannerLoop opens a scanner and watches it, again and again. With a
// scanner chosen it opens only that one and waits for it while it does not
// answer, never falling back; otherwise it makes the automatic pick and
// stays with that scanner until it stops answering.
func (a *Agent) scannerLoop(ctx context.Context) {
	for ctx.Err() == nil {
		a.mu.Lock()
		addr := a.local.ScannerAddress
		chosen := a.local.ScannerID
		a.mu.Unlock()

		var sc *Scanner
		var err error
		if chosen == "" {
			a.lookMu.Lock()
			sc, err = a.opt.Discover(ctx, addr, a.logf)
			if sc != nil {
				a.mu.Lock()
				a.openSkip = skipOf(sc)
				a.mu.Unlock()
			}
			a.lookMu.Unlock()
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
		} else {
			sc = a.openChosen(ctx, chosen)
			if sc == nil {
				a.mu.Lock()
				kind := "NONE"
				if f, ok := a.foundLocked(chosen); ok {
					kind = f.Kind()
				} else if len(a.local.ScannerVia) > 0 {
					kind = a.local.ScannerVia[0]
				}
				a.scanner = scannerView{Kind: kind, Name: a.local.ScannerName, ID: chosen, State: "OFFLINE"}
				a.mu.Unlock()
				if !a.sleepChosen(ctx, 20*time.Second) {
					return
				}
				continue
			}
		}
		a.mu.Lock()
		if a.local.ScannerID != chosen {
			// The choice changed while it was opening. Closed first: the list
			// leaves the scanner alone until it is.
			a.mu.Unlock()
			if sc.Close != nil {
				sc.Close()
			}
			a.mu.Lock()
			a.openSkip = Skip{}
			a.mu.Unlock()
			continue
		}
		a.openedLocked(sc)
		a.mu.Unlock()
		a.logf("found %s scanner %s at %s (eSCL %s, %s, id %s)", strings.ToLower(sc.Kind), sc.Name, sc.Where, sc.Client.Version,
			map[bool]string{true: "both sides", false: "one side"}[sc.Client.Duplex], sc.ID)
		a.kickHeartbeat()
		a.watch(ctx, sc)
		// Closed first: the list leaves the scanner alone until it is.
		if sc.Close != nil {
			sc.Close()
		}
		a.mu.Lock()
		a.scannerOpen, a.inUse, a.openSkip = false, nil, Skip{}
		a.mu.Unlock()
	}
}

// openChosen opens the chosen scanner, looking for it first when it is not
// on the list. nil when it does not answer.
func (a *Agent) openChosen(ctx context.Context, chosen string) *Scanner {
	a.mu.Lock()
	f, ok := a.foundLocked(chosen)
	a.mu.Unlock()
	if !ok {
		a.inventoryPass(ctx)
		// This pass is not news to the wait below.
		select {
		case <-a.invDone:
		default:
		}
		a.mu.Lock()
		f, ok = a.foundLocked(chosen)
		a.mu.Unlock()
	}
	if !ok {
		return nil
	}
	a.lookMu.Lock()
	sc, err := a.opt.OpenFound(ctx, f, a.logf)
	if err == nil {
		a.mu.Lock()
		a.openSkip = skipOf(sc)
		a.mu.Unlock()
	}
	a.lookMu.Unlock()
	if err != nil {
		a.logf("the chosen scanner %s is not answering: %v", f.Name, err)
		return nil
	}
	return sc
}

// openedLocked records the open scanner: its view, its list entry, and
// what the list must leave alone.
func (a *Agent) openedLocked(sc *Scanner) {
	a.scanner = scannerView{Kind: sc.Kind, Name: sc.Name, ID: sc.ID, State: "UNKNOWN"}
	a.scannerOpen = true
	f, ok := a.foundLocked(sc.ID)
	if !ok {
		f = Found{ID: sc.ID, Name: sc.Name, Stable: sc.Stable, Feeder: sc.Feeder}
	}
	if sc.Kind == "USB" {
		f.USB = unionStrings([]string{sc.Where}, f.USB)
	} else {
		f.Net = unionBases([]netBase{{URL: sc.Where, Root: sc.Client.Root}}, f.Net)
	}
	a.openSkip = skipOf(sc)
	f.Answering, f.Reason = true, ""
	a.inUse = &f
	a.learnLocked(sc.learned, a.opt.Now())
	a.mergeInUseLocked(a.opt.Now())
	if a.local.ScannerID == sc.ID {
		a.local.ScannerName, a.local.ScannerVia, a.local.ScannerUnstable = sc.Name, f.Via(), !sc.Stable
		a.saveLocked()
	}
}

// skipOf is what the scanner list must leave alone while sc is open: its
// USB device, or its network base.
func skipOf(sc *Scanner) Skip {
	if sc.Kind == "USB" {
		return Skip{USBKey: usbscan.DeviceKey(sc.Where)}
	}
	return Skip{Bases: []string{sc.Where}}
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

// sleepChosen waits for a chosen scanner that is not answering: d, or
// until the choice changes or the list is refreshed.
func (a *Agent) sleepChosen(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-a.scanKick:
	case <-a.invDone:
	case <-t.C:
	}
	return true
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
// when the scanner stops answering or its address or the choice changed
// (only between piles: a running pile always finishes first).
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
			a.lastJam = false
		} else {
			fails = 0
			obs = autoscan.Observation{Reachable: true, Idle: st.Idle(), Loaded: st.Loaded(), Clear: st.FeederClear()}
			a.scanner.State = stateOf(st)
			a.scanner.AdfLoaded = st.Loaded()
			a.lastJam = st.Jammed() || st.DoorOpen()
			if a.jamOpen && !st.Jammed() && !st.DoorOpen() {
				// The note closes by itself when the scanner reports it fixed.
				a.jamOpen = false
				a.problem = ""
			}
		}
		a.lastObs = obs
		paused, _ := a.local.paused(now)
		set := autoscan.Settings{AutoStart: a.local.autoStart(), Delay: a.local.delay()}
		kind := a.machine.Observe(now, obs, set, paused)
		var seq uint64
		if kind != autoscan.None {
			a.startPileLocked(now, kind)
			seq = a.jobSeq
		}
		lapsed := a.lapseLocked(now)
		a.mu.Unlock()
		if lapsed {
			a.kickHeartbeat()
		}

		if err != nil && fails >= 5 {
			a.logf("the scanner stopped answering: %v", err)
			return
		}
		if kind != autoscan.None {
			a.kickHeartbeat()
			end := a.runJob(ctx, sc, kind, seq)
			if !end.halted {
				// A halted pile was ended, and its hold set, by runJob in the
				// same locked step that cleared the job.
				a.mu.Lock()
				a.machine.Ended()
				if end.jam {
					// The job's own last status showed the jam: that counts as
					// "something other than idle with paper", even if the
					// person clears it before the next poll.
					paused, _ := a.local.paused(a.opt.Now())
					a.machine.Observe(a.opt.Now(), autoscan.Observation{Reachable: true, Idle: true}, set, paused)
				}
				a.mu.Unlock()
			}
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

// startPileLocked begins a pile: a new job id, and the Sally requests that
// fired on it.
func (a *Agent) startPileLocked(now time.Time, kind autoscan.Kind) {
	a.machine.Started()
	a.jobSeq++
	a.job = &sally.ScannerJob{ID: newJobID(now), Kind: string(kind), StartedAt: now.UTC()}
	a.jobWaiters = nil
	for _, id := range a.machine.TakeFired() {
		if id != "" {
			a.jobWaiters = append(a.jobWaiters, id)
			a.results.record(id, resScanning, count(0), nil, "", "")
		}
	}
	a.stopped, a.stoppedAt, a.stoppedBy, a.stoppedFrom = "", time.Time{}, "", ""
}

// jobEnd is how a pile ended.
type jobEnd struct {
	// halted: stopped by a Stop. jam: the scanner reported a jam.
	// startFailed: the job never began. early: it ended early otherwise
	// (an error, a stall, the agent quitting). saveFailed: a page could
	// not be kept on this PC.
	halted, jam, startFailed, early, saveFailed bool
	// sides and sheets are what is kept on the PC (whole sheets only);
	// stack is the pile's first stack.
	sides, sheets int
	stack         string
	// from is where the Stop came from (stopSally or stopPC).
	from string
}

// stopWords is what the status page says after a pile was stopped.
func stopWords(sheets int) string {
	switch {
	case sheets == 0:
		return "Stopped before a whole sheet was scanned. Put every sheet back on the pile, then press Scan now to scan it, or take the pile out."
	case sheets == 1:
		return "Stopped after 1 sheet. It is safe on this PC. Put every sheet after it back on the pile; if you are not sure, put back a few more: Sally sets aside any sheet it already has. Then press Scan now to scan the rest, or take the pile out."
	}
	return fmt.Sprintf("Stopped after %d sheets. They are safe on this PC. Put every sheet after them back on the pile; if you are not sure, put back a few more: Sally sets aside any sheet it already has. Then press Scan now to scan the rest, or take the pile out.", sheets)
}

// runJob scans one feeder load into one stack (more if a load passes 1000
// sides, or 500 sheets one-sided). Every side goes to disk as it arrives.
// Before every NextDocument it checks for a Stop of pile seq; a duplex pile
// stopped after a front waits up to stopWait for the back. It reports how
// the pile ended, and records the results of the commands it answers.
func (a *Agent) runJob(ctx context.Context, sc *Scanner, kind autoscan.Kind, seq uint64) (end jobEnd) {
	a.logf("scan starting (%s)", kind)
	a.play(sound.Tick)
	a.mu.Lock()
	a.scanner.Scanning, a.scanner.Sides = true, 0
	a.problem, a.jamOpen = "", false
	a.mu.Unlock()
	a.kickHeartbeat()
	defer func() {
		a.mu.Lock()
		a.scanner.Scanning = false
		a.job = nil
		if a.stopFor == seq {
			end.from = a.stopFrom
		}
		a.recordPileEndLocked(end)
		a.jobWaiters, a.stopIDs, a.stopFor, a.stopFrom, a.stopBy = nil, nil, 0, "", ""
		if end.halted {
			// The rest of the pile is likely still in the feeder: it waits
			// until the feeder has been cleared. Set here, so no check-in or
			// command sees the pile over without its hold.
			a.machine.Ended()
			h := autoscan.HoldAfterStop
			if end.from == stopPC {
				h = autoscan.HoldAfterStopOnPC
			}
			a.machine.HoldUntilClear(h)
		}
		a.mu.Unlock()
		a.up.Kick()
		a.kickHeartbeat()
	}()

	duplex := sc.Client.Duplex
	job, err := sc.Client.StartJob(ctx, escl.ScanSettings(sc.Client.Version, duplex))
	if err != nil {
		a.logf("the scanner did not start: %v", err)
		a.fail("The scanner did not start.", false)
		end.startFailed = true
		return end
	}

	var w *outbox.StackWriter
	first := ""
	problem := ""
	// stopped: the job ended other than by the scanner's own "no more
	// pages" or a Stop (an error, a stall, the agent quitting). The scanner
	// may still be feeding paper, so the job is cancelled, and the receipt
	// says the stack is partial.
	stopped := false
	halted := false
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
		// A Stop takes effect between sheets: never with a front whose back
		// has not come, unless the back does not come within stopWait.
		if asked, since := a.stopAsked(seq); asked && (!duplex || total%2 == 0 || since > a.stopWait) {
			halted = true
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
			a.logf("the scan stopped early: %v", err)
			problem, stopped = "The scan stopped early.", true
			break
		}
		if done {
			break
		}
		if w != nil && w.Full() {
			a.finish(w, "", "", false)
			w = nil
		}
		if w == nil {
			if w, err = a.store.NewStack(duplex); err != nil {
				a.logf("could not start a stack: %v", err)
				problem, end.saveFailed = "Could not save pages on this PC.", true
				cancelJob()
				break
			}
			if first == "" {
				first = w.ID()
			}
		}
		if err := w.Add(page); err != nil {
			a.logf("could not save a page: %v", err)
			problem, end.saveFailed = "Could not save a page on this PC.", true
			cancelJob()
			break
		}
		total++
		a.mu.Lock()
		a.scanner.Sides = total
		a.mu.Unlock()
	}
	if halted {
		a.logf("pile stopped on request after %d sides", total)
		cancelJob()
		if duplex && total%2 == 1 && w != nil {
			// A half-fed sheet is never kept: its front goes, and the sheet
			// is fed again whole.
			if err := w.DropLast(); err != nil {
				a.logf("could not drop the unpaired front: %v", err)
			} else {
				total--
				a.mu.Lock()
				a.scanner.Sides = total
				a.mu.Unlock()
			}
		}
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

	ended := ""
	switch {
	case halted:
		ended = outbox.EndedStopped
	case jam:
		ended = outbox.EndedJam
	case stopped || end.saveFailed:
		ended = outbox.EndedError
	}
	whole := total
	if duplex {
		whole = total / 2
	}

	sheets := 0
	saved := true
	if w != nil {
		mproblem := problem
		if halted && mproblem == "" {
			mproblem = "stopped part-way on request"
		}
		// A stopped or halted stack gets no "Safe" receipt of its own: the
		// lines below say what was kept and what to do.
		r, ferr := a.finish(w, mproblem, ended, (stopped && !jam) || halted)
		sheets = r.Sheets
		if r.Sides == 0 && first == r.Stack {
			first = ""
		}
		if ferr != nil && problem == "" {
			problem = "Some pages could not be saved on this PC. Scan this stack again."
		}
		if ferr != nil {
			saved = false
			end.saveFailed = true
			if stopped {
				problem = "The scan stopped and some pages could not be saved on this PC. Scan this stack again."
			}
		}
	}
	switch {
	case jam && halted:
		problem = fmt.Sprintf("Paper jam. Open the cover, take out the stuck sheet and put it back on top of the stack, then press Scan now to scan the rest. "+
			"Sally kept the %d %s already scanned and sets aside anything scanned twice.", whole, plural(whole, "sheet", "sheets"))
	case jam:
		problem = fmt.Sprintf("Paper jam. Open the cover, take out the stuck sheet and put it back on top of the stack. "+
			"Sally kept the %d %s already scanned and sets aside anything scanned twice.", sheets, plural(sheets, "sheet", "sheets"))
	case halted:
		problem = ""
	case stopped && saved && sheets > 0:
		problem = fmt.Sprintf("Got %d %s before it stopped. They are safe on this PC. "+
			"Check the feeder and the output tray: put the sheets that weren't scanned back in.", sheets, plural(sheets, "sheet", "sheets"))
	case stopped && saved:
		problem = "The scanner stopped before sending a page. Check the feeder and the output tray: put the sheets back in."
	}
	if halted && !jam {
		// The Stop words have their own line; one low tone, no chime, and
		// never the jam's repeat.
		a.mu.Lock()
		a.stopped, a.stoppedAt, a.stoppedBy, a.stoppedFrom = stopWords(whole), a.opt.Now(), a.stopBy, a.stopFrom
		a.mu.Unlock()
		a.play(sound.Problem)
	}
	if problem != "" {
		a.fail(problem, jam)
	}
	end.halted, end.jam, end.early = halted, jam, stopped
	end.sides, end.sheets, end.stack = total, whole, first
	a.logf("scan finished: %d sides", total)
	return end
}

// recordPileEndLocked records the final results of the commands a pile
// answers: the Scan now requests that fired on it or joined it, and the
// Stops asked for it.
func (a *Agent) recordPileEndLocked(end jobEnd) {
	sides, sheets, stack := count(end.sides), count(end.sheets), end.stack
	n := fmt.Sprintf("%d %s", end.sheets, plural(end.sheets, "sheet", "sheets"))
	for _, id := range a.jobWaiters {
		switch {
		case end.startFailed:
			a.results.record(id, resFailed, nil, nil, "", "The scanner did not start.")
		case end.halted:
			a.results.record(id, resStopped, sides, sheets, stack, "")
		case end.sides == 0:
			a.results.record(id, resFailed, sides, sheets, "", "The scanner sent no pages.")
		case end.jam:
			a.results.record(id, resFailed, sides, sheets, stack, "Paper jam after "+n+". They are safe on this PC.")
		case end.saveFailed:
			a.results.record(id, resFailed, sides, sheets, stack, "Could not save pages on this PC.")
		case end.early:
			a.results.record(id, resFailed, sides, sheets, stack, "The scan stopped early after "+n+". They are safe on this PC.")
		default:
			a.results.record(id, resDone, sides, sheets, stack, "")
		}
	}
	for _, id := range a.stopIDs {
		if end.halted {
			a.results.record(id, resDone, sides, sheets, stack, "")
		} else {
			a.results.record(id, resNothingToStop, nil, nil, "", "That pile had already finished.")
		}
	}
}

// finish closes a stack and says "safe" only if every side is on disk.
// quiet leaves the receipt to the caller (a stack the scanner cut short or
// a Stop ended).
func (a *Agent) finish(w *outbox.StackWriter, problem, ended string, quiet bool) (outbox.Receipt, error) {
	r, err := w.Finish(problem, ended)
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
		a.play(sound.Chime)
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
		a.play(sound.Problem)
		if !jam {
			return
		}
		time.Sleep(30 * time.Second)
		a.mu.Lock()
		still := a.jamOpen
		a.mu.Unlock()
		if still {
			a.play(sound.Problem)
		}
	}()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
