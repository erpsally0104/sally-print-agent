package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sallyerp/sally-print-agent/internal/autoscan"
	"github.com/sallyerp/sally-print-agent/internal/sally"
	"github.com/sallyerp/sally-print-agent/internal/sound"
)

// run starts the agent until the test ends.
func run(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// soundLog records the sounds an agent plays.
type soundLog struct {
	mu sync.Mutex
	n  map[sound.Sound]int
}

func recordSounds(a *Agent) *soundLog {
	l := &soundLog{n: map[sound.Sound]int{}}
	a.play = func(s sound.Sound) {
		l.mu.Lock()
		l.n[s]++
		l.mu.Unlock()
	}
	return l
}

func (l *soundLog) count(s sound.Sound) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n[s]
}

func autoOn(a *Agent, delay int) {
	on := true
	a.local.AutoStart, a.local.StartDelaySec = &on, delay
}

func num(m map[string]any, k string) float64 {
	f, _ := m[k].(float64)
	return f
}

// startStopTest scans a duplex pile from a Sally Scan now, holding the
// scanner after side 3, and asks Sally to stop it there.
func startStopTest(t *testing.T) (*fakeScanner, *fakeSallyAll, *Agent, *soundLog) {
	sc := &fakeScanner{pages: 10, holdAt: 3}
	scSrv := httptest.NewServer(sc)
	t.Cleanup(scSrv.Close)
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(scSrv.URL))
	autoOn(a, 2)
	a.stopWait = 3 * time.Second
	sounds := recordSounds(a)
	run(t, a)
	waitFor(t, "the scanner", func() bool { return a.Snapshot().ScannerID != "" })
	fs.queue(`{"id":"scan-1","kind":"SCAN_NOW","pauseMinutes":null}`)
	a.kickHeartbeat()
	waitFor(t, "the scan now to wait for paper", func() bool { return fs.lastResult("scan-1")["result"] == "WAITING_FOR_PAPER" })
	sc.set(func(f *fakeScanner) { f.loaded = true })
	waitFor(t, "side 3", func() bool { v := a.Snapshot(); return v.ScanSides == 3 && v.JobID != "" })
	fs.queue(fmt.Sprintf(`{"id":"stop-1","kind":"STOP","pauseMinutes":null,"job":%q,"byName":"Dana Field"}`, a.Snapshot().JobID))
	a.kickHeartbeat()
	waitFor(t, "the stop to be accepted", func() bool { return a.Snapshot().StopRequested })
	return sc, fs, a, sounds
}

func TestAStopAfterAFrontWaitsForItsBackAndKeepsWholeSheets(t *testing.T) {
	sc, fs, a, sounds := startStopTest(t)
	sc.set(func(f *fakeScanner) { f.holdAt = 0 })
	waitFor(t, "the partial stack to reach Sally", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.done == 1
	})
	fs.mu.Lock()
	an := fs.announced[0]
	fs.mu.Unlock()
	if num(an, "sheets") != 2 || num(an, "sides") != 4 || an["ended"] != "STOPPED" {
		t.Fatalf("announced %v", an)
	}
	sc.mu.Lock()
	if len(sc.deleted) != 1 || sc.deleted[0] != "/eSCL/ScanJobs/1" || sc.served != 4 {
		t.Fatalf("deleted %v served %d", sc.deleted, sc.served)
	}
	sc.mu.Unlock()
	waitFor(t, "the results", func() bool { return fs.lastResult("stop-1")["result"] == "DONE" })
	stop, scan := fs.lastResult("stop-1"), fs.lastResult("scan-1")
	if scan["result"] != "STOPPED" || num(scan, "sheets") != 2 || num(scan, "sides") != 4 || scan["stack"] != an["stack"] {
		t.Fatalf("scan now %v", scan)
	}
	if num(stop, "sheets") != 2 || num(stop, "sides") != 4 || stop["stack"] != an["stack"] {
		t.Fatalf("stop %v", stop)
	}
	// On the PC: the Stop words, no receipt, one low tone, no chime.
	v := a.Snapshot()
	if v.Stopped != stopWords(2) || !v.StoppedFromSally || v.StoppedBy != "Dana Field" || v.Receipt != "" || v.Problem != "" {
		t.Fatalf("%+v", v)
	}
	if sounds.count(sound.Problem) != 1 || sounds.count(sound.Chime) != 0 {
		t.Fatalf("problem %d chime %d", sounds.count(sound.Problem), sounds.count(sound.Chime))
	}
	if v.HoldState != "AFTER_STOP" {
		t.Fatalf("hold %q", v.HoldState)
	}

	// The rest of the pile is in the feeder: nothing starts while it reads
	// loaded, busy or jammed.
	time.Sleep(300 * time.Millisecond)
	sc.set(func(f *fakeScanner) { f.state = "Processing" })
	time.Sleep(300 * time.Millisecond)
	sc.set(func(f *fakeScanner) { f.state, f.jam = "", true })
	time.Sleep(300 * time.Millisecond)
	sc.set(func(f *fakeScanner) { f.jam = false })
	time.Sleep(2500 * time.Millisecond)
	sc.mu.Lock()
	jobs := sc.jobs
	sc.mu.Unlock()
	if jobs != 1 {
		t.Fatalf("a job started during the hold: %d", jobs)
	}
	// Taken out, then put back: it starts.
	sc.set(func(f *fakeScanner) { f.loaded = false })
	waitFor(t, "the hold to lift", func() bool { return a.Snapshot().HoldState == "" })
	sc.set(func(f *fakeScanner) { f.loaded = true })
	waitFor(t, "the next pile", func() bool {
		sc.mu.Lock()
		defer sc.mu.Unlock()
		return sc.jobs == 2
	})
}

func TestAStopWhoseBackNeverComesDropsTheLoneFront(t *testing.T) {
	sc, fs, _, _ := startStopTest(t)
	_ = sc
	waitFor(t, "the partial stack to reach Sally", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.done == 1
	})
	fs.mu.Lock()
	an := fs.announced[0]
	sides := fs.sides
	fs.mu.Unlock()
	if num(an, "sheets") != 1 || num(an, "sides") != 2 || an["ended"] != "STOPPED" || sides != 2 {
		t.Fatalf("announced %v, %d sides sent", an, sides)
	}
	waitFor(t, "the stop result", func() bool { return fs.lastResult("stop-1")["result"] == "DONE" })
	if rs := fs.results("stop-1"); rs[0]["result"] != "STOPPING" {
		t.Fatalf("the stop must first report STOPPING: %v", rs)
	}
	if r := fs.lastResult("scan-1"); r["result"] != "STOPPED" || num(r, "sheets") != 1 || num(r, "sides") != 2 {
		t.Fatalf("%v", r)
	}
}

func TestAStopForNoPileIsNothingToStop(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "s1", Kind: "STOP", Job: "j20261014T091502-3f9a"}, {ID: "s2", Kind: "STOP"}}})
	if r, _ := a.results.result("s1"); r.Result != "NOTHING_TO_STOP" || r.Message != "That pile had already finished." {
		t.Fatalf("%+v", r)
	}
	if r, _ := a.results.result("s2"); r.Result != "NOTHING_TO_STOP" || r.Message != "Sally did not say which pile to stop." {
		t.Fatalf("%+v", r)
	}
	a.jobSeq, a.job = 1, &sally.ScannerJob{ID: "jA"}
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "s3", Kind: "STOP", Job: "jB"}, {ID: "s4", Kind: "STOP", Job: "jA"}}})
	if r, _ := a.results.result("s3"); r.Result != "NOTHING_TO_STOP" {
		t.Fatalf("%+v", r)
	}
	if r, _ := a.results.result("s4"); r.Result != "STOPPING" || !a.job.Stopping {
		t.Fatalf("%+v", r)
	}
	// The pile ends by itself before the stop takes effect.
	a.recordPileEndLocked(jobEnd{sides: 4, sheets: 2, stack: "s"})
	if r, _ := a.results.result("s4"); r.Result != "NOTHING_TO_STOP" || r.Message != "That pile had already finished." {
		t.Fatalf("%+v", r)
	}
}

func TestSallysScanNowDuringTheHoldsAfterAStop(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.opt.Now = func() time.Time { return now }
	a.scannerOpen = true
	a.machine.HoldUntilClear(autoscan.HoldAfterStop)
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c1", Kind: "SCAN_NOW"}}})
	if r, _ := a.results.result("c1"); r.Result != "WAITING_FOR_PAPER" {
		t.Fatalf("%+v", r)
	}
	if k := a.machine.Observe(now.Add(time.Second), autoscan.Observation{Reachable: true, Idle: true, Loaded: true}, autoscan.Settings{AutoStart: true}, false); k != autoscan.ScanNow {
		t.Fatalf("scan now must scan during AFTER_STOP: %q", k)
	}
	b := pairedAgent(t, "http://127.0.0.1:1", nil)
	b.scannerOpen = true
	b.machine.HoldUntilClear(autoscan.HoldAfterStopOnPC)
	b.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c2", Kind: "SCAN_NOW"}}})
	if r, _ := b.results.result("c2"); r.Result != "FAILED" || r.Message != "Someone stopped this pile on the PC." {
		t.Fatalf("%+v", r)
	}
	if b.machine.Pending(time.Now()) != autoscan.None {
		t.Fatal("nothing may wait")
	}
}

func TestAScanNowReportsWaitingScanningAndDone(t *testing.T) {
	sc := &fakeScanner{pages: 4}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(scSrv.URL))
	autoOn(a, 5)
	run(t, a)
	waitFor(t, "the scanner", func() bool { return a.Snapshot().ScannerID != "" })
	fs.queue(`{"id":"scan-1","kind":"SCAN_NOW","pauseMinutes":null}`)
	a.kickHeartbeat()
	waitFor(t, "waiting for paper", func() bool { return fs.lastResult("scan-1")["result"] == "WAITING_FOR_PAPER" })
	sc.set(func(f *fakeScanner) { f.loaded, f.pageDelay = true, 300*time.Millisecond })
	waitFor(t, "done", func() bool { return fs.lastResult("scan-1")["result"] == "DONE" })
	var seq []string
	for _, r := range fs.results("scan-1") {
		if len(seq) == 0 || seq[len(seq)-1] != r["result"] {
			seq = append(seq, r["result"].(string))
		}
	}
	if strings.Join(seq, ",") != "WAITING_FOR_PAPER,SCANNING,DONE" {
		t.Fatalf("results %v", seq)
	}
	fs.mu.Lock()
	stack := fs.announced[0]["stack"]
	fs.mu.Unlock()
	if r := fs.lastResult("scan-1"); num(r, "sides") != 4 || num(r, "sheets") != 2 || r["stack"] != stack {
		t.Fatalf("%v (stack %v)", r, stack)
	}
}

func TestResultsAreResentUntilA2xxThenDropped(t *testing.T) {
	fs := newFakeSallyAll(t)
	fs.failBeats = 1
	a := pairedAgent(t, fs.srv.URL, nil)
	a.results.record("c1", resDone, nil, nil, "", "")
	a.StopPile("nothing") // refused: no action queued
	a.heartbeatOnce(context.Background())
	a.heartbeatOnce(context.Background())
	a.heartbeatOnce(context.Background())
	if n := len(fs.results("c1")); n != 2 {
		t.Fatalf("sent %d times, want 2 (once refused, once taken)", n)
	}
	if _, ok := a.results.result("c1"); ok {
		t.Fatal("a delivered final result must be dropped")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, ok := fs.beats[2]["commandResults"]; ok {
		t.Fatalf("nothing left to send: %v", fs.beats[2])
	}
}

func TestAScanNowWithoutPaperLapses(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.opt.Now = func() time.Time { return now }
	a.scannerOpen = true
	a.lastObs = autoscan.Observation{Reachable: true, Idle: true, Clear: true}
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c1", Kind: "SCAN_NOW"}}})
	now = now.Add(121 * time.Second)
	a.report()
	if r, _ := a.results.result("c1"); r.Result != "NO_PAPER" {
		t.Fatalf("%+v", r)
	}
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c2", Kind: "TEST_SCAN"}}})
	a.lastJam = true
	now = now.Add(121 * time.Second)
	a.report()
	if r, _ := a.results.result("c2"); r.Result != "FAILED" || r.Message != "Paper jam or cover open." {
		t.Fatalf("%+v", r)
	}
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c3", Kind: "SCAN_NOW"}}})
	a.lastObs, a.lastJam = autoscan.Observation{}, false
	now = now.Add(121 * time.Second)
	a.report()
	if r, _ := a.results.result("c3"); r.Result != "FAILED" || r.Message != "The scanner is not answering." {
		t.Fatalf("%+v", r)
	}
	// No scanner at all: refused at once.
	a.scannerOpen = false
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c4", Kind: "SCAN_NOW"}}})
	if r, _ := a.results.result("c4"); r.Result != "FAILED" || r.Message != "No scanner was found on this PC." {
		t.Fatalf("%+v", r)
	}
}

func TestAScanNowMidPileJoinsIt(t *testing.T) {
	sc := &fakeScanner{pages: 6, holdAt: 3, loaded: true}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(scSrv.URL))
	autoOn(a, 2)
	run(t, a)
	waitFor(t, "side 3", func() bool { return a.Snapshot().ScanSides == 3 })
	fs.queue(`{"id":"scan-2","kind":"SCAN_NOW","pauseMinutes":null}`)
	a.kickHeartbeat()
	waitFor(t, "scanning", func() bool { return fs.lastResult("scan-2")["result"] == "SCANNING" })
	if r := fs.lastResult("scan-2"); num(r, "sides") != 3 {
		t.Fatalf("%v", r)
	}
	sc.set(func(f *fakeScanner) { f.holdAt = 0 })
	waitFor(t, "done", func() bool { return fs.lastResult("scan-2")["result"] == "DONE" })
	if r := fs.lastResult("scan-2"); num(r, "sides") != 6 || num(r, "sheets") != 3 {
		t.Fatalf("%v", r)
	}
	time.Sleep(300 * time.Millisecond)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.jobs != 1 {
		t.Fatalf("%d jobs", sc.jobs)
	}
}

func TestAPileWithNoPagesFails(t *testing.T) {
	sc := &fakeScanner{pages: 0}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(scSrv.URL))
	run(t, a)
	waitFor(t, "the scanner", func() bool { return a.Snapshot().ScannerID != "" })
	fs.queue(`{"id":"scan-1","kind":"SCAN_NOW","pauseMinutes":null}`)
	a.kickHeartbeat()
	waitFor(t, "waiting", func() bool { return fs.lastResult("scan-1")["result"] == "WAITING_FOR_PAPER" })
	sc.set(func(f *fakeScanner) { f.loaded = true })
	waitFor(t, "failed", func() bool { return fs.lastResult("scan-1")["result"] == "FAILED" })
	if r := fs.lastResult("scan-1"); r["message"] != "The scanner sent no pages." {
		t.Fatalf("%v", r)
	}
}

func TestNoRawErrorReachesSally(t *testing.T) {
	for name, set := range map[string]func(f *fakeScanner){
		"page error": func(f *fakeScanner) { f.failAt, f.failBody, f.pages = 2, "SECRET-PAGE-BODY 10.0.0.9", 6 },
		"start":      func(f *fakeScanner) { f.startStatus, f.pages = 500, 6 },
	} {
		t.Run(name, func(t *testing.T) {
			sc := &fakeScanner{}
			sc.set(set)
			scSrv := httptest.NewServer(sc)
			defer scSrv.Close()
			fs := newFakeSallyAll(t)
			a := pairedAgent(t, fs.srv.URL, discoverAt(scSrv.URL))
			run(t, a)
			waitFor(t, "the scanner", func() bool { return a.Snapshot().ScannerID != "" })
			fs.queue(`{"id":"scan-1","kind":"SCAN_NOW","pauseMinutes":null}`)
			a.kickHeartbeat()
			waitFor(t, "waiting", func() bool { return fs.lastResult("scan-1")["result"] == "WAITING_FOR_PAPER" })
			sc.set(func(f *fakeScanner) { f.loaded = true })
			waitFor(t, "failed", func() bool { return fs.lastResult("scan-1")["result"] == "FAILED" })
			r := fs.lastResult("scan-1")
			want := map[string]string{
				"page error": "The scan stopped early after 1 sheet. They are safe on this PC.",
				"start":      "The scanner did not start.",
			}[name]
			if r["message"] != want {
				t.Fatalf("%v", r)
			}
			req, _ := a.report()
			body, _ := json.Marshal(req)
			if strings.Contains(string(body), "SECRET") || strings.Contains(string(body), "escl:") || strings.Contains(a.Snapshot().Problem, "SECRET") {
				t.Fatalf("a raw error got out: %s", body)
			}
			if name == "start" && req.Scanner.Problem != "The scanner did not start." {
				t.Fatalf("problem %q", req.Scanner.Problem)
			}
		})
	}
}

func TestSallysScanNowWhilePausedIsRefusedAndNothingScans(t *testing.T) {
	sc := &fakeScanner{pages: 4, loaded: true}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(scSrv.URL))
	a.Pause(0)
	run(t, a)
	waitFor(t, "the scanner", func() bool { return a.Snapshot().ScannerID != "" })
	fs.queue(`{"id":"scan-1","kind":"SCAN_NOW","pauseMinutes":null}`)
	a.kickHeartbeat()
	waitFor(t, "refused", func() bool { return fs.lastResult("scan-1")["result"] == "FAILED" })
	if r := fs.lastResult("scan-1"); r["message"] != "This PC is paused." {
		t.Fatalf("%v", r)
	}
	time.Sleep(500 * time.Millisecond)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.jobs != 0 {
		t.Fatal("a paused PC scanned for Sally")
	}
}

func TestAPauseCancelsAWaitingScanNow(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	loaded := autoscan.Observation{Reachable: true, Idle: true, Loaded: true}
	for _, from := range []string{"Sally", "the status page"} {
		a := pairedAgent(t, "http://127.0.0.1:1", nil)
		a.opt.Now = func() time.Time { return now }
		a.scannerOpen = true
		a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "c1", Kind: "SCAN_NOW"}}})
		if from == "Sally" {
			m := 15
			a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "p1", Kind: "PAUSE", PauseMinutes: &m}}})
		} else {
			a.Pause(15)
		}
		if r, _ := a.results.result("c1"); r.Result != "FAILED" || r.Message != "The PC was paused before paper went in." {
			t.Fatalf("%s: %+v", from, r)
		}
		if k := a.machine.Observe(now.Add(time.Second), loaded, autoscan.Settings{AutoStart: true}, true); k != autoscan.None {
			t.Fatalf("%s: paper loaded after the pause was scanned", from)
		}
	}
}

// twoScanners serves A and B and lists both.
func twoScanners(t *testing.T) (a, b *fakeScanner, aURL, bURL string, look Looker, idA, idB string) {
	const uA, uB = "aaaaaaaa-0000-4000-8000-000000000001", "bbbbbbbb-0000-4000-8000-000000000002"
	a, b = &fakeScanner{uuid: uA, pages: 4}, &fakeScanner{uuid: uB, pages: 4}
	sa, sb := httptest.NewServer(a), httptest.NewServer(b)
	t.Cleanup(sa.Close)
	t.Cleanup(sb.Close)
	idA, idB = ScannerID("uuid:"+uA), ScannerID("uuid:"+uB)
	look = func(context.Context, string, Skip, map[string]string, func(string, ...any)) []Found {
		return []Found{
			{ID: idA, Name: "Front desk scanner", Net: []netBase{{URL: sa.URL, Root: "eSCL", keys: addrKeys(sa.URL)}}, Answering: true, Stable: true},
			{ID: idB, Name: "Back office scanner", Net: []netBase{{URL: sb.URL, Root: "eSCL", keys: addrKeys(sb.URL)}}, Answering: true, Stable: true},
		}
	}
	return a, b, sa.URL, sb.URL, look, idA, idB
}

func TestChoosingAnotherScannerSwitchesAfterTheRunningPile(t *testing.T) {
	scA, scB, aURL, _, look, idA, idB := twoScanners(t)
	scA.set(func(f *fakeScanner) { f.loaded, f.holdAt = true, 2 })
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(aURL))
	a.opt.Look = look
	autoOn(a, 2)
	run(t, a)
	waitFor(t, "side 2 on A", func() bool { v := a.Snapshot(); return v.ScanSides == 2 && v.ScannerID == idA && len(v.Scanners) == 2 })
	fs.queue(fmt.Sprintf(`{"id":"sel-1","kind":"SELECT_SCANNER","pauseMinutes":null,"scannerId":%q,"byName":"Dana Field"}`, idB))
	a.kickHeartbeat()
	waitFor(t, "the choice", func() bool { return fs.lastResult("sel-1")["result"] == "DONE" })
	if v := a.Snapshot(); v.ScannerID != idA || v.JobID == "" || v.ChosenID != idB || v.ChosenBy != "Dana Field" {
		t.Fatalf("the pile on A must finish first: %+v", v)
	}
	scA.set(func(f *fakeScanner) { f.holdAt = 0 })
	waitFor(t, "B in use", func() bool { v := a.Snapshot(); return v.ScannerID == idB && v.ScannerState == "IDLE" })
	scA.set(func(f *fakeScanner) { f.loaded, f.pages, f.served = true, 4, 0 })
	scB.set(func(f *fakeScanner) { f.loaded = true })
	waitFor(t, "a pile on B", func() bool {
		scB.mu.Lock()
		defer scB.mu.Unlock()
		return scB.jobs == 1
	})
	time.Sleep(300 * time.Millisecond)
	scA.mu.Lock()
	defer scA.mu.Unlock()
	if scA.jobs != 1 {
		t.Fatalf("A was scanned again: %d jobs", scA.jobs)
	}
	if body := fs.beats[len(fs.beats)-1]; body["chosenScannerId"] != idB {
		t.Fatalf("chosenScannerId %v", body["chosenScannerId"])
	}
}

func TestAChosenScannerThatDoesNotAnswerIsWaitedFor(t *testing.T) {
	scA, scB, aURL, bURL, look, _, idB := twoScanners(t)
	_ = scB
	scA.set(func(f *fakeScanner) { f.loaded = true })
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, discoverAt(aURL))
	a.opt.Look = func(ctx context.Context, addr string, s Skip, k map[string]string, l func(string, ...any)) []Found {
		fs := look(ctx, addr, s, k, l)
		fs[1].Net[0].URL = "http://127.0.0.1:1" // B is switched off
		return fs
	}
	_ = bURL
	autoOn(a, 2)
	a.local.ScannerID, a.local.ScannerName, a.local.ScannerVia = idB, "Back office scanner", []string{"NETWORK"}
	run(t, a)
	waitFor(t, "B reported offline", func() bool {
		req, _ := a.report()
		return req.Scanner.ID == idB && req.Scanner.State == "OFFLINE" && req.Scanner.Kind == "NETWORK" && !req.Scanner.AdfLoaded && !req.Scanner.Scanning
	})
	v := a.Snapshot()
	if !v.ChosenMissing || v.ScannerName != "Back office scanner" {
		t.Fatalf("%+v", v)
	}
	time.Sleep(3 * time.Second)
	scA.mu.Lock()
	defer scA.mu.Unlock()
	if scA.jobs != 0 {
		t.Fatal("the PC fell back to A")
	}
}

func TestSelectScannerChecksTheID(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	idB := ScannerID("uuid:bbbbbbbb-0000-4000-8000-000000000002")
	a.mergeInventoryLocked([]Found{{ID: idB, Name: "Back office scanner", Net: []netBase{{URL: "http://b"}}, Answering: true}}, time.Now())
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{
		{ID: "s1", Kind: "SELECT_SCANNER", ScannerID: json.RawMessage(`"sc-00000000000000000000"`)},
		{ID: "s2", Kind: "SELECT_SCANNER"},
		{ID: "s3", Kind: "SELECT_SCANNER", ScannerID: json.RawMessage(`"not-an-id"`)},
		{ID: "s4", Kind: "SELECT_SCANNER", ScannerID: json.RawMessage(`"` + idB + `"`), ByName: "Dana Field"},
	}})
	for id, want := range map[string]string{"s1": "That scanner is not on this PC's list.", "s2": "Sally did not say which scanner.", "s3": "That scanner is not on this PC's list."} {
		if r, _ := a.results.result(id); r.Result != "FAILED" || r.Message != want {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	if r, _ := a.results.result("s4"); r.Result != "DONE" || a.local.ScannerID != idB || a.local.ScannerChosenBy != "Dana Field" {
		t.Fatalf("%+v %+v", r, a.local)
	}
	a.apply(&sally.HeartbeatResponse{Commands: []sally.Command{{ID: "s5", Kind: "SELECT_SCANNER", ScannerID: json.RawMessage(`null`)}}})
	if r, _ := a.results.result("s5"); r.Result != "DONE" || a.local.ScannerID != "" {
		t.Fatalf("null must mean automatic: %+v %q", r, a.local.ScannerID)
	}
}

func TestTheChoiceAndKnownScannersSurviveARestart(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	idB := ScannerID("uuid:bbbbbbbb-0000-4000-8000-000000000002")
	k := mdnsKeys("Back office [0B0B0B]", "back.local.")
	a.mergeInventoryLocked([]Found{{ID: idB, Name: "Back office scanner", Net: []netBase{{URL: "http://b"}}, Answering: true, learned: map[string]string{k.key: idB}}}, time.Now())
	if err := a.SelectScanner(idB); err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{Dir: a.opt.Dir, BaseURL: "http://127.0.0.1:1", Version: "x", Scanning: true, Look: noLook})
	if err != nil {
		t.Fatal(err)
	}
	if b.local.ScannerID != idB || b.local.ScannerName != "Back office scanner" || b.local.ScannerChosenBy != "PC" || b.local.ScannerChosenAt == nil {
		t.Fatalf("%+v", b.local)
	}
	if b.local.KnownScanners[k.key] != idB {
		t.Fatalf("known %v", b.local.KnownScanners)
	}
	req, _ := b.report()
	if req.ChosenScannerID == nil || *req.ChosenScannerID != idB {
		t.Fatal("the choice must be reported after a restart")
	}
}

func TestStatusPageActionsAreReportedUntilA2xx(t *testing.T) {
	fs := newFakeSallyAll(t)
	fs.failBeats = 1
	a := pairedAgent(t, fs.srv.URL, nil)
	idB := ScannerID("uuid:bbbbbbbb-0000-4000-8000-000000000002")
	a.mergeInventoryLocked([]Found{{ID: idB, Name: "Back office scanner", Net: []netBase{{URL: "http://b"}}, Answering: true}}, time.Now())
	if err := a.SelectScanner("sc-00000000000000000000"); err == nil {
		t.Fatal("an unknown scanner must be refused")
	}
	if err := a.SelectScanner(idB); err != nil {
		t.Fatal(err)
	}
	a.jobSeq, a.job = 1, &sally.ScannerJob{ID: "j20261014T091502-3f9a"}
	if err := a.StopPile("j20261014T091502-0000"); err == nil || err.Error() != "That pile has already finished." {
		t.Fatalf("%v", err)
	}
	if err := a.StopPile("j20261014T091502-3f9a"); err != nil {
		t.Fatal(err)
	}
	if a.stopFrom != stopPC || !a.job.Stopping {
		t.Fatal("the stop must be marked as from this PC")
	}
	a.heartbeatOnce(context.Background()) // 500
	a.heartbeatOnce(context.Background())
	a.heartbeatOnce(context.Background())
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for i := 0; i < 2; i++ {
		acts, _ := fs.beats[i]["localActions"].([]any)
		if len(acts) != 2 {
			t.Fatalf("beat %d: %v", i, fs.beats[i]["localActions"])
		}
		sel, stop := acts[0].(map[string]any), acts[1].(map[string]any)
		if sel["kind"] != "SELECT_SCANNER" || sel["scannerId"] != idB || stop["kind"] != "STOP" || stop["job"] != "j20261014T091502-3f9a" || sel["id"] == "" || sel["at"] == nil {
			t.Fatalf("%v %v", sel, stop)
		}
	}
	if _, ok := fs.beats[2]["localActions"]; ok {
		t.Fatal("delivered actions must be dropped")
	}
}

func TestTheHeartbeatCarriesTheNewFields(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	decode := func() map[string]any {
		req, _ := a.report()
		b, _ := json.Marshal(req)
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}
	m := decode()
	if f, _ := m["features"].([]any); len(f) != 3 || f[0] != "COMMAND_RESULTS" || f[1] != "STOP" || f[2] != "SCANNERS" {
		t.Fatalf("features %v", m["features"])
	}
	if s, ok := m["scanners"].([]any); !ok || len(s) != 0 {
		t.Fatalf("scanners %v", m["scanners"])
	}
	if v, ok := m["chosenScannerId"]; !ok || v != nil {
		t.Fatalf("chosenScannerId %v", m["chosenScannerId"])
	}
	scn := m["scanner"].(map[string]any)
	for _, k := range []string{"job", "held", "id", "problem"} {
		if _, ok := scn[k]; ok {
			t.Fatalf("%s must be absent: %v", k, scn)
		}
	}
	a.jobSeq, a.job = 1, &sally.ScannerJob{ID: "j20261014T091502-3f9a", Kind: "AUTO", StartedAt: time.Now()}
	a.scanner.Scanning, a.scanner.Sides = true, 7
	a.machine.HoldUntilClear(autoscan.HoldAfterStop)
	scn = decode()["scanner"].(map[string]any)
	job, _ := scn["job"].(map[string]any)
	if job == nil || job["id"] != "j20261014T091502-3f9a" || job["sides"] != float64(7) || job["stopping"] != false || scn["held"] != "AFTER_STOP" {
		t.Fatalf("%v", scn)
	}
}

func TestBeatEveryAndTheOneSecondFloor(t *testing.T) {
	now := time.Now()
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.hbEvery = 10 * time.Second
	if d := a.beatEvery(now); d != 10*time.Second {
		t.Fatalf("idle %s", d)
	}
	a.job = &sally.ScannerJob{ID: "j"}
	if d := a.beatEvery(now); d != 5*time.Second {
		t.Fatalf("scanning %s", d)
	}
	a.job = nil
	a.machine.Request(now, autoscan.ScanNow, "c1")
	if d := a.beatEvery(now); d != 5*time.Second {
		t.Fatalf("waiting %s", d)
	}
	a.machine.Cancel()
	a.stopFor = 1
	if d := a.beatEvery(now); d != 5*time.Second {
		t.Fatalf("stopping %s", d)
	}

	fs := newFakeSallyAll(t)
	b := pairedAgent(t, fs.srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.heartbeatLoop(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	beats := func() int {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.beats)
	}
	waitFor(t, "the first check-in", func() bool { return beats() == 1 })
	b.kickHeartbeat()
	time.Sleep(100 * time.Millisecond)
	b.kickHeartbeat()
	time.Sleep(1500 * time.Millisecond)
	if n := beats(); n != 2 {
		t.Fatalf("two kicks within a second sent %d check-ins after the first", n-1)
	}
}

func TestTextIsCutOnRuneBoundaries(t *testing.T) {
	s := strings.Repeat("a", 199) + "€" + "tail"
	got := short(s)
	if !utf8.ValidString(got) || len(got) != 199 {
		t.Fatalf("%d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.scanner = scannerView{Kind: "USB", Name: "Desk\x00 " + strings.Repeat("€", 130), State: "IDLE"}
	req, _ := a.report()
	if strings.ContainsRune(req.Scanner.Name, 0) || !utf8.ValidString(req.Scanner.Name) || utf8.RuneCountInString(req.Scanner.Name) != 120 {
		t.Fatalf("%q", req.Scanner.Name)
	}
}
