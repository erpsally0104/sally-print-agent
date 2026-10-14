package autoscan

import (
	"testing"
	"time"
)

var (
	idleLoaded = Observation{Reachable: true, Idle: true, Loaded: true}
	idleEmpty  = Observation{Reachable: true, Idle: true}
	idleClear  = Observation{Reachable: true, Idle: true, Clear: true}
	busy       = Observation{Reachable: true, Loaded: true}
	jammed     = Observation{Reachable: true, Idle: true} // AdfJam: not "loaded"
	on3        = Settings{AutoStart: true, Delay: 3 * time.Second}
)

// sim walks the machine one second at a time.
type sim struct {
	t   *testing.T
	m   *Machine
	now time.Time
}

func newSim(t *testing.T) *sim {
	return &sim{t: t, m: New(), now: time.Date(2026, 10, 12, 11, 0, 0, 0, time.UTC)}
}

// feed observes o for secs seconds and returns the second (1-based) a scan
// started, or 0.
func (s *sim) feed(o Observation, secs int, set Settings, paused bool) (int, Kind) {
	for i := 1; i <= secs; i++ {
		s.now = s.now.Add(time.Second)
		if k := s.m.Observe(s.now, o, set, paused); k != None {
			s.m.Started()
			return i, k
		}
	}
	return 0, None
}

func TestStartsAfterTheDelayOfContinuousIdleWithPaper(t *testing.T) {
	s := newSim(t)
	if at, _ := s.feed(idleEmpty, 5, on3, false); at != 0 {
		t.Fatal("started with an empty feeder")
	}
	// Paper in at t=0; observed at 1,2,3 s → the 3 s mark is the third poll
	// after the first sighting.
	at, k := s.feed(idleLoaded, 10, on3, false)
	if k != Auto || at != 4 {
		t.Fatalf("started at %d (%s), want the 4th poll (3 s after first seen)", at, k)
	}
}

func TestABusyMomentRestartsTheWait(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 2, on3, false)
	s.feed(busy, 1, on3, false)
	if at, _ := s.feed(idleLoaded, 3, on3, false); at != 0 {
		t.Fatal("the wait must restart after the scanner was busy")
	}
	if at, _ := s.feed(idleLoaded, 1, on3, false); at != 1 {
		t.Fatal("should start once the new period reaches 3 s")
	}
}

func TestFinishedJobThenEmptyThenReloadStartsAgain(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 4, on3, false)
	s.m.Ended()
	s.feed(idleEmpty, 2, on3, false)
	if at, k := s.feed(idleLoaded, 10, on3, false); k != Auto || at != 4 {
		t.Fatalf("reload after an empty feeder should start after 3 s, got %d %s", at, k)
	}
}

func TestAJobThatLeavesPaperInTheFeederDoesNotLoop(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 4, on3, false)
	s.m.Ended() // a misfeed: nothing scanned, paper still there
	if at, _ := s.feed(idleLoaded, 60, on3, false); at != 0 {
		t.Fatal("must not start again until something changes")
	}
}

func TestJamMidJobThenClearedStartsAgain(t *testing.T) {
	s := newSim(t)
	if _, k := s.feed(idleLoaded, 4, on3, false); k != Auto {
		t.Fatal("first stack should start")
	}
	// The job ends with an error: the scanner reports the jam.
	s.m.Ended()
	if at, _ := s.feed(jammed, 20, on3, false); at != 0 {
		t.Fatal("must not start while jammed")
	}
	// The person clears the jam and puts the rest back on top. The feeder
	// never reported "empty": no empty→loaded edge is needed.
	at, k := s.feed(idleLoaded, 10, on3, false)
	if k != Auto || at != 4 {
		t.Fatalf("after the jam is cleared it should start 3 s later, got %d %s", at, k)
	}
}

func TestJamClearedWhileStillIdleLoadedNeedsAChange(t *testing.T) {
	// Some scanners report the jam only on the job and go straight back to
	// idle-with-paper. Opening the door (any non idle-loaded state) re-arms.
	s := newSim(t)
	s.feed(idleLoaded, 4, on3, false)
	s.m.Ended()
	if at, _ := s.feed(idleLoaded, 10, on3, false); at != 0 {
		t.Fatal("no change seen yet")
	}
	s.feed(Observation{Reachable: true, Idle: true}, 1, on3, false) // door open
	if at, _ := s.feed(idleLoaded, 4, on3, false); at != 4 {
		t.Fatal("should start 3 s after the door closes")
	}
}

func TestPausedOrAutoStartOffNeverStarts(t *testing.T) {
	for name, tc := range map[string]struct {
		set    Settings
		paused bool
	}{
		"paused":         {on3, true},
		"auto-start off": {Settings{AutoStart: false, Delay: 3 * time.Second}, false},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSim(t)
			if at, _ := s.feed(idleLoaded, 30, tc.set, tc.paused); at != 0 {
				t.Fatal("started")
			}
			if !s.m.HeldWhilePaused() {
				t.Fatal("should say paper is waiting while paused")
			}
			// Resuming with that paper still in does not send it.
			if at, _ := s.feed(idleLoaded, 30, on3, false); at != 0 {
				t.Fatal("paper put in while paused must not go up on resume")
			}
			// Taking it out and putting it back does.
			s.feed(idleEmpty, 1, on3, false)
			if at, _ := s.feed(idleLoaded, 4, on3, false); at != 4 {
				t.Fatal("a fresh load after resume should start")
			}
		})
	}
}

func TestScanNowWorksWhilePausedButOnlyOnce(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 5, on3, true)
	s.m.Request(s.now, ScanNow, "")
	at, k := s.feed(idleLoaded, 1, on3, true)
	if k != ScanNow || at != 1 {
		t.Fatalf("scan now should start at once, got %d %s", at, k)
	}
	s.m.Ended()
	if at, _ := s.feed(idleLoaded, 30, on3, true); at != 0 {
		t.Fatal("scan now must scan once")
	}
}

func TestScanNowWaitsForPaperThenExpires(t *testing.T) {
	s := newSim(t)
	s.m.Request(s.now, TestScan, "")
	s.feed(idleEmpty, 10, Settings{}, false)
	if s.m.Pending(s.now) != TestScan {
		t.Fatal("the request should still be waiting for paper")
	}
	if _, k := s.feed(idleLoaded, 1, Settings{}, false); k != TestScan {
		t.Fatal("test scan should start when paper arrives")
	}
	s.m.Ended()
	s.m.Request(s.now, ScanNow, "")
	s.feed(idleEmpty, 200, Settings{}, false)
	if _, k := s.feed(idleLoaded, 1, Settings{}, false); k != None {
		t.Fatal("an old request must not fire")
	}
}

func TestNothingStartsWhileAJobRuns(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 4, on3, false) // started
	s.m.Request(s.now, ScanNow, "")
	if at, _ := s.feed(idleLoaded, 10, on3, false); at != 0 {
		t.Fatal("started a second job while one runs")
	}
}

func TestUnreachableScannerResetsTheWait(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 2, on3, false)
	s.feed(Observation{}, 1, on3, false)
	if at, _ := s.feed(idleLoaded, 3, on3, false); at != 0 {
		t.Fatal("the wait restarts after the scanner dropped off")
	}
}

func TestDefaultDelayIsThreeSeconds(t *testing.T) {
	s := newSim(t)
	if at, _ := s.feed(idleLoaded, 10, Settings{AutoStart: true}, false); at != 4 {
		t.Fatalf("started at %d", at)
	}
}

func TestTwoRequestsInOneWindowFireOnOneStart(t *testing.T) {
	s := newSim(t)
	s.m.Request(s.now, ScanNow, "c1")
	s.feed(idleEmpty, 5, on3, false)
	s.m.Request(s.now, ScanNow, "c2")
	if _, k := s.feed(idleLoaded, 1, on3, false); k != ScanNow {
		t.Fatal("should start")
	}
	if got := s.m.TakeFired(); len(got) != 2 || got[0] != "c1" || got[1] != "c2" {
		t.Fatalf("fired %v", got)
	}
	if got := s.m.TakeFired(); len(got) != 0 {
		t.Fatalf("taken twice: %v", got)
	}
}

func TestALapsedRequestComesBackOnceEvenWithoutObserve(t *testing.T) {
	s := newSim(t)
	s.m.Request(s.now, ScanNow, "c1")
	if got := s.m.TakeLapsed(s.now.Add(119 * time.Second)); len(got) != 0 {
		t.Fatalf("lapsed early: %v", got)
	}
	if got := s.m.TakeLapsed(s.now.Add(121 * time.Second)); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("lapsed %v", got)
	}
	if got := s.m.TakeLapsed(s.now.Add(122 * time.Second)); len(got) != 0 {
		t.Fatalf("lapsed twice: %v", got)
	}
	// Through Observe as well.
	s.m.Request(s.now, TestScan, "c2")
	s.feed(idleEmpty, 121, on3, false)
	if got := s.m.TakeLapsed(s.now); len(got) != 1 || got[0] != "c2" {
		t.Fatalf("lapsed %v", got)
	}
}

func TestARequestAfterTheWindowLapsesTheOldIDs(t *testing.T) {
	s := newSim(t)
	s.m.Request(s.now, ScanNow, "old")
	s.now = s.now.Add(3 * time.Minute)
	s.m.Request(s.now, ScanNow, "new")
	if got := s.m.TakeLapsed(s.now); len(got) != 1 || got[0] != "old" {
		t.Fatalf("lapsed %v", got)
	}
	s.feed(idleLoaded, 1, on3, false)
	if got := s.m.TakeFired(); len(got) != 1 || got[0] != "new" {
		t.Fatalf("fired %v", got)
	}
}

func TestCancelDropsTheWaitingRequest(t *testing.T) {
	s := newSim(t)
	s.m.Request(s.now, ScanNow, "c1")
	s.m.Request(s.now, ScanNow, "")
	s.m.Cancel()
	if got := s.m.TakeCancelled(); len(got) != 2 || got[0] != "c1" {
		t.Fatalf("cancelled %v", got)
	}
	if at, _ := s.feed(idleLoaded, 30, on3, true); at != 0 {
		t.Fatal("a cancelled request fired")
	}
	if s.m.Pending(s.now) != None {
		t.Fatal("still pending")
	}
}

func TestTheHoldAfterAStopLiftsOnlyOnAClearFeeder(t *testing.T) {
	for _, h := range []Hold{HoldAfterStop, HoldAfterStopOnPC} {
		for name, clear := range map[string]Observation{
			"feeder empty":    idleClear,
			"no feeder state": {Reachable: true, Idle: true, Clear: true},
		} {
			s := newSim(t)
			s.feed(idleLoaded, 4, on3, false)
			s.m.Ended()
			s.m.HoldUntilClear(h)
			s.feed(busy, 2, on3, false)
			if at, _ := s.feed(idleLoaded, 30, on3, false); at != 0 {
				t.Fatalf("%s: started after busy", name)
			}
			s.feed(jammed, 2, on3, false)
			s.feed(Observation{Reachable: true, Idle: true}, 2, on3, false) // door open
			if at, _ := s.feed(idleLoaded, 30, on3, false); at != 0 {
				t.Fatalf("%s: a jam or an open door lifted the hold", name)
			}
			s.feed(clear, 1, on3, false)
			if s.m.Held() != "" {
				t.Fatalf("%s: still held", name)
			}
			if at, k := s.feed(idleLoaded, 10, on3, false); k != Auto || at != 4 {
				t.Fatalf("%s: got %d %s", name, at, k)
			}
		}
	}
}

func TestScanNowFiresDuringAHoldAndEndedClearsIt(t *testing.T) {
	for _, h := range []Hold{HoldAfterStop, HoldAfterStopOnPC} {
		s := newSim(t)
		s.feed(idleLoaded, 4, on3, false)
		s.m.Ended()
		s.m.HoldUntilClear(h)
		s.m.Request(s.now, ScanNow, "c1")
		if _, k := s.feed(idleLoaded, 1, on3, false); k != ScanNow {
			t.Fatal("scan now must fire during a hold")
		}
		s.m.Ended()
		if s.m.Held() != "" {
			t.Fatalf("Ended must clear the hold: %q", s.m.Held())
		}
	}
}

func TestHeldNamesTheHold(t *testing.T) {
	s := newSim(t)
	s.feed(idleLoaded, 3, on3, true)
	if s.m.Held() != "WHILE_PAUSED" {
		t.Fatalf("%q", s.m.Held())
	}
	s.m.HoldUntilClear(HoldAfterStop)
	if s.m.Held() != "AFTER_STOP" {
		t.Fatalf("%q", s.m.Held())
	}
	s.m.HoldUntilClear(HoldAfterStopOnPC)
	if s.m.Held() != "AFTER_STOP_ON_PC" {
		t.Fatalf("%q", s.m.Held())
	}
}
