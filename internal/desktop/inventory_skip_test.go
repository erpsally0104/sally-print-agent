package desktop

// The inventory must read openSkip only once it holds lookMu. Read before
// the wait, a pass that waited while the scanner loop opened a scanner
// would probe that scanner with a skip that names nothing.

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestTheInventoryReadsItsSkipAfterTheOpen(t *testing.T) {
	sc := &fakeScanner{pages: 4}
	scSrv := httptest.NewServer(sc)
	defer scSrv.Close()
	fs := newFakeSallyAll(t)

	inDiscover := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	disc := func(ctx context.Context, _ string, _ func(string, ...any)) (*Scanner, error) {
		once.Do(func() { close(inDiscover) })
		<-release // the automatic pick is still probing
		return openBase(ctx, scSrv.URL, "eSCL", "")
	}
	a := pairedAgent(t, fs.srv.URL, disc)
	a.opt.InventoryEvery = time.Hour

	type call struct {
		skip     Skip
		openNow  bool
		openSkip Skip
	}
	var mu sync.Mutex
	var calls []call
	a.opt.Look = func(ctx context.Context, _ string, s Skip, _ map[string]string, _ func(string, ...any)) []Found {
		time.Sleep(200 * time.Millisecond) // a real Look browses mDNS for 2 s, then probes
		a.mu.Lock()
		c := call{skip: s, openNow: a.scannerOpen, openSkip: a.openSkip}
		a.mu.Unlock()
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		return nil
	}
	run(t, a)
	<-inDiscover // the scanner loop holds lookMu
	time.Sleep(300 * time.Millisecond)
	a.LookAgain() // a pass starting now copies openSkip (empty) and waits for lookMu
	time.Sleep(300 * time.Millisecond)
	close(release)
	waitFor(t, "the scanner", func() bool { return a.Snapshot().ScannerID != "" })
	time.Sleep(800 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	stale := 0
	for i, c := range calls {
		t.Logf("look %d: skip.Bases=%v skip.USBKey=%q scannerOpen=%v openSkip.Bases=%v", i, c.skip.Bases, c.skip.USBKey, c.openNow, c.openSkip.Bases)
		if c.openNow && len(c.skip.Bases) == 0 && c.skip.USBKey == "" {
			stale++
		}
	}
	if stale > 0 {
		t.Errorf("%d inventory Look(s) ran while the scanner was open, with a skip that names nothing", stale)
	}
}
