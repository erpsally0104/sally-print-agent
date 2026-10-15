package desktop

// How a pass judges the entries it did not see: only what the Look looked
// for, by whether its USB device is listed, and never undoing what
// openChosen says.

import (
	"context"
	"testing"

	"github.com/sallyerp/sally-print-agent/internal/usbscan"
)

// A chosen last-resort id gives way to the capabilities' UUID once the
// scanner answers after a replug: the stale entry's device is listed, so it
// is neither held by Windows nor not found.
func TestAChosenLastResortIDThatNowAnswersUnderItsUUIDIsNotHeldByWindows(t *testing.T) {
	u := installUSB(t, n4000(refusesRead, refusesRead))
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.opt.Look = Look
	ctx := context.Background()
	a.inventoryPass(ctx)
	stale := ScannerID(usbKeys(usbscan.DeviceKey(n4000PI0)).key)
	if f, ok := a.foundLocked(stale); !ok || f.Stable || f.Answering {
		t.Fatalf("%+v %v", f, ok)
	}
	a.local.ScannerID = stale

	paths := u.paths
	u.set(func(u *fakeUSB) { u.paths = nil })
	a.inventoryPass(ctx) // unplugged
	if f, _ := a.foundLocked(stale); f.Reason != ReasonNotFound {
		t.Fatalf("unplugged: %+v", f)
	}
	u.set(func(u *fakeUSB) {
		u.paths, u.attached = paths, true
		u.do = map[string]string{n4000PI0: answers, n4000PI1: answers}
	})
	for i := 0; i < 2; i++ {
		a.inventoryPass(ctx)
		if f, ok := a.foundLocked(ScannerID("uuid:" + usbUUID)); !ok || !f.Answering {
			t.Fatalf("the UUID entry: %+v %v", f, ok)
		}
		if f, ok := a.foundLocked(stale); !ok || f.Answering || f.Reason != "" {
			t.Fatalf("pass %d: %+v %v", i, f, ok)
		}
		if req, _ := a.report(); req.Scanner.Problem != "" {
			t.Fatalf("pass %d: %q", i, req.Scanner.Problem)
		}
		if sc := a.openChosen(ctx, stale); sc != nil {
			t.Fatal("opened another scanner")
		}
		if f, _ := a.foundLocked(stale); f.Reason != "" {
			t.Fatalf("openChosen %d: %+v", i, f)
		}
	}

	// Windows refuses the channel again once the answer is old: the device
	// is listed under its UUID, and the stale entry says what its probe
	// said, as openChosen does.
	u.set(func(u *fakeUSB) { u.do = map[string]string{n4000PI0: refusesRead, n4000PI1: refusesRead} })
	a.probes.forgetAnswer(usbKeys(usbscan.DeviceKey(n4000PI0)).key)
	for i := 0; i < 2; i++ {
		a.inventoryPass(ctx)
		if f, _ := a.foundLocked(stale); f.Answering || f.Reason != ReasonWindows {
			t.Fatalf("refused, pass %d: %+v", i, f)
		}
		if sc := a.openChosen(ctx, stale); sc != nil {
			t.Fatal("opened")
		}
		if f, _ := a.foundLocked(stale); f.Reason != ReasonWindows {
			t.Fatalf("refused, openChosen %d: %+v", i, f)
		}
	}
}

// The open USB scanner closes while a pass is in its Look, which left the
// device alone: the merge must not judge it.
func TestAPassDoesNotJudgeTheDeviceItsLookSkipped(t *testing.T) {
	for _, chosen := range []bool{true, false} {
		installUSB(t, n4000(answers, answers)).set(func(u *fakeUSB) { u.attached = true })
		a := pairedAgent(t, "http://127.0.0.1:1", nil)
		a.opt.Look = Look
		ctx := context.Background()
		a.inventoryPass(ctx)
		id := ScannerID("uuid:" + usbUUID)
		f, ok := a.foundLocked(id)
		if !ok {
			t.Fatal("not listed")
		}
		if chosen {
			a.local.ScannerID = id
		}
		a.local.KnownScanners = map[string]string{usbKeys(usbscan.DeviceKey(n4000PI0)).key: id}
		sc, err := OpenFound(ctx, f, a.logf)
		if err != nil {
			t.Fatal(err)
		}
		a.mu.Lock()
		a.openedLocked(sc)
		a.mu.Unlock()
		a.opt.Look = func(ctx context.Context, addr string, s Skip, known map[string]string, logf func(string, ...any)) []Found {
			found := Look(ctx, addr, s, known, logf)
			a.mu.Lock()
			a.scannerOpen, a.inUse, a.openSkip = false, nil, Skip{}
			a.mu.Unlock()
			return found
		}
		a.inventoryPass(ctx)
		if g, _ := a.foundLocked(id); !g.Answering || g.Reason != "" || g.Misses != 0 {
			t.Fatalf("chosen %v: %+v", chosen, g)
		}
		if req, _ := a.report(); req.Scanner.Problem != "" {
			t.Fatalf("chosen %v: %q", chosen, req.Scanner.Problem)
		}
		sc.Close()
	}
}

// A chosen scanner reached by USB and the network is switched off: the
// passes keep the reason openChosen gives it.
func TestAPassKeepsTheReasonOfAChosenScannerAlsoOnTheNetwork(t *testing.T) {
	installUSB(t, &fakeUSB{})
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	id := ScannerID("uuid:" + usbUUID)
	f := Found{ID: id, Name: n4000Name, USB: []string{n4000PI0, n4000PI1},
		Net: []netBase{{URL: "http://127.0.0.1:1", Root: "eSCL", keys: addrKeys("127.0.0.1:1")}}, Answering: true}
	list := []Found{f}
	a.opt.Look = lookReturning(&list)
	a.local.ScannerID = id
	ctx := context.Background()
	a.inventoryPass(ctx)
	list = nil // switched off
	a.inventoryPass(ctx)
	notFound := linkProblem[ReasonNotFound]
	for i := 0; i < 2; i++ {
		if sc := a.openChosen(ctx, id); sc != nil {
			t.Fatal("opened")
		}
		a.inventoryPass(ctx)
		if g, _ := a.foundLocked(id); g.Answering || g.Reason != ReasonNotFound {
			t.Fatalf("round %d: %+v", i, g)
		}
		if req, _ := a.report(); req.Scanner.Problem != notFound {
			t.Fatalf("round %d: %q", i, req.Scanner.Problem)
		}
	}
}
