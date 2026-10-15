package desktop

// What the agent says when a USB scanner cannot be used: on the list, in
// the problem Sally gets, and on the status page, while the network path
// keeps working.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/escl"
	"github.com/sallyerp/sally-print-agent/internal/usbscan"
)

func lookReturning(list *[]Found) Looker {
	return func(context.Context, string, Skip, map[string]string, func(string, ...any)) []Found {
		return append([]Found(nil), (*list)...)
	}
}

func TestAnUnseenUSBOnlyEntryIsNotFoundOrHeldByWindows(t *testing.T) {
	for _, chosen := range []bool{false, true} {
		u := installUSB(t, &fakeUSB{})
		a := newAgent(t, "http://127.0.0.1:1", nil)
		x := Found{ID: ScannerID("x"), Name: n4000Name, USB: []string{n4000PI0, n4000PI1}, Answering: true}
		y := Found{ID: ScannerID("y"), Name: "Network scanner", Net: []netBase{{URL: "http://y"}}, Answering: true}
		z := Found{ID: ScannerID("z"), Name: "Both ways", USB: []string{`\\?\USB#VID_1111&PID_2222&PI_00#1&2&0&0000#{g}`}, Net: []netBase{{URL: "http://z"}}, Answering: true}
		list := []Found{x, y, z}
		a.opt.Look = lookReturning(&list)
		if chosen {
			a.local.ScannerID = x.ID
		}
		ctx := context.Background()
		a.inventoryPass(ctx)
		list = nil
		a.inventoryPass(ctx)
		want := map[string]string{x.ID: ReasonNotFound, y.ID: "", z.ID: ""}
		for id, r := range want {
			if f, ok := a.foundLocked(id); !ok || f.Answering || f.Reason != r {
				t.Fatalf("%+v %v, want reason %q", f, ok, r)
			}
		}
		u.set(func(u *fakeUSB) { u.attached = true })
		a.inventoryPass(ctx)
		if f, _ := a.foundLocked(x.ID); f.Reason != ReasonWindows {
			t.Fatalf("plugged in, interfaces gone: %+v", f)
		}
		a.inventoryPass(ctx)
		if _, ok := a.foundLocked(x.ID); ok != chosen {
			t.Fatalf("chosen %v: listed %v after 3 passes", chosen, ok)
		}
	}
}

func TestAChosenUSBScannerNeverSeenIsNotFoundAfterAPass(t *testing.T) {
	installUSB(t, &fakeUSB{})
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	id := ScannerID("uuid:" + usbUUID)
	a.local.ScannerID, a.local.ScannerName, a.local.ScannerVia = id, n4000Name, []string{"USB"}
	if req, _ := a.report(); req.Scanner.Problem != "" {
		t.Fatalf("no pass yet: %q", req.Scanner.Problem)
	}
	if v := a.Snapshot(); v.LinkReason != "" || v.Scanners[0].Reason != "" {
		t.Fatalf("%+v", v)
	}
	a.inventoryPass(context.Background())
	v := a.Snapshot()
	if v.LinkReason != ReasonNotFound || v.LinkName != n4000Name || len(v.Scanners) != 1 || v.Scanners[0].Reason != ReasonNotFound {
		t.Fatalf("%+v", v)
	}
	notFound := "The chosen scanner is not found on USB. Check that it is plugged in and switched on, unplug it and plug it back in, or choose another scanner."
	if req, _ := a.report(); req.Scanner.Problem != notFound {
		t.Fatalf("%q", req.Scanner.Problem)
	}
	a.problem = "The scanner stopped sending pages."
	if req, _ := a.report(); req.Scanner.Problem != notFound {
		t.Fatalf("a stale problem won: %q", req.Scanner.Problem)
	}
	jam := "Paper jam. Open the cover, take out the stuck sheet and put it back on top of the stack."
	a.problem, a.jamOpen = jam, true
	if req, _ := a.report(); req.Scanner.Problem != jam {
		t.Fatalf("an open jam must win: %q", req.Scanner.Problem)
	}
}

func TestAutomaticNamesAKnownUSBScannerWindowsHolds(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	id := ScannerID("uuid:" + usbUUID)
	a.mergeInventoryLocked([]Found{
		{ID: ScannerID("printer"), Name: "HP LaserJet Example", USB: []string{`\\?\USB#VID_03F0&PID_0001&PI_00#1&2&0&0000#{g}`}, Reason: ReasonWindows},
		{ID: id, Name: n4000Name, USB: []string{n4000PI0, n4000PI1}, Reason: ReasonWindows},
	}, time.Now())
	if r, _ := a.linkLocked(); r != "" {
		t.Fatalf("never answered here: %q", r)
	}
	a.local.KnownScanners = map[string]string{usbKeys(usbscan.DeviceKey(n4000PI1)).key: id}
	v := a.Snapshot()
	if v.LinkReason != ReasonWindows || v.LinkName != n4000Name {
		t.Fatalf("%q %q", v.LinkReason, v.LinkName)
	}
	windows := "Windows is not letting Sally Desktop use the scanner's USB connection. Unplug the scanner and plug it back in, or use it over the network."
	if req, _ := a.report(); req.Scanner.Problem != windows {
		t.Fatalf("%q", req.Scanner.Problem)
	}
	a.scannerOpen = true
	if v := a.Snapshot(); v.LinkReason != "" || v.LinkName != "" {
		t.Fatalf("a scanner is open: %+v", v)
	}
	if req, _ := a.report(); req.Scanner.Problem != "" {
		t.Fatalf("%q", req.Scanner.Problem)
	}
}

func TestOpenChosenMarksTheEntryWhenUSBCannotBeUsed(t *testing.T) {
	installUSB(t, n4000(refusesOpen, refusesRead))
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	id := ScannerID("uuid:" + usbUUID)
	usbKey := usbKeys(usbscan.DeviceKey(n4000PI0)).key
	netKey := addrKeys("127.0.0.1:1").key
	f := Found{ID: id, Name: n4000Name, USB: []string{n4000PI0, n4000PI1},
		Net: []netBase{{URL: "http://127.0.0.1:1", Root: "eSCL", keys: addrKeys("127.0.0.1:1")}}, Answering: true}
	a.mergeInventoryLocked([]Found{f}, time.Now())
	a.local.ScannerID = id
	a.probes.put(usbKey, probe{caps: &escl.Capabilities{UUID: usbUUID}, answering: true, at: time.Now()})
	a.probes.put(netKey, probe{at: time.Now()})
	if sc, _ := a.openChosen(context.Background(), id); sc != nil {
		t.Fatal("opened")
	}
	if g, _ := a.foundLocked(id); g.Answering || g.Reason != ReasonWindows {
		t.Fatalf("%+v", g)
	}
	if c, ok := a.probes.get(usbKey); !ok || c.answering || c.caps != nil || c.reason != ReasonWindows {
		t.Fatalf("the try must replace the cached answer: %+v %v", c, ok)
	}
	if _, ok := a.probes.get(netKey); !ok {
		t.Fatal("a cached failure stays")
	}

	// A network scanner that does not answer: only logged, as before.
	b := pairedAgent(t, "http://127.0.0.1:1", nil)
	n := Found{ID: ScannerID("net"), Name: "Network scanner", Net: f.Net, Answering: true}
	b.mergeInventoryLocked([]Found{n}, time.Now())
	b.local.ScannerID = n.ID
	b.probes.put(netKey, probe{answering: true, at: time.Now()})
	if sc, _ := b.openChosen(context.Background(), n.ID); sc != nil {
		t.Fatal("opened")
	}
	if g, _ := b.foundLocked(n.ID); !g.Answering || g.Reason != "" {
		t.Fatalf("%+v", g)
	}
	if _, ok := b.probes.get(netKey); !ok {
		t.Fatal("the network answer must stay")
	}
}

// 256db17: a chosen scanner that is not on the list is looked for once,
// then waited for the full time; the pass openChosen ran is not news to
// that wait.
func TestAChosenScannerNotOnTheListIsWaitedForTheFullTime(t *testing.T) {
	fs := newFakeSallyAll(t)
	a := pairedAgent(t, fs.srv.URL, nil)
	a.opt.InventoryEvery = time.Hour
	id := ScannerID("uuid:" + usbUUID)
	a.local.ScannerID, a.local.ScannerName, a.local.ScannerVia = id, n4000Name, []string{"USB"}
	var mu sync.Mutex
	calls := 0
	a.opt.Look = func(context.Context, string, Skip, map[string]string, func(string, ...any)) []Found {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil
	}
	run(t, a)
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	n := calls
	mu.Unlock()
	if n > 3 {
		t.Fatalf("%d searches in 1.5 s", n)
	}
	req, _ := a.report()
	if req.Scanner.Kind != "USB" || req.Scanner.ID != id || req.Scanner.State != "OFFLINE" {
		t.Fatalf("%+v", req.Scanner)
	}
}
