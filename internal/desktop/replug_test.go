package desktop

// What the list says after the unplug and replug the agent advises, and
// about the other entries of a device: the open scanner's twins, and the
// entries that are not chosen.

import (
	"context"
	"testing"

	"github.com/sallyerp/sally-print-agent/internal/usbscan"
)

// Windows refuses the chosen scanner, it is unplugged, and the open fails
// while it is out: once it is back and answering, the next pass probes it
// at once instead of reusing that failed try.
func TestAScannerReplugAfterARefusedOpenIsProbedAtOnce(t *testing.T) {
	u := installUSB(t, n4000(refusesRead, refusesRead))
	u.uuid = "" // answers under its last-resort id
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	a.opt.Look = Look
	ctx := context.Background()
	a.inventoryPass(ctx)
	id := ScannerID(usbKeys(usbscan.DeviceKey(n4000PI0)).key)
	if f, ok := a.foundLocked(id); !ok || f.Answering || f.Reason != ReasonWindows {
		t.Fatalf("%+v %v", f, ok)
	}
	a.local.ScannerID = id

	paths := u.paths
	u.set(func(u *fakeUSB) { u.paths = nil })
	a.inventoryPass(ctx) // unplugged: its probe is dropped
	if sc, _ := a.openChosen(ctx, id); sc != nil {
		t.Fatal("opened")
	}
	u.set(func(u *fakeUSB) {
		u.paths = paths
		u.do = map[string]string{n4000PI0: answers, n4000PI1: answers}
	})
	opened := len(u.openedNow())
	a.inventoryPass(ctx)
	if n := len(u.openedNow()); n == opened {
		t.Fatal("the device back on the list was not probed")
	}
	if f, ok := a.foundLocked(id); !ok || !f.Answering || f.Reason != "" {
		t.Fatalf("back: %+v %v", f, ok)
	}
}
