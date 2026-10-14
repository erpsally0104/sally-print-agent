package desktop

// The jam words after a Stop reach Sally whole, and a chosen scanner that
// has not been seen keeps the stability it was last reported with.

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTheJamWordsAfterAStopReachSallyWhole(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	for _, n := range []int{1, 7, 12, 150} {
		a.problem = fmt.Sprintf("Paper jam. Open the cover, take out the stuck sheet and put it back on top of the stack, then press Scan now to scan the rest. "+
			"Sally kept the %d %s already scanned and sets aside anything scanned twice.", n, plural(n, "sheet", "sheets"))
		req, _ := a.report()
		p := req.Scanner.Problem
		if utf8.RuneCountInString(p) > 200 || !strings.HasSuffix(p, ".") {
			t.Errorf("n=%d: Sally gets %q", n, p[len(p)-40:])
		}
	}
}

func TestAChosenScannerNotSeenKeepsItsStability(t *testing.T) {
	a := pairedAgent(t, "http://127.0.0.1:1", nil)
	id := ScannerID("usb:vid_03f0&pid_5c05#6&1a2b3c4d&0")
	a.mergeInventoryLocked([]Found{{ID: id, Name: "USB scanner", USB: []string{`\?\usb#x`}, Answering: true, Stable: false}}, time.Now())
	if err := a.SelectScanner(id); err != nil {
		t.Fatal(err)
	}
	// After a restart the list is empty until the scanner is seen again.
	b, err := New(Options{Dir: a.opt.Dir, BaseURL: "http://127.0.0.1:1", Version: "x", Scanning: true, Look: noLook})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := b.report()
	if len(req.Scanners) != 1 || req.Scanners[0].ID != id || req.Scanners[0].Stable {
		t.Errorf("the chosen last-resort scanner is reported stable: %+v", req.Scanners)
	}
}
