package desktop

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sallyerp/sally-print-agent/internal/escl"
)

func TestNormaliseUUID(t *testing.T) {
	const want = "0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9"
	for _, in := range []string{
		"0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9",
		" urn:uuid:0E1D2C3B-4A59-6877-8695-A4B3C2D1E0F9 ",
		"{0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9}",
		"0E1D2C3B4A5968778695A4B3C2D1E0F9",
	} {
		if got := NormaliseUUID(in); got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
	for _, junk := range []string{"", "unknown", "0e1d2c3b-4a59-6877-8695", "zz1d2c3b-4a59-6877-8695-a4b3c2d1e0f9", "<x>"} {
		if got := NormaliseUUID(junk); got != "" {
			t.Errorf("%q → %q", junk, got)
		}
	}
}

func TestScannerIDFormatAndStability(t *testing.T) {
	re := regexp.MustCompile(`^sc-[0-9a-f]{20}$`)
	id := ScannerID("uuid:0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9")
	if !re.MatchString(id) || id != ScannerID("uuid:0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9") || !ValidScannerID(id) {
		t.Fatalf("%q", id)
	}
	if ScannerID("a") == ScannerID("b") {
		t.Fatal("two keys, one id")
	}
}

func TestIdentifyKeyOrder(t *testing.T) {
	const u = "0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9"
	usb := usbKeys("vid_03f0&pid_5c05#6&1a2b3c4d&0")
	net := mdnsKeys("Desk Scanner [0A0B0C]", "desk-scanner.local.")
	full := &escl.Capabilities{UUID: strings.ToUpper(u), SerialNumber: "SN-TEST-1", MakeAndModel: "Example Scan 4000"}
	serialOnly := &escl.Capabilities{SerialNumber: "SN-TEST-1", MakeAndModel: "Example Scan 4000"}

	// (a) beats (b).
	if id, stable, fromCaps := identify(full, "", usb, nil); id != ScannerID("uuid:"+u) || !stable || !fromCaps {
		t.Fatalf("caps uuid: %s %v %v", id, stable, fromCaps)
	}
	// One serial over USB and over the network gives one id, even with a TXT
	// UUID on the network sighting.
	a, _, _ := identify(serialOnly, "", usb, nil)
	b, _, _ := identify(serialOnly, "11111111-2222-3333-4444-555555555555", net, nil)
	if a != b || a != ScannerID("sn:example scan 4000/SN-TEST-1") {
		t.Fatalf("serial ids %s %s", a, b)
	}
	// A TXT UUID equal to the caps UUID gives the same id with no caps.
	if c, stable, _ := identify(nil, "urn:uuid:"+u, net, nil); c != ScannerID("uuid:"+u) || !stable {
		t.Fatalf("txt uuid %s", c)
	}
	// Caps that stop answering keep the remembered id.
	known := map[string]string{net.key: a}
	if d, stable, fromCaps := identify(nil, "", net, known); d != a || !stable || fromCaps {
		t.Fatalf("remembered %s %v %v", d, stable, fromCaps)
	}
	// Unusable serials and no UUID: the last resort, not stable.
	for _, k := range []sightingKeys{usb, net, addrKeys("192.168.1.20")} {
		for _, sn := range []string{"", "0", "Unknown", strings.Repeat("x", 65), "bad\x01"} {
			id, stable, _ := identify(&escl.Capabilities{SerialNumber: sn, MakeAndModel: "M"}, "", k, nil)
			if stable || id != ScannerID(k.last) {
				t.Fatalf("%q %q: %s %v", k.last, sn, id, stable)
			}
		}
	}
	if usb.last != "usb:vid_03f0&pid_5c05#6&1a2b3c4d&0" || net.last != "mdns:desk scanner [0a0b0c]" || addrKeys(" Scanner.LAN ").last != "addr:scanner.lan" {
		t.Fatalf("last-resort keys %q %q", usb.last, net.last)
	}
}

func TestOneDeviceOverUSBAndBothNetworkRecordsIsOneEntry(t *testing.T) {
	caps := &escl.Capabilities{UUID: "0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9", MakeAndModel: "Example Scan 4000", Feeder: true}
	k := mdnsKeys("Example Scan 4000 [0A0B0C]", "example.local.")
	sights := []sighting{
		{keys: usbKeys("vid_1#a"), caps: caps, answering: true, usb: []string{`\\?\usb#vid_1&pi_00#a&0#{x}`, `\\?\usb#vid_1&pi_01#a&1#{x}`}, devKey: "vid_1#a"},
		{keys: k, label: "Example Scan 4000 [0A0B0C]", caps: caps, answering: true, mdns: true,
			net: []netBase{{URL: "http://192.168.1.41:80", Root: "eSCL", keys: k}, {URL: "https://192.168.1.41:443", Root: "eSCL", keys: k}}},
	}
	fs := mergeSightings(sights, nil)
	if len(fs) != 1 {
		t.Fatalf("%d entries: %+v", len(fs), fs)
	}
	f := fs[0]
	if v := f.Via(); len(v) != 2 || v[0] != "USB" || v[1] != "NETWORK" {
		t.Fatalf("via %v", v)
	}
	if !f.Answering || !f.Stable || f.Feeder == nil || !*f.Feeder || f.Name != "Example Scan 4000" || f.Detail != "Example Scan 4000 [0A0B0C]" {
		t.Fatalf("%+v", f)
	}
	if len(f.learned) != 2 {
		t.Fatalf("learned %v", f.learned)
	}
}

func TestTwoUSBScannersWithOneNameAreNumbered(t *testing.T) {
	mk := func(uuid, dev string) sighting {
		return sighting{keys: usbKeys(dev), caps: &escl.Capabilities{UUID: uuid, MakeAndModel: "Example Scan 4000"}, answering: true, usb: []string{dev}, devKey: dev}
	}
	fs := mergeSightings([]sighting{
		mk("22222222-2222-2222-2222-222222222222", "vid_1#b"),
		mk("11111111-1111-1111-1111-111111111111", "vid_1#a"),
	}, nil)
	if len(fs) != 2 || fs[0].Detail != "USB 2" || fs[1].Detail != "USB 1" {
		t.Fatalf("%+v", fs)
	}
}

func TestNamesAndDetailsAreCutOnRuneBoundariesAndNeverAnAddress(t *testing.T) {
	long := strings.Repeat("é", 130)
	fs := mergeSightings([]sighting{{keys: mdnsKeys("x", "h"), name: long, label: strings.Repeat("ü", 90), mdns: true, net: []netBase{{URL: "http://h"}}}}, nil)
	if utf8.RuneCountInString(fs[0].Name) != 120 || !utf8.ValidString(fs[0].Name) {
		t.Fatalf("name %d runes", utf8.RuneCountInString(fs[0].Name))
	}
	if utf8.RuneCountInString(fs[0].Detail) != 80 || !utf8.ValidString(fs[0].Detail) {
		t.Fatalf("detail %d runes", utf8.RuneCountInString(fs[0].Detail))
	}
	for _, bad := range []string{"192.168.1.20", "Scanner at 10.0.0.5", "http://scanner", `\\?\usb#vid`, "fe80::1:2", "C:/scans"} {
		if safeDetail(bad) != "" {
			t.Errorf("%q was kept", bad)
		}
	}
	for _, ok := range []string{"Front desk [0A0B0C]", "USB 2", "Accounts: upstairs"} {
		if safeDetail(ok) != ok {
			t.Errorf("%q was dropped", ok)
		}
	}
}

func TestTheListSendsSixteenKeepingTheChosenAndTheOlderOnes(t *testing.T) {
	a := newAgent(t, "http://127.0.0.1:1", nil)
	t0 := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	var older []Found
	for i := 0; i < 4; i++ {
		older = append(older, Found{ID: ScannerID(fmt.Sprint("old", i)), Name: fmt.Sprintf("Zed %d", i), Net: []netBase{{URL: "http://x"}}, Answering: true})
	}
	a.mergeInventoryLocked(older, t0)
	// A burst of 36 new adverts, one of them chosen.
	burst := append([]Found(nil), older...)
	for i := 0; i < 36; i++ {
		burst = append(burst, Found{ID: ScannerID(fmt.Sprint("new", i)), Name: fmt.Sprintf("Aardvark %02d", i), Net: []netBase{{URL: "http://y"}}, Answering: true})
	}
	chosen := ScannerID("new35")
	a.local.ScannerID = chosen
	a.mergeInventoryLocked(burst, t0.Add(time.Minute))
	got := a.scannersLocked()
	if len(got) != 16 {
		t.Fatalf("%d sent", len(got))
	}
	if got[0].ID != chosen {
		t.Fatalf("the chosen scanner must lead: %+v", got[0])
	}
	for i := 0; i < 4; i++ {
		if got[1+i].ID != older[i].ID {
			t.Fatalf("earlier-seen scanners must come before the burst: %d %+v", i, got[1+i])
		}
	}
	// A chosen scanner never seen is still listed, not answering.
	a.local.ScannerID, a.local.ScannerName = ScannerID("gone"), "Back office scanner"
	got = a.scannersLocked()
	if got[0].ID != ScannerID("gone") || got[0].Answering || got[0].Name != "Back office scanner" || len(got[0].Via) != 1 {
		t.Fatalf("%+v", got[0])
	}
}

func TestAnEntryUnseenForThreePassesIsDroppedUnlessChosen(t *testing.T) {
	a := newAgent(t, "http://127.0.0.1:1", nil)
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	x := Found{ID: ScannerID("x"), Name: "X", Net: []netBase{{URL: "http://x"}}, Answering: true}
	y := Found{ID: ScannerID("y"), Name: "Y", Net: []netBase{{URL: "http://y"}}, Answering: true}
	a.mergeInventoryLocked([]Found{x, y}, now)
	a.local.ScannerID = y.ID
	for i := 1; i <= 3; i++ {
		a.mergeInventoryLocked(nil, now.Add(time.Duration(i)*time.Minute))
	}
	if _, ok := a.foundLocked(x.ID); ok {
		t.Fatal("x should be gone")
	}
	if f, ok := a.foundLocked(y.ID); !ok || f.Answering {
		t.Fatalf("the chosen y stays, not answering: %+v %v", f, ok)
	}
}
