package desktop

// USB scanners on the list: only those present, named by Windows, probed
// again after 5 minutes, and, when they cannot be used, why. The system
// calls are the package variables findUSB, openUSB, attachedUSB and
// browseMDNS, replaced here.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/escl"
	"github.com/sallyerp/sally-print-agent/internal/mdns"
	"github.com/sallyerp/sally-print-agent/internal/usbscan"
)

const (
	n4000PI0  = `\\?\USB#VID_03F0&PID_5C05&PI_00#6&2df78daf&0&c000#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
	n4000PI1  = `\\?\USB#VID_03F0&PID_5C05&PI_01#6&2df78daf&0&c001#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
	n4000Name = "HP ScanJet Pro N4000 snw1"
	usbUUID   = "5c05aaaa-1111-4222-8333-444455556666"
)

// What an interface does when opened.
const (
	answers     = "answers"
	refusesOpen = "refuses-open"
	refusesRead = "refuses-read"
	isGone      = "gone"
	failsRead   = "fails-read"
)

// fakeUSB stands in for Windows: the interfaces it lists, what each does,
// and which were opened, in order.
type fakeUSB struct {
	mu       sync.Mutex
	paths    []usbscan.Path
	findErr  error
	do       map[string]string
	uuid     string // in the capabilities; "" for none
	attached bool
	opened   []string
}

func installUSB(t *testing.T, u *fakeUSB) *fakeUSB {
	t.Helper()
	oldFind, oldOpen, oldAttached, oldBrowse := findUSB, openUSB, attachedUSB, browseMDNS
	t.Cleanup(func() { findUSB, openUSB, attachedUSB, browseMDNS = oldFind, oldOpen, oldAttached, oldBrowse })
	findUSB = func() ([]usbscan.Path, error) {
		u.mu.Lock()
		defer u.mu.Unlock()
		return append([]usbscan.Path(nil), u.paths...), u.findErr
	}
	openUSB = func(p string) (escl.Port, error) {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.opened = append(u.opened, p)
		switch u.do[p] {
		case answers:
			return &capsPort{uuid: u.uuid}, nil
		case refusesRead:
			return &refusedPort{}, nil
		case failsRead:
			return failedPort{}, nil
		case refusesOpen:
			return nil, fmt.Errorf("usbscan: opening the scanner: %w", fs.ErrPermission)
		}
		return nil, fmt.Errorf("usbscan: opening the scanner: %w", fs.ErrNotExist)
	}
	attachedUSB = func(string) bool {
		u.mu.Lock()
		defer u.mu.Unlock()
		return u.attached
	}
	browseMDNS = func(context.Context, time.Duration) ([]mdns.Service, error) { return nil, nil }
	return u
}

func (u *fakeUSB) set(fn func(u *fakeUSB)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fn(u)
}

func (u *fakeUSB) openedNow() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.opened...)
}

func n4000(pi0, pi1 string) *fakeUSB {
	return &fakeUSB{
		paths: []usbscan.Path{{Path: n4000PI0, Name: n4000Name}, {Path: n4000PI1, Name: n4000Name}},
		do:    map[string]string{n4000PI0: pi0, n4000PI1: pi1},
		uuid:  usbUUID,
	}
}

// capsPort answers GET …/ScannerCapabilities, without a MakeAndModel.
type capsPort struct {
	uuid    string
	pending []byte
}

func (p *capsPort) Write(b []byte) (int, error) {
	if strings.HasPrefix(string(b), "GET /eSCL/ScannerCapabilities ") {
		body := `<scan:ScannerCapabilities xmlns:scan="` + escl.NSScan + `" xmlns:pwg="` + escl.NSPWG + `"><pwg:Version>2.9</pwg:Version>`
		if p.uuid != "" {
			body += "<scan:UUID>" + p.uuid + "</scan:UUID>"
		}
		body += `</scan:ScannerCapabilities>`
		p.pending = append(p.pending, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", len(body), body)...)
	}
	return len(b), nil
}

func (p *capsPort) ReadTimeout(b []byte, _ time.Duration) (int, error) {
	if len(p.pending) == 0 {
		return 0, escl.ErrTimeout
	}
	n := copy(b, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

func (p *capsPort) Close() error { return nil }

// refusedPort opens, but its first read fails at once: Windows holds the
// channel.
type refusedPort struct{}

func (refusedPort) Write(b []byte) (int, error) { return len(b), nil }
func (refusedPort) ReadTimeout([]byte, time.Duration) (int, error) {
	return 0, fmt.Errorf("usbscan: read: %w", fs.ErrPermission)
}
func (refusedPort) Close() error { return nil }

func quiet(string, ...any) {}

func TestLookUSBTriesEachInterfaceAndNamesTheDeviceAsWindowsDoes(t *testing.T) {
	u := installUSB(t, n4000(refusesRead, answers))
	got := lookUSB(context.Background(), Skip{Cache: &ProbeCache{}}, time.Now(), quiet)
	if len(got) != 1 || !got[0].answering || got[0].reason != "" || got[0].name != n4000Name {
		t.Fatalf("%+v", got)
	}
	if o := u.openedNow(); len(o) != 2 || o[0] != n4000PI0 || o[1] != n4000PI1 {
		t.Fatalf("opened %v", o)
	}
	found := mergeSightings(got, nil)
	if len(found) != 1 || found[0].Name != n4000Name || found[0].ID != ScannerID("uuid:"+usbUUID) {
		t.Fatalf("%+v", found)
	}
}

func TestAUSBScannerWindowsHoldsIsListedWithTheReasonAndNotReopenedForAWhile(t *testing.T) {
	u := installUSB(t, n4000(refusesOpen, refusesRead))
	cache := &ProbeCache{}
	t0 := time.Now()
	found := Look(context.Background(), "", Skip{Cache: cache}, nil, quiet)
	if len(found) != 1 || found[0].Answering || found[0].Reason != ReasonWindows || found[0].Name != n4000Name {
		t.Fatalf("%+v", found)
	}
	if len(u.openedNow()) != 2 {
		t.Fatalf("opened %v", u.openedNow())
	}
	got := lookUSB(context.Background(), Skip{Cache: cache}, t0.Add(time.Minute), quiet)
	if len(u.openedNow()) != 2 {
		t.Fatalf("a minute later it was opened again: %v", u.openedNow())
	}
	if len(got) != 1 || got[0].answering || got[0].reason != ReasonWindows {
		t.Fatalf("%+v", got)
	}
}

func TestUSBProbesExpireAndADeviceThatComesBackIsProbedAtOnce(t *testing.T) {
	u := installUSB(t, n4000(refusesRead, refusesRead))
	cache := &ProbeCache{}
	t0 := time.Now()
	ctx := context.Background()
	lookUSB(ctx, Skip{Cache: cache}, t0, quiet)
	u.set(func(u *fakeUSB) { u.paths = nil })
	lookUSB(ctx, Skip{Cache: cache}, t0.Add(time.Minute), quiet)
	u.set(func(u *fakeUSB) {
		u.paths = []usbscan.Path{{Path: n4000PI0, Name: n4000Name}, {Path: n4000PI1, Name: n4000Name}}
		u.do[n4000PI1] = answers
	})
	got := lookUSB(ctx, Skip{Cache: cache}, t0.Add(2*time.Minute), quiet)
	if len(u.openedNow()) != 4 || len(got) != 1 || !got[0].answering {
		t.Fatalf("a device back on the list must be probed at once: opened %v, %+v", u.openedNow(), got)
	}

	// An answer is kept 5 minutes, then the device is probed again.
	key := usbKeys(usbscan.DeviceKey(n4000PI0)).key
	for _, c := range []struct {
		age    time.Duration
		probed bool
	}{{4 * time.Minute, false}, {6 * time.Minute, true}} {
		u.set(func(u *fakeUSB) { u.opened, u.do[n4000PI1] = nil, refusesRead })
		t1 := time.Now()
		cache.put(key, probe{caps: &escl.Capabilities{UUID: usbUUID}, answering: true, at: t1.Add(-c.age)})
		got := lookUSB(ctx, Skip{Cache: cache}, t1, quiet)
		if probed := len(u.openedNow()) > 0; probed != c.probed {
			t.Fatalf("an answer %v old: probed %v", c.age, probed)
		}
		if c.probed && (got[0].answering || got[0].reason != ReasonWindows) {
			t.Fatalf("%v: %+v", c.age, got[0])
		}
		if !c.probed && !got[0].answering {
			t.Fatalf("%v: %+v", c.age, got[0])
		}
	}
}

func TestOpenFoundUsesTheInterfaceThatAnswers(t *testing.T) {
	for _, c := range []struct {
		name, uuid, id string
	}{
		{"caps UUID", usbUUID, ScannerID("uuid:" + usbUUID)},
		{"no UUID", "", ScannerID("usb:" + usbscan.DeviceKey(n4000PI0))},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := n4000(refusesRead, answers)
			u.uuid = c.uuid
			installUSB(t, u)
			f := Found{ID: c.id, Name: n4000Name, USB: []string{n4000PI0, n4000PI1}}
			s, err := OpenFound(context.Background(), f, quiet)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if s.Kind != "USB" || s.Where != n4000PI1 || s.ID != f.ID || s.Name != n4000Name {
				t.Fatalf("%+v", s)
			}
		})
	}
}

func TestOpenFoundFallsBackToTheNetworkAndSaysWhyUSBFailed(t *testing.T) {
	sc := &fakeScanner{uuid: usbUUID}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	id := ScannerID("uuid:" + usbUUID)
	ctx := context.Background()

	u := installUSB(t, n4000(refusesOpen, refusesRead))
	f := Found{ID: id, Name: n4000Name, USB: []string{n4000PI0, n4000PI1},
		Net: []netBase{{URL: srv.URL, Root: "eSCL", keys: addrKeys(srv.URL)}}}
	s, err := OpenFound(ctx, f, quiet)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s.Kind != "NETWORK" || s.ID != id {
		t.Fatalf("%+v", s)
	}

	f.Net = nil
	_, err = OpenFound(ctx, f, quiet)
	if reasonOf(err) != ReasonWindows || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("%v", err)
	}

	u.set(func(u *fakeUSB) { u.do = map[string]string{} })
	_, err = OpenFound(ctx, f, quiet)
	if reasonOf(err) != ReasonNotFound || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%v", err)
	}
	u.set(func(u *fakeUSB) { u.attached = true })
	if _, err = OpenFound(ctx, f, quiet); reasonOf(err) != ReasonWindows {
		t.Fatalf("plugged in but its interfaces gone: %v", err)
	}
	if reasonOf(errors.New("dial tcp: refused")) != "" || reasonOf(nil) != "" {
		t.Fatal("reasonOf")
	}
}

func TestDiscoverFallsBackToTheTypedAddressWhenWindowsHoldsUSB(t *testing.T) {
	sc := &fakeScanner{uuid: "abcdabcd-0000-4000-8000-00000000000a"}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	u := installUSB(t, n4000(refusesOpen, refusesRead))
	s, err := Discover(context.Background(), strings.TrimPrefix(srv.URL, "http://"), quiet)
	if err != nil || s == nil {
		t.Fatalf("%v %v", s, err)
	}
	s.Close()
	if s.Kind != "NETWORK" {
		t.Fatalf("%+v", s)
	}
	if o := u.openedNow(); len(o) != 2 || o[0] != n4000PI0 || o[1] != n4000PI1 {
		t.Fatalf("both USB interfaces are tried first: %v", o)
	}
}

func TestUSBReasons(t *testing.T) {
	denied := fmt.Errorf("usbscan: read: %w", fs.ErrPermission)
	gone := fmt.Errorf("usbscan: opening the scanner: %w", fs.ErrNotExist)
	timeout := fmt.Errorf("escl: reading the reply: %w", escl.ErrTimeout)
	for _, c := range []struct {
		errs []error
		want string
	}{
		{nil, ""},
		{[]error{gone, gone}, ReasonNotFound},
		{[]error{gone, denied}, ReasonWindows},
		{[]error{timeout, denied}, ReasonWindows},
		{[]error{gone, timeout}, ""},
		{[]error{timeout}, ""},
	} {
		if got := usbReason(c.errs); got != c.want {
			t.Errorf("%v: %q, want %q", c.errs, got, c.want)
		}
	}

	k := usbKeys(usbscan.DeviceKey(n4000PI0))
	s := func(reason string, answering bool) sighting {
		return sighting{keys: k, usb: []string{n4000PI0}, reason: reason, answering: answering}
	}
	for _, c := range []struct {
		in   []sighting
		want string
	}{
		{[]sighting{s(ReasonNotFound, false), s(ReasonWindows, false)}, ReasonWindows},
		{[]sighting{s(ReasonWindows, false), s(ReasonNotFound, false)}, ReasonWindows},
		{[]sighting{s("", false), s(ReasonNotFound, false)}, ReasonNotFound},
		{[]sighting{s(ReasonWindows, false), s("", true)}, ""},
	} {
		got := mergeSightings(c.in, nil)
		if len(got) != 1 || got[0].Reason != c.want {
			t.Errorf("%+v", got)
		}
	}
}

// failedPort opens, but its first read fails at once for a reason that
// says nothing about why.
type failedPort struct{}

func (failedPort) Write(b []byte) (int, error) { return len(b), nil }
func (failedPort) ReadTimeout([]byte, time.Duration) (int, error) {
	return 0, errors.New("usbscan: read: the device did not respond")
}
func (failedPort) Close() error { return nil }
