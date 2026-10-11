package outbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/sally"
)

// xorSealer stands in for DPAPI: it must change the bytes, so a test can
// prove nothing is stored as plain JPEG.
type xorSealer struct{}

func (xorSealer) Seal(b []byte) ([]byte, error) { return xor(b), nil }
func (xorSealer) Open(b []byte) ([]byte, error) { return xor(b), nil }
func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5A
	}
	return out
}

// page makes JPEG-ish bytes: the start-of-image marker and noise. Never a
// real JPEG, which is the point: the agent must not decode anything.
func page(i int) []byte {
	b := make([]byte, 2000+i*37)
	for j := range b {
		b[j] = byte(i*31 + j*7)
	}
	b[0], b[1] = 0xFF, 0xD8
	return b
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, xorSealer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetOwner("co-1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSafeOnlyWhenEverySideIsOnDisk(t *testing.T) {
	s := openStore(t, t.TempDir())
	w, err := s.NewStack(true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Add(page(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Five sides on disk but the stack is still scanning: nothing may say
	// "safe" yet, and the uploader must not see it.
	if len(s.Stacks()) != 0 {
		t.Fatal("an unfinished stack must not be offered for upload")
	}
	r, err := w.Finish("")
	if err != nil || !r.Safe {
		t.Fatalf("finish: %+v %v", r, err)
	}
	if r.Sheets != 3 || r.Sides != 5 {
		t.Fatalf("sheets %d sides %d", r.Sheets, r.Sides)
	}
	if r.Message() != "Got 3 sheets. Safe on this PC." {
		t.Fatalf("message %q", r.Message())
	}
	// Stored sealed, never as the plain page.
	raw, _ := os.ReadFile(filepath.Join(s.Dir(), r.Stack, "sheet-001-side-1.page"))
	if bytes.Equal(raw, page(0)) {
		t.Fatal("page stored in the clear")
	}
	got, err := s.ReadSide(r.Stack, 1, 1)
	if err != nil || !bytes.Equal(got, page(0)) {
		t.Fatal("round trip failed")
	}
}

type failingSealer struct{ after, n int }

func (f *failingSealer) Seal(b []byte) ([]byte, error) {
	f.n++
	if f.n > f.after {
		return nil, errors.New("disk full")
	}
	return b, nil
}
func (f *failingSealer) Open(b []byte) ([]byte, error) { return b, nil }

func TestNotSafeWhenASideFailedToWrite(t *testing.T) {
	s, err := Open(t.TempDir(), &failingSealer{after: 2})
	if err != nil {
		t.Fatal(err)
	}
	s.SetOwner("co-1", "dev-1")
	w, _ := s.NewStack(true)
	w.Add(page(0))
	w.Add(page(1))
	if err := w.Add(page(2)); err == nil {
		t.Fatal("the third write should fail")
	}
	r, err := w.Finish("")
	if err == nil || r.Safe || r.Message() != "" {
		t.Fatalf("must not say safe after a failed write: %+v %v", r, err)
	}
	// What did reach the disk still goes up.
	if len(s.Stacks()) != 1 || len(s.Stacks()[0].Sides) != 2 {
		t.Fatal("the two written sides should still be queued")
	}
}

func TestNotSafeWhenAFileVanished(t *testing.T) {
	s := openStore(t, t.TempDir())
	w, _ := s.NewStack(true)
	w.Add(page(0))
	os.Remove(filepath.Join(s.Dir(), w.ID(), "sheet-001-side-1.page"))
	if r, err := w.Finish(""); err == nil || r.Safe {
		t.Fatal("a missing file must not be called safe")
	}
}

func TestRejectsNonJPEGAndEmptyStacksVanish(t *testing.T) {
	s := openStore(t, t.TempDir())
	w, _ := s.NewStack(true)
	if err := w.Add([]byte("%PDF-1.7")); err == nil {
		t.Fatal("a non-JPEG must be refused")
	}
	s2 := openStore(t, t.TempDir())
	w2, _ := s2.NewStack(true)
	r, err := w2.Finish("")
	if err != nil || r.Sides != 0 || r.Message() != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if entries, _ := os.ReadDir(s2.Dir()); len(entries) != 0 {
		t.Fatal("an empty stack should leave nothing behind")
	}
}

func TestManifestShapeAndResumeAfterRestart(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	w, _ := s.NewStack(true)
	w.Add(page(0))
	w.Add(page(1))
	w.Add(page(2))
	// The agent dies mid-scan: no Finish.

	s2 := openStore(t, dir)
	st := s2.Stacks()
	if len(st) != 1 {
		t.Fatalf("restarted outbox has %d stacks", len(st))
	}
	m := st[0]
	if !m.Complete || m.Problem == "" || m.Sheets != 2 || len(m.Sides) != 3 {
		t.Fatalf("%+v", m)
	}
	sum := sha256.Sum256(page(1))
	sd := m.Sides[1]
	if sd.Sheet != 1 || sd.Side != 2 || sd.SHA256 != hex.EncodeToString(sum[:]) || sd.Size != int64(len(page(1))) || sd.State != Pending || sd.File == "" {
		t.Fatalf("side %+v", sd)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, m.Stack, "manifest.json"))
	for _, k := range []string{`"stack"`, `"created"`, `"sheets"`, `"sha256"`, `"size"`, `"file"`, `"state"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("manifest lacks %s", k)
		}
	}
}

// fakeSally plays Sally and S3.
type fakeSally struct {
	t        *testing.T
	mu       sync.Mutex
	runs     map[string]string // stack → runId
	stored   map[string][]byte // "run/sheet/side" → bytes confirmed
	inS3     map[string][]byte // ticket → bytes
	declared map[string]sally.SideDecl
	done     map[string]int
	puts     int32
	inFlight int32
	maxPar   int32
	failPuts int32 // fail this many PUTs with 500
	announce int
	// refuse answers announcing these stacks with this status.
	refuse map[string]int
	// badHash answers every side of these runs 422.
	badHash map[string]bool
	srv     *httptest.Server
}

func newFakeSally(t *testing.T) *fakeSally {
	f := &fakeSally{t: t, runs: map[string]string{}, stored: map[string][]byte{}, inS3: map[string][]byte{}, declared: map[string]sally.SideDecl{}, done: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSally) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/s3/") {
		n := atomic.AddInt32(&f.inFlight, 1)
		defer atomic.AddInt32(&f.inFlight, -1)
		for {
			m := atomic.LoadInt32(&f.maxPar)
			if n <= m || atomic.CompareAndSwapInt32(&f.maxPar, m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		if r.Header.Get("Content-Type") != "image/jpeg" {
			w.WriteHeader(403)
			return
		}
		if atomic.AddInt32(&f.failPuts, -1) >= 0 {
			w.WriteHeader(500)
			return
		}
		b, _ := io.ReadAll(r.Body)
		atomic.AddInt32(&f.puts, 1)
		f.mu.Lock()
		f.inS3[strings.TrimPrefix(r.URL.Path, "/s3/")] = b
		f.mu.Unlock()
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("x-active-company-id") != "co-1" {
		w.WriteHeader(401)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var in map[string]any
	json.NewDecoder(r.Body).Decode(&in)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/agent/scan/stacks"), "/")
	switch {
	case r.URL.Path == "/api/agent/scan/stacks":
		f.announce++
		stack := in["stack"].(string)
		if code := f.refuse[stack]; code != 0 {
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(map[string]any{"error": "That stack is not yours."})
			return
		}
		run, existed := f.runs[stack]
		if !existed {
			run = "run-" + stack
			f.runs[stack] = run
		}
		received := []map[string]int{}
		for k := range f.stored {
			var sh, sd int
			if _, err := fmt.Sscanf(strings.TrimPrefix(k, run+"/"), "%d/%d", &sh, &sd); err == nil && strings.HasPrefix(k, run+"/") {
				received = append(received, map[string]int{"sheet": sh, "side": sd})
			}
		}
		if existed {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(201)
		}
		json.NewEncoder(w).Encode(map[string]any{"runId": run, "received": received})
	case len(parts) == 3 && parts[2] == "upload-url":
		run := parts[1]
		sides := in["sides"].([]any)
		if len(sides) > 25 {
			w.WriteHeader(400)
			return
		}
		var ups []map[string]any
		for _, x := range sides {
			d := x.(map[string]any)
			sh, sd := int(d["sheet"].(float64)), int(d["side"].(float64))
			ticket := fmt.Sprintf("%s-%d-%d", run, sh, sd)
			f.declared[ticket] = sally.SideDecl{Sheet: sh, Side: sd, SHA256: d["sha256"].(string), Size: int64(d["size"].(float64))}
			ups = append(ups, map[string]any{"sheet": sh, "side": sd, "ticket": ticket, "url": f.srv.URL + "/s3/" + ticket, "method": "PUT", "headers": map[string]string{"Content-Type": "image/jpeg"}})
		}
		json.NewEncoder(w).Encode(map[string]any{"uploads": ups})
	case len(parts) == 3 && parts[2] == "sides":
		run := parts[1]
		if f.badHash[run] {
			w.WriteHeader(422)
			json.NewEncoder(w).Encode(map[string]any{"error": "sha256 mismatch"})
			return
		}
		ticket := in["ticket"].(string)
		b, ok := f.inS3[ticket]
		sum := sha256.Sum256(b)
		if !ok || len(b) < 2 || b[0] != 0xFF || b[1] != 0xD8 || hex.EncodeToString(sum[:]) != in["sha256"] {
			w.WriteHeader(400)
			return
		}
		key := fmt.Sprintf("%s/%d/%d", run, int(in["sheet"].(float64)), int(in["side"].(float64)))
		if _, had := f.stored[key]; had {
			json.NewEncoder(w).Encode(map[string]any{"file": map[string]any{"id": key}, "alreadyHad": true})
			return
		}
		f.stored[key] = b
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"file": map[string]any{"id": key, "status": "UPLOADED"}})
	case len(parts) == 3 && parts[2] == "done":
		f.done[parts[1]]++
		json.NewEncoder(w).Encode(map[string]any{"runId": parts[1], "status": "PROCESSING"})
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeSally) client() *sally.Client {
	c := sally.NewClient(f.srv.URL, "test")
	c.SetAuth("tok", "co-1")
	return c
}

func scanStack(t *testing.T, s *Store, sides int) Receipt {
	t.Helper()
	w, err := s.NewStack(true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sides; i++ {
		if err := w.Add(page(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := w.Finish("")
	if err != nil || !r.Safe {
		t.Fatal(err)
	}
	return r
}

func TestUploadsAStackThreeAtATimeAndDeletesConfirmedCopies(t *testing.T) {
	f := newFakeSally(t)
	s := openStore(t, t.TempDir())
	s.Keep = func() bool { return false }
	r := scanStack(t, s, 60) // more than one upload-url batch of 25

	u := &Uploader{Store: s, API: f.client()}
	if err := u.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	run := "run-" + r.Stack
	if len(f.stored) != 60 || f.done[run] != 1 {
		t.Fatalf("stored %d, done %d", len(f.stored), f.done[run])
	}
	if !bytes.Equal(f.stored[run+"/2/1"], page(2)) {
		t.Fatal("bytes changed on the way up")
	}
	if m := atomic.LoadInt32(&f.maxPar); m > 3 || m < 2 {
		t.Fatalf("max parallel PUTs %d, want 3 at most (and more than one)", m)
	}
	if c := s.Counts(); c.StacksWaiting != 0 || c.SidesWaiting != 0 || c.Last.State != "SENT" {
		t.Fatalf("counts %+v", c)
	}
	s.Clean()
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 0 {
		t.Fatalf("a sent stack with no kept copies should be gone, found %d", len(entries))
	}
}

func TestResumeWhenSallyAlreadyHasSomeSides(t *testing.T) {
	f := newFakeSally(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	r := scanStack(t, s, 10)

	// First attempt: S3 fails after a few PUTs, as a dropped connection would.
	atomic.StoreInt32(&f.failPuts, 0)
	u := &Uploader{Store: s, API: f.client(), Parallel: 1}
	ctx, cancel := context.WithCancel(context.Background())
	var calls int32
	api := &cancelAfter{API: f.client(), n: 4, cancel: cancel, calls: &calls}
	u.API = api
	if err := u.SendAll(ctx); err == nil {
		t.Fatal("the interrupted send should report an error")
	}
	f.mu.Lock()
	had := len(f.stored)
	f.mu.Unlock()
	if had == 0 || had == 10 {
		t.Fatalf("want a partial upload, Sally holds %d", had)
	}

	// Restart: a fresh store from disk, a fresh uploader.
	s2 := openStore(t, dir)
	u2 := &Uploader{Store: s2, API: f.client()}
	before := atomic.LoadInt32(&f.puts)
	if err := u2.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	run := "run-" + r.Stack
	if len(f.stored) != 10 || f.done[run] != 1 {
		t.Fatalf("stored %d done %d", len(f.stored), f.done[run])
	}
	if sent := atomic.LoadInt32(&f.puts) - before; int(sent) != 10-had {
		t.Fatalf("resumed with %d PUTs, want only the %d missing sides", sent, 10-had)
	}
	// Keep is on by default: confirmed copies stay for 7 days.
	if _, err := os.Stat(filepath.Join(dir, r.Stack, "sheet-001-side-1.page")); err != nil {
		t.Fatal("the kept copy should still be there")
	}
	s2.Now = func() time.Time { return time.Now().Add(KeepFor + time.Hour) }
	s2.Clean()
	if _, err := os.Stat(filepath.Join(dir, r.Stack)); !os.IsNotExist(err) {
		t.Fatal("the janitor should remove a sent stack after 7 days")
	}
}

// cancelAfter cancels the context after n confirmed sides.
type cancelAfter struct {
	API
	n      int32
	calls  *int32
	cancel func()
}

func (c *cancelAfter) ConfirmSide(ctx context.Context, run string, sheet, side int, sha, ticket string) error {
	if atomic.AddInt32(c.calls, 1) > c.n {
		c.cancel()
		return context.Canceled
	}
	return c.API.ConfirmSide(ctx, run, sheet, side, sha, ticket)
}

func TestFailedPutIsRetriedLater(t *testing.T) {
	f := newFakeSally(t)
	s := openStore(t, t.TempDir())
	scanStack(t, s, 4)
	atomic.StoreInt32(&f.failPuts, 1)
	u := &Uploader{Store: s, API: f.client()}
	if err := u.SendAll(context.Background()); err == nil {
		t.Fatal("a failed PUT must surface")
	}
	if c := s.Counts(); c.StacksWaiting != 1 {
		t.Fatal("the stack must still be waiting")
	}
	if err := u.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := s.Counts(); c.StacksWaiting != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestCountsWhileSending(t *testing.T) {
	s := openStore(t, t.TempDir())
	r := scanStack(t, s, 6)
	s.MarkConfirmed(r.Stack, 1, 1)
	s.MarkConfirmed(r.Stack, 1, 2)
	c := s.Counts()
	if c.StacksWaiting != 1 || c.SidesWaiting != 4 || c.SendingTotal != 6 || c.SendingSent != 2 || c.Last.State != "SENDING" || c.BytesWaiting == 0 {
		t.Fatalf("%+v", c)
	}
}

func TestARefusedStackDoesNotBlockTheNext(t *testing.T) {
	for _, code := range []int{400, 404, 409} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newFakeSally(t)
			s := openStore(t, t.TempDir())
			now := time.Now()
			s.Now = func() time.Time { return now }
			stuck := scanStack(t, s, 4)
			now = now.Add(time.Minute)
			next := scanStack(t, s, 2)
			f.refuse = map[string]int{stuck.Stack: code}

			var refused []string
			u := &Uploader{Store: s, API: f.client(), OnRefused: func(stack, reason string, _ error) {
				refused = append(refused, stack+": "+reason)
			}}
			if err := u.SendAll(context.Background()); err != nil {
				t.Fatalf("a stack-only refusal must not fail the round: %v", err)
			}
			if f.done["run-"+next.Stack] != 1 {
				t.Fatal("the next stack should have gone up")
			}
			if len(refused) != 1 || refused[0] != stuck.Stack+": That stack is not yours." {
				t.Fatalf("refused %v", refused)
			}
			c := s.Counts()
			if c.StacksWaiting != 0 || len(c.Refused) != 1 || c.Refused[0].Stack != stuck.Stack || c.Refused[0].Refused == "" {
				t.Fatalf("counts %+v", c)
			}
			// Never retried, never deleted, and it survives a restart.
			before := f.announce
			if err := u.SendAll(context.Background()); err != nil || f.announce != before {
				t.Fatalf("a refused stack was tried again: %v", err)
			}
			s.Keep = func() bool { return false }
			s.Clean()
			for i := 1; i <= 2; i++ {
				if _, err := s.ReadSide(stuck.Stack, i, 1); err != nil {
					t.Fatalf("an unconfirmed side of a refused stack is gone: %v", err)
				}
			}
			if c := openStore(t, s.Dir()).Counts(); len(c.Refused) != 1 {
				t.Fatal("the refusal should be remembered")
			}
		})
	}
}

func TestARepeatedBadHashRefusesOnlyThatStack(t *testing.T) {
	f := newFakeSally(t)
	s := openStore(t, t.TempDir())
	now := time.Now()
	s.Now = func() time.Time { return now }
	bad := scanStack(t, s, 1)
	now = now.Add(time.Minute)
	good := scanStack(t, s, 2)
	f.badHash = map[string]bool{"run-" + bad.Stack: true}
	u := &Uploader{Store: s, API: f.client()}

	for i := 1; i < MaxBadHash; i++ {
		err := u.SendAll(context.Background())
		if sally.StatusOf(err) != 422 {
			t.Fatalf("round %d: a 422 should be retried later, got %v", i, err)
		}
		if f.done["run-"+good.Stack] != 1 {
			t.Fatalf("round %d: the good stack must not wait behind the bad one", i)
		}
		if len(s.Counts().Refused) != 0 {
			t.Fatalf("round %d: refused too early", i)
		}
	}
	if err := u.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := s.Counts()
	if len(c.Refused) != 1 || !strings.Contains(c.Refused[0].Refused, "did not arrive intact") {
		t.Fatalf("counts %+v", c)
	}
	if _, err := s.ReadSide(bad.Stack, 1, 1); err != nil {
		t.Fatal("the refused side must stay on disk")
	}
}

func TestOfflineStillStopsTheRound(t *testing.T) {
	f := newFakeSally(t)
	s := openStore(t, t.TempDir())
	scanStack(t, s, 2)
	f.srv.Close()
	u := &Uploader{Store: s, API: f.client()}
	if err := u.SendAll(context.Background()); err == nil {
		t.Fatal("offline must surface")
	}
	if c := s.Counts(); len(c.Refused) != 0 || c.StacksWaiting != 1 {
		t.Fatalf("offline must not refuse a stack: %+v", c)
	}
}

func TestAStackGoesOnlyToTheCompanyAndDeviceItWasScannedFor(t *testing.T) {
	f := newFakeSally(t)
	dir := t.TempDir()
	s, err := Open(dir, xorSealer{})
	if err != nil {
		t.Fatal(err)
	}
	var clockMu sync.Mutex
	now := time.Now()
	s.Now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		now = now.Add(time.Second)
		return now
	}

	// Scanned before this PC was ever connected: no owner yet, and nothing
	// to send it with.
	early := scanStack(t, s, 2)
	if len(s.Stacks()) != 0 {
		t.Fatal("nothing is sendable before a connection")
	}
	if c := s.Counts(); c.StacksWaiting != 1 || c.Held != 0 {
		t.Fatalf("an unconnected stack waits, it is not held: %+v", c)
	}

	// Connected to company 1: the early stack takes that connection.
	s.SetOwner("co-1", "dev-1")
	mine := scanStack(t, s, 2)
	u := &Uploader{Store: s, API: f.client()}
	if err := u.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.done["run-"+early.Stack] != 1 || f.done["run-"+mine.Stack] != 1 {
		t.Fatalf("done %v", f.done)
	}

	// A stack scanned for company 1 is still waiting when the PC is
	// revoked and connected to company 2.
	old := scanStack(t, s, 2)
	s.SetOwner("", "")
	s.SetOwner("co-2", "dev-2")
	if st := s.Stacks(); len(st) != 0 {
		t.Fatalf("a stack for another company was offered: %v", st[0].Stack)
	}
	if c := s.Counts(); c.Held != 1 || c.StacksWaiting != 0 {
		t.Fatalf("counts %+v", c)
	}
	// Same company, another device: still held. The stamp never changes.
	s.SetOwner("co-1", "dev-9")
	if len(s.Stacks()) != 0 {
		t.Fatal("a stack for another device was offered")
	}
	reopened := openStore(t, dir) // owner co-1/dev-1 again
	st := reopened.Stacks()
	if len(st) != 1 || st[0].Stack != old.Stack || st[0].CompanyID != "co-1" || st[0].DeviceID != "dev-1" {
		t.Fatalf("stacks %+v", st)
	}
	// Held stacks are kept, whatever the janitor does.
	s.Keep = func() bool { return false }
	s.Clean()
	if _, err := s.ReadSide(old.Stack, 1, 1); err != nil {
		t.Fatal("a held stack lost a page")
	}
}

func TestOneSidedScanNumbersEverySideAsItsOwnSheet(t *testing.T) {
	s := openStore(t, t.TempDir())
	w, err := s.NewStack(false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Add(page(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := w.Finish("")
	if err != nil || r.Sheets != 3 || r.Sides != 3 || r.Message() != "Got 3 sheets. Safe on this PC." {
		t.Fatalf("%+v %v", r, err)
	}
	m := s.Stacks()[0]
	if m.Duplex {
		t.Fatal("the manifest must record a one-sided scan")
	}
	for i, sd := range m.Sides {
		if sd.Sheet != i+1 || sd.Side != 1 {
			t.Fatalf("side %d numbered %d/%d", i, sd.Sheet, sd.Side)
		}
	}
	got, err := s.ReadSide(r.Stack, 2, 1)
	if err != nil || !bytes.Equal(got, page(1)) {
		t.Fatal("sheet 2 should hold the second page scanned")
	}

	// A one-sided stack is full at 500 sheets, a duplex one at 1000 sides.
	w, _ = s.NewStack(false)
	for i := 0; i < MaxSheets; i++ {
		if w.Full() {
			t.Fatalf("full after %d sheets", i)
		}
		if err := w.Add(page(0)); err != nil {
			t.Fatal(err)
		}
	}
	if !w.Full() || w.Add(page(0)) == nil {
		t.Fatal("a one-sided stack takes at most 500 sheets")
	}
}
