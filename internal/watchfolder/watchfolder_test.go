package watchfolder

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/outbox"
)

type plain struct{}

func (plain) Seal(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
func (plain) Open(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

// clock is a settable test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Date(2026, 10, 12, 11, 0, 0, 0, time.Local)} }
func pdf(body string) []byte         { return []byte("%PDF-1.7\n" + body) }
func jpeg(body string) []byte        { return append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, body...) }
func png(body string) []byte {
	return append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, body...)
}
func tiff(body string) []byte              { return append([]byte{'I', 'I', 0x2A, 0x00}, body...) }
func today(c *clock) string                { return c.t.Local().Format("2006-01-02") }
func sentDir(root string, c *clock) string { return filepath.Join(root, SentFolder, today(c)) }

type rig struct {
	t      *testing.T
	root   string
	agent  string
	clock  *clock
	store  *outbox.Store
	w      *Watcher
	folder string
	taken  int
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, root: t.TempDir(), agent: t.TempDir(), clock: newClock()}
	r.folder = r.root
	r.open()
	return r
}

// open (re)starts the outbox and the watcher from what is on disk, as a
// restarted agent does.
func (r *rig) open() {
	r.t.Helper()
	st, err := outbox.Open(filepath.Join(r.agent, "outbox"), plain{})
	if err != nil {
		r.t.Fatal(err)
	}
	st.Now = r.clock.now
	r.store = st
	w, err := New(Options{
		Folder:  func() string { return r.folder },
		Journal: filepath.Join(r.agent, "watchfolder.json"),
		Store:   st,
		Now:     r.clock.now,
		Settle:  5 * time.Second,
		OnTaken: func() { r.taken++ },
	})
	if err != nil {
		r.t.Fatal(err)
	}
	r.w = w
}

func (r *rig) write(rel string, b []byte) string {
	r.t.Helper()
	p := filepath.Join(r.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		r.t.Fatal(err)
	}
	// Give each write its own time, as a real disk would.
	mt := r.clock.t
	_ = os.Chtimes(p, mt, mt)
	return p
}

// pollAfter moves the clock and polls.
func (r *rig) pollAfter(d time.Duration) {
	r.clock.add(d)
	r.w.Poll()
}

func (r *rig) stacks() []*outbox.Manifest {
	r.store.SetOwner("co-alpha", "dev-1")
	return r.store.Stacks()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func names(dir string) []string {
	es, _ := os.ReadDir(dir)
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestAFileIsSentOnlyOnceItsSizeAndTimeSettle(t *testing.T) {
	r := newRig(t)
	p := r.write("scan-001.pdf", pdf("half"))
	r.pollAfter(0)
	if n := len(r.stacks()); n != 0 {
		t.Fatalf("sent at first sight: %d stacks", n)
	}
	// Still growing: every poll sees a new size and time.
	for i := 0; i < 5; i++ {
		r.clock.add(2 * time.Second)
		r.write("scan-001.pdf", pdf(strings.Repeat("more ", i+2)))
		r.w.Poll()
		if n := len(r.stacks()); n != 0 {
			t.Fatalf("a growing file was sent (poll %d)", i)
		}
	}
	if st := r.w.Status(); st.Waiting != 1 {
		t.Fatalf("waiting = %d, want 1", st.Waiting)
	}
	// It stops growing: 4 s later it has not settled yet, 6 s later it has.
	r.pollAfter(4 * time.Second)
	if n := len(r.stacks()); n != 0 {
		t.Fatal("sent before the settle period")
	}
	r.pollAfter(2 * time.Second)
	ms := r.stacks()
	if len(ms) != 1 {
		t.Fatalf("stacks = %d, want 1", len(ms))
	}
	m := ms[0]
	if m.Kind != outbox.KindFolder || m.FileName != "scan-001.pdf" || m.FolderName != "" || len(m.Sides) != 1 {
		t.Fatalf("manifest = %+v", m)
	}
	if sd := m.Sides[0]; sd.Sheet != 1 || sd.Side != 0 || sd.Name != "scan-001.pdf" || sd.ContentType != "application/pdf" {
		t.Fatalf("side = %+v", sd)
	}
	if exists(p) {
		t.Fatal("the file was not moved out of the folder")
	}
	if !exists(filepath.Join(sentDir(r.root, r.clock), "scan-001.pdf")) {
		t.Fatalf("not in Sent to Sally: %v", names(sentDir(r.root, r.clock)))
	}
	if st := r.w.Status(); st.SentToday != 1 || st.Waiting != 0 || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}
	if r.taken != 1 {
		t.Fatalf("OnTaken called %d times", r.taken)
	}
	// The outbox copy is the file's bytes.
	got, err := r.store.ReadSide(m.Stack, 1, 0)
	if err != nil || string(got) != string(pdf(strings.Repeat("more ", 6))) {
		t.Fatalf("outbox copy = %q, %v", got, err)
	}
}

func TestAMovedFileNeverOverwritesOneAlreadySent(t *testing.T) {
	r := newRig(t)
	dir := sentDir(r.root, r.clock)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invoice.jpg"), []byte("earlier"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invoice (2).jpg"), []byte("earlier too"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.write("invoice.jpg", jpeg("today's"))
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	want := []string{"invoice (2).jpg", "invoice (3).jpg", "invoice.jpg"}
	if got := names(dir); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Sent to Sally = %v, want %v", got, want)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "invoice.jpg")); string(b) != "earlier" {
		t.Fatal("the earlier file was overwritten")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "invoice (3).jpg")); string(b) != string(jpeg("today's")) {
		t.Fatal("the new file is not under its numbered name")
	}
}

func TestOnlyPDFsAndPicturesAreTaken(t *testing.T) {
	r := newRig(t)
	keep := []string{"notes.txt", "~$draft.pdf", "scan.tmp", "scan.pdf.part", ".hidden.pdf", "empty.pdf", "fake.pdf", "big.docx"}
	for _, n := range keep {
		b := []byte("not a pdf")
		if n == "empty.pdf" {
			b = nil
		}
		r.write(n, b)
	}
	r.write("a.pdf", pdf("a"))
	r.write("b.JPG", jpeg("b"))
	r.write("c.jpeg", jpeg("c"))
	r.write("d.png", png("d"))
	r.write("e.tif", tiff("e"))
	r.write("f.TIFF", tiff("f"))
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	ms := r.stacks()
	if len(ms) != 6 {
		t.Fatalf("stacks = %d, want 6 (one run per file)", len(ms))
	}
	types := map[string]string{}
	for _, m := range ms {
		types[m.FileName] = m.Sides[0].ContentType
	}
	want := map[string]string{"a.pdf": "application/pdf", "b.JPG": "image/jpeg", "c.jpeg": "image/jpeg", "d.png": "image/png", "e.tif": "image/tiff", "f.TIFF": "image/tiff"}
	for k, v := range want {
		if types[k] != v {
			t.Fatalf("%s: type %q, want %q (all: %v)", k, types[k], v, types)
		}
	}
	for _, n := range keep {
		if !exists(filepath.Join(r.root, n)) {
			t.Fatalf("%s was moved; it should be left alone", n)
		}
	}
	// fake.pdf is a .pdf that is not a PDF inside: said once, then left.
	if st := r.w.Status(); !strings.Contains(st.LastError, "fake.pdf") {
		t.Fatalf("last error = %q", st.LastError)
	}
	r.pollAfter(10 * time.Second)
	if len(r.stacks()) != 6 {
		t.Fatal("a refused file was sent later")
	}
}

func TestSentToSallyIsNotLookedInto(t *testing.T) {
	r := newRig(t)
	r.write(SentFolder+"/2026-10-11/old.pdf", pdf("old"))
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	if n := len(r.stacks()); n != 0 {
		t.Fatalf("Sent to Sally was sent again: %d stacks", n)
	}
}

func TestAFolderDroppedInIsOneRunOnceEveryFileSettles(t *testing.T) {
	r := newRig(t)
	r.write("Monday/page-1.jpg", jpeg("1"))
	r.write("Monday/page-2.jpg", jpeg("2"))
	r.write("Monday/readme.txt", []byte("left alone"))
	r.pollAfter(0)
	// A third file arrives while the copy is still running.
	r.clock.add(4 * time.Second)
	r.write("Monday/more/page-3.pdf", pdf("3"))
	r.w.Poll()
	r.pollAfter(4 * time.Second)
	if n := len(r.stacks()); n != 0 {
		t.Fatal("the drop was sent before its last file settled")
	}
	if st := r.w.Status(); st.Waiting != 3 {
		t.Fatalf("waiting = %d, want 3", st.Waiting)
	}
	r.pollAfter(2 * time.Second)
	ms := r.stacks()
	if len(ms) != 1 {
		t.Fatalf("stacks = %d, want 1 for the whole folder", len(ms))
	}
	m := ms[0]
	if m.FolderName != "Monday" || m.FileName != "" || len(m.Sides) != 3 {
		t.Fatalf("manifest = %+v", m)
	}
	var got []string
	for _, sd := range m.Sides {
		got = append(got, sd.FolderPath+"|"+sd.Name)
	}
	if strings.Join(got, ",") != "|page-1.jpg,|page-2.jpg,more|page-3.pdf" {
		t.Fatalf("files = %v", got)
	}
	dest := filepath.Join(sentDir(r.root, r.clock), "Monday")
	if !exists(filepath.Join(dest, "page-1.jpg")) || !exists(filepath.Join(dest, "more", "page-3.pdf")) {
		t.Fatalf("not moved: %v", names(dest))
	}
	// The text file stays where it was, and keeps its folder.
	if !exists(filepath.Join(r.root, "Monday", "readme.txt")) {
		t.Fatal("readme.txt was moved")
	}
	if exists(filepath.Join(r.root, "Monday", "more")) {
		t.Fatal("the emptied sub-folder was left behind")
	}
	if st := r.w.Status(); st.SentToday != 3 {
		t.Fatalf("sent today = %d", st.SentToday)
	}
	// What is left (one text file) is never a run.
	r.pollAfter(10 * time.Second)
	if len(r.stacks()) != 1 {
		t.Fatal("the leftover folder became a run")
	}
}

func TestACrashAfterTheOutboxCopyNeitherLosesNorSendsTwice(t *testing.T) {
	r := newRig(t)
	p := r.write("scan.pdf", pdf("signed"))
	// The agent copied the file into the outbox and stopped before it
	// wrote the journal: the file is still in the folder.
	if _, err := r.store.NewFolderStack("scan.pdf", "", []outbox.FolderFile{{Name: "scan.pdf", ContentType: "application/pdf", Data: pdf("signed")}}); err != nil {
		t.Fatal(err)
	}
	r.open()
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	if n := len(r.stacks()); n != 1 {
		t.Fatalf("stacks = %d, want the one already in the outbox", n)
	}
	if exists(p) || !exists(filepath.Join(sentDir(r.root, r.clock), "scan.pdf")) {
		t.Fatal("the file was not moved")
	}
	if r.taken != 0 {
		t.Fatal("a file already in the outbox was taken as new")
	}
}

func TestTheJournalFinishesMovesAfterARestart(t *testing.T) {
	r := newRig(t)
	p := r.write("scan.pdf", pdf("signed"))
	// Every move fails, as if the agent stopped right after the journal.
	rename = func(string, string) error { return errors.New("stopped") }
	t.Cleanup(func() { rename = os.Rename })
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	if len(r.stacks()) != 1 || !exists(p) {
		t.Fatal("expected one stack and the file still in place")
	}
	rename = os.Rename
	// Restart: the journal moves it; nothing is sent again.
	r.open()
	r.pollAfter(0)
	if n := len(r.stacks()); n != 1 {
		t.Fatalf("stacks = %d after the restart, want 1", n)
	}
	if exists(p) || !exists(filepath.Join(sentDir(r.root, r.clock), "scan.pdf")) {
		t.Fatal("the journal did not finish the move")
	}
	// The journal is empty now.
	raw, _ := os.ReadFile(filepath.Join(r.agent, "watchfolder.json"))
	if strings.Contains(string(raw), "scan.pdf") {
		t.Fatalf("journal still pending: %s", raw)
	}
	if st := r.w.Status(); st.SentToday != 1 {
		t.Fatalf("sent today = %d", st.SentToday)
	}
}

func TestAFileReplacedBeforeTheMoveIsNotMovedAsTheOldOne(t *testing.T) {
	r := newRig(t)
	r.write("scan.pdf", pdf("first"))
	rename = func(string, string) error { return errors.New("locked") }
	t.Cleanup(func() { rename = os.Rename })
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	rename = os.Rename
	// Someone saves a new scan under the same name before the move.
	r.clock.add(time.Second)
	r.write("scan.pdf", pdf("second, a new paper"))
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	ms := r.stacks()
	if len(ms) != 2 {
		t.Fatalf("stacks = %d, want 2 (the new paper is sent too)", len(ms))
	}
	if got := names(sentDir(r.root, r.clock)); len(got) != 1 {
		t.Fatalf("Sent to Sally = %v", got)
	}
}

func TestALockedFileIsMovedOnALaterPoll(t *testing.T) {
	r := newRig(t)
	p := r.write("scan.png", png("x"))
	fails := 2
	rename = func(a, b string) error {
		if fails > 0 {
			fails--
			return errors.New("The process cannot access the file because it is being used by another process.")
		}
		return os.Rename(a, b)
	}
	t.Cleanup(func() { rename = os.Rename })
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	if !exists(p) {
		t.Fatal("moved despite the lock")
	}
	if st := r.w.Status(); !strings.Contains(st.LastError, "trying again") {
		t.Fatalf("last error = %q", st.LastError)
	}
	r.pollAfter(2 * time.Second) // still locked
	r.pollAfter(2 * time.Second) // free
	if exists(p) {
		t.Fatal("not moved once free")
	}
	if n := len(r.stacks()); n != 1 {
		t.Fatalf("stacks = %d, want 1 (never sent twice while locked)", n)
	}
}

func TestACopyThatNeverFinishedIsTakenAgain(t *testing.T) {
	r := newRig(t)
	// A folder stack directory with no manifest: the agent stopped mid-copy.
	half := filepath.Join(r.agent, "outbox", "20261012T110000-abcd-f")
	if err := os.MkdirAll(half, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(half, "file-001.page"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.write("scan.pdf", pdf("whole"))
	r.open()
	if exists(half) {
		t.Fatal("the unfinished copy was kept")
	}
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	if n := len(r.stacks()); n != 1 {
		t.Fatalf("stacks = %d", n)
	}
}

func TestNoFolderChosenDoesNothing(t *testing.T) {
	r := newRig(t)
	r.folder = ""
	r.write("scan.pdf", pdf("x"))
	r.pollAfter(0)
	r.pollAfter(6 * time.Second)
	if len(r.stacks()) != 0 {
		t.Fatal("sent with no folder chosen")
	}
	r.folder = filepath.Join(r.root, "missing")
	r.pollAfter(0)
	if st := r.w.Status(); !strings.Contains(st.LastError, "cannot be read") {
		t.Fatalf("last error = %q", st.LastError)
	}
}
