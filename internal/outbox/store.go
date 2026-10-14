// Package outbox keeps scanned pages safe on the PC until Sally has them.
//
// Every side is written to disk the moment it arrives from the scanner,
// sealed with DPAPI on Windows (a 0600 file in a 0700 directory elsewhere),
// fsynced, and recorded in the stack's manifest. Only when every side of a
// stack is durably on disk does the agent say "Got N sheets. Safe on this
// PC." and the person may take the paper away.
//
// Uploads run in the background and resume across restarts from the
// manifest. A local copy is deleted (or kept for 7 days, a per-PC setting)
// only after Sally confirms it holds that side.
package outbox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/secure"
)

// Side upload states.
const (
	Pending   = "pending"   // on disk, not yet in S3
	Uploaded  = "uploaded"  // PUT to S3 succeeded, Sally has not confirmed
	Confirmed = "confirmed" // Sally holds it (sides answered 200/201)
)

// MaxSides and MaxSheets are the contract's caps per stack.
const (
	MaxSides  = 1000
	MaxSheets = 500
)

// How a pile ended early (Manifest.Ended).
const (
	EndedStopped = "STOPPED"
	EndedJam     = "JAM"
	EndedError   = "ERROR"
)

// KeepFor is how long a confirmed side stays when "keep a copy" is on.
const KeepFor = 7 * 24 * time.Hour

// Side is one scanned side in a manifest.
type Side struct {
	Sheet       int        `json:"sheet"`
	Side        int        `json:"side"` // 1 or 2, as scanned
	SHA256      string     `json:"sha256"`
	Size        int64      `json:"size"`
	File        string     `json:"file"`
	State       string     `json:"state"`
	ConfirmedAt *time.Time `json:"confirmedAt,omitempty"`
	Deleted     bool       `json:"deleted,omitempty"`
	// BadHash counts Sally's 422 answers (the bytes it got did not match
	// the hash) for this side.
	BadHash int `json:"badHash,omitempty"`

	// A watched-folder stack's file: Sheet is its place in the stack
	// (1…N), Side is 0, and these say what it is. Empty for a scanned side.
	Name        string `json:"name,omitempty"`
	FolderPath  string `json:"folderPath,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

// Manifest describes one stack: everything one feeder load produced.
type Manifest struct {
	Stack   string    `json:"stack"`
	Created time.Time `json:"created"`
	// Kind is "" for a scanned stack and KindFolder for files taken from
	// the watched folder (folder.go). A folder stack has no sheets: its
	// Sides are files, and FileName (one file) or FolderName (a folder
	// drop) names it.
	Kind       string `json:"kind,omitempty"`
	FileName   string `json:"fileName,omitempty"`
	FolderName string `json:"folderName,omitempty"`
	// CompanyID and DeviceID are the Sally company and device the stack was
	// scanned for. A stack scanned before this PC was connected has neither
	// and takes the first connection made; once set they never change, and
	// the stack is sent only by that same device into that same company.
	CompanyID string `json:"companyId,omitempty"`
	DeviceID  string `json:"deviceId,omitempty"`
	// Duplex: the scan asked for both sides of every sheet, so sides
	// alternate front, back. Otherwise every side is side 1 of its own
	// sheet.
	Duplex bool `json:"duplex"`
	Sheets int  `json:"sheets"`
	// Complete: scanning finished and every side is on disk.
	Complete bool `json:"complete"`
	// Problem: why scanning stopped early (a jam), if it did.
	Problem string `json:"problem,omitempty"`
	// Ended says how a scanned stack whose pile ended early ended, for
	// Sally: EndedStopped (someone pressed Stop), EndedJam (a paper jam) or
	// EndedError (anything else, including a stack recovered after the
	// agent stopped mid-scan). Empty for a pile that ran to its end.
	Ended string `json:"ended,omitempty"`
	RunID   string `json:"runId,omitempty"`
	// Done: Sally acknowledged /done; nothing more to send.
	Done bool `json:"done"`
	// Refused: Sally answered this stack in a way that can never clear
	// (400, 404, 409, or the same side failing its hash again and again).
	// The stack is no longer sent; its unconfirmed pages stay on the PC.
	Refused   string     `json:"refused,omitempty"`
	RefusedAt *time.Time `json:"refusedAt,omitempty"`
	Sides     []Side     `json:"sides"`
}

func (m *Manifest) clone() *Manifest {
	c := *m
	c.Sides = append([]Side(nil), m.Sides...)
	return &c
}

// Sealer encrypts pages at rest.
type Sealer interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

// OSSealer is DPAPI on Windows and a pass-through elsewhere.
type OSSealer struct{}

func (OSSealer) Seal(b []byte) ([]byte, error) { return secure.Protect(b) }
func (OSSealer) Open(b []byte) ([]byte, error) { return secure.Unprotect(b) }

// Store is the outbox on disk.
type Store struct {
	dir    string
	sealer Sealer
	// Keep reports the "keep a copy for 7 days" setting.
	Keep func() bool
	// Now is the clock (tests replace it).
	Now func() time.Time

	mu     sync.Mutex
	stacks map[string]*Manifest
	// The connection stacks are sent with now (empty when not connected).
	company, device string
}

// SetOwner names the Sally company and device this PC is connected as
// (both empty when it is not). New stacks are stamped with them, stacks
// scanned while unconnected take them, and only stacks stamped with them
// are offered for sending. A stack stamped for another connection is held,
// never sent and never deleted.
func (s *Store) SetOwner(companyID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.company, s.device = companyID, deviceID
	if companyID == "" {
		return nil
	}
	var first error
	for _, m := range s.stacks {
		if m.CompanyID != "" {
			continue
		}
		m.CompanyID, m.DeviceID = companyID, deviceID
		// A run id from before the stack had an owner belongs to whatever
		// connection made it; this connection announces the stack afresh.
		m.RunID = ""
		if err := s.writeManifest(m); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// mine reports whether m belongs to the current connection.
func (s *Store) mine(m *Manifest) bool {
	return s.company != "" && m.CompanyID == s.company && m.DeviceID == s.device
}

// Open opens (creating) the outbox under dir and loads every manifest, so a
// restarted agent resumes what it was sending.
func Open(dir string, sealer Sealer) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	s := &Store{dir: dir, sealer: sealer, Keep: func() bool { return true }, Now: time.Now, stacks: map[string]*Manifest{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !validStackID(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name(), "manifest.json"))
		if errors.Is(err, os.ErrNotExist) && isFolderStackID(e.Name()) {
			// A folder stack's manifest is written last: without it the
			// copy never finished, and the files are still in the watched
			// folder, to be taken again.
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
			continue
		}
		if err != nil {
			continue
		}
		var m Manifest
		if json.Unmarshal(raw, &m) != nil || m.Stack != e.Name() {
			continue
		}
		if !m.Complete && m.Kind == KindFolder {
			_ = os.RemoveAll(filepath.Join(dir, m.Stack))
			continue
		}
		if !m.Complete {
			// The agent stopped mid-scan. What reached the disk is safe;
			// send it as a stack of its own.
			if len(m.Sides) == 0 {
				_ = os.RemoveAll(filepath.Join(dir, m.Stack))
				continue
			}
			m.Complete = true
			if m.Problem == "" {
				m.Problem = "the agent stopped while this stack was scanning"
			}
			m.Ended = EndedError
			m.Sheets = sheetsOf(m.Sides)
			if err := s.writeManifest(&m); err != nil {
				return nil, err
			}
		}
		s.stacks[m.Stack] = &m
	}
	return s, nil
}

// Dir is the outbox directory.
func (s *Store) Dir() string { return s.dir }

func validStackID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func newStackID(now time.Time) string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return now.UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b)
}

func sheetsOf(sides []Side) int {
	n := 0
	for _, sd := range sides {
		if sd.Sheet > n {
			n = sd.Sheet
		}
	}
	return n
}

func (s *Store) stackDir(id string) string { return filepath.Join(s.dir, id) }

// writeManifest saves m atomically (temp + fsync + rename + dir fsync).
func (s *Store) writeManifest(m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return secure.WriteFileAtomic(filepath.Join(s.stackDir(m.Stack), "manifest.json"), b)
}

// ── Writing a stack ────────────────────────────────────────────────────────

// StackWriter receives the sides of one stack as the scanner delivers them.
type StackWriter struct {
	s      *Store
	id     string
	failed error
}

// NewStack starts a stack. duplex is whether the scan job asked for both
// sides; it decides how the sides are numbered.
func (s *Store) NewStack(duplex bool) (*StackWriter, error) {
	now := s.Now()
	id := newStackID(now)
	if err := os.MkdirAll(s.stackDir(id), 0o700); err != nil {
		return nil, err
	}
	s.mu.Lock()
	company, device := s.company, s.device
	s.mu.Unlock()
	m := &Manifest{Stack: id, Created: now.UTC(), CompanyID: company, DeviceID: device, Duplex: duplex, Sides: []Side{}}
	if err := s.writeManifest(m); err != nil {
		return nil, err
	}
	if err := secure.SyncDir(s.dir); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.stacks[id] = m
	s.mu.Unlock()
	return &StackWriter{s: s, id: id}, nil
}

// ID is the stack id.
func (w *StackWriter) ID() string { return w.id }

// Sides is how many sides are on disk.
func (w *StackWriter) Sides() int {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return len(w.s.stacks[w.id].Sides)
}

// Full reports whether the stack can take no more sides (1000 sides, or
// 500 sheets for a one-sided scan).
func (w *StackWriter) Full() bool {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	m := w.s.stacks[w.id]
	sheet, _ := numberSide(m.Duplex, len(m.Sides))
	return len(m.Sides) >= MaxSides || sheet > MaxSheets
}

// numberSide gives the sheet and side of the idx-th side scanned (from 0).
func numberSide(duplex bool, idx int) (sheet, side int) {
	if duplex {
		return idx/2 + 1, idx%2 + 1
	}
	return idx + 1, 1
}

// Add writes the next side, in scan order: for a duplex scan sheet 1 side
// 1, sheet 1 side 2, sheet 2 side 1…; for a one-sided scan sheet 1 side 1,
// sheet 2 side 1… It returns only once the side is durably on disk.
func (w *StackWriter) Add(page []byte) error {
	if w.failed != nil {
		return w.failed
	}
	err := w.add(page)
	if err != nil {
		w.failed = err
	}
	return err
}

func (w *StackWriter) add(page []byte) error {
	if len(page) < 2 || page[0] != 0xFF || page[1] != 0xD8 {
		return errors.New("outbox: the scanner sent a page that is not a JPEG")
	}
	w.s.mu.Lock()
	idx := len(w.s.stacks[w.id].Sides)
	duplex := w.s.stacks[w.id].Duplex
	w.s.mu.Unlock()
	if idx >= MaxSides {
		return fmt.Errorf("outbox: a stack holds at most %d sides", MaxSides)
	}
	sheet, side := numberSide(duplex, idx)
	if sheet > MaxSheets {
		return fmt.Errorf("outbox: a stack holds at most %d sheets", MaxSheets)
	}
	name := fmt.Sprintf("sheet-%03d-side-%d.page", sheet, side)
	sealed, err := w.s.sealer.Seal(page)
	if err != nil {
		return fmt.Errorf("outbox: sealing the page: %w", err)
	}
	if err := secure.WriteFileAtomic(filepath.Join(w.s.stackDir(w.id), name), sealed); err != nil {
		return fmt.Errorf("outbox: writing the page: %w", err)
	}
	sum := sha256.Sum256(page)

	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	m := w.s.stacks[w.id]
	m.Sides = append(m.Sides, Side{
		Sheet: sheet, Side: side,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(page)),
		File: name, State: Pending,
	})
	m.Sheets = sheetsOf(m.Sides)
	if err := w.s.writeManifest(m); err != nil {
		m.Sides = m.Sides[:len(m.Sides)-1]
		m.Sheets = sheetsOf(m.Sides)
		return fmt.Errorf("outbox: writing the manifest: %w", err)
	}
	return nil
}

// Receipt is what the person is told when a stack finishes.
type Receipt struct {
	Stack  string
	Sheets int
	Sides  int
	// Safe: every side the scanner delivered is durably on disk.
	Safe bool
}

// Message is the line shown and spoken about a finished stack.
func (r Receipt) Message() string {
	if !r.Safe || r.Sides == 0 {
		return ""
	}
	return fmt.Sprintf("Got %d %s. Safe on this PC.", r.Sheets, plural(r.Sheets, "sheet", "sheets"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// DropLast removes the last side from the stack and deletes its file. It is
// used only for a stopped duplex pile's unpaired front: a half-fed sheet is
// never kept, so it is fed again whole.
func (w *StackWriter) DropLast() error {
	s := w.s
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.stacks[w.id]
	if len(m.Sides) == 0 {
		return nil
	}
	last := m.Sides[len(m.Sides)-1]
	m.Sides = m.Sides[:len(m.Sides)-1]
	m.Sheets = sheetsOf(m.Sides)
	if err := s.writeManifest(m); err != nil {
		m.Sides = append(m.Sides, last)
		m.Sheets = sheetsOf(m.Sides)
		return err
	}
	if err := os.Remove(filepath.Join(s.stackDir(w.id), last.File)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Finish closes the stack. problem says why scanning stopped early (a jam)
// or is empty; ended is how a pile that ended early ended (EndedStopped,
// EndedJam, EndedError) or "". The receipt is Safe only if every Add
// succeeded and every side's file is on disk.
func (w *StackWriter) Finish(problem, ended string) (Receipt, error) {
	s := w.s
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.stacks[w.id]
	r := Receipt{Stack: w.id, Sheets: m.Sheets, Sides: len(m.Sides)}
	if len(m.Sides) == 0 {
		delete(s.stacks, w.id)
		_ = os.RemoveAll(s.stackDir(w.id))
		return r, w.failed
	}
	m.Complete = true
	m.Problem = problem
	m.Ended = ended
	if err := s.writeManifest(m); err != nil {
		return r, err
	}
	if w.failed != nil {
		return r, w.failed
	}
	for _, sd := range m.Sides {
		st, err := os.Stat(filepath.Join(s.stackDir(w.id), sd.File))
		if err != nil || st.Size() == 0 {
			return r, fmt.Errorf("outbox: side %d/%d is missing on disk", sd.Sheet, sd.Side)
		}
	}
	r.Safe = true
	return r, nil
}

// ── Reading and updating ───────────────────────────────────────────────────

// Stacks returns copies of every stack still to send, oldest first.
func (s *Store) Stacks() []*Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Manifest, 0, len(s.stacks))
	for _, m := range s.stacks {
		if m.Complete && !m.Done && m.Refused == "" && s.mine(m) {
			out = append(out, m.clone())
		}
	}
	sortStacks(out)
	return out
}

func sortStacks(ms []*Manifest) {
	sort.Slice(ms, func(i, j int) bool {
		if !ms[i].Created.Equal(ms[j].Created) {
			return ms[i].Created.Before(ms[j].Created)
		}
		return ms[i].Stack < ms[j].Stack
	})
}

// ReadSide reads and unseals one side and checks its hash.
func (s *Store) ReadSide(stack string, sheet, side int) ([]byte, error) {
	s.mu.Lock()
	m, ok := s.stacks[stack]
	var sd *Side
	if ok {
		sd = findSide(m, sheet, side)
	}
	var file, want string
	if sd != nil {
		file, want = sd.File, sd.SHA256
	}
	s.mu.Unlock()
	if sd == nil {
		return nil, fmt.Errorf("outbox: no side %d/%d in %s", sheet, side, stack)
	}
	sealed, err := os.ReadFile(filepath.Join(s.stackDir(stack), file))
	if err != nil {
		return nil, err
	}
	page, err := s.sealer.Open(sealed)
	if err != nil {
		return nil, fmt.Errorf("outbox: unsealing %s: %w", file, err)
	}
	sum := sha256.Sum256(page)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("outbox: %s/%s does not match its hash", stack, file)
	}
	return page, nil
}

func findSide(m *Manifest, sheet, side int) *Side {
	for i := range m.Sides {
		if m.Sides[i].Sheet == sheet && m.Sides[i].Side == side {
			return &m.Sides[i]
		}
	}
	return nil
}

func (s *Store) update(stack string, fn func(m *Manifest) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.stacks[stack]
	if !ok {
		return fmt.Errorf("outbox: no stack %s", stack)
	}
	if !fn(m) {
		return nil
	}
	return s.writeManifest(m)
}

// SetRunID records Sally's run for the stack.
func (s *Store) SetRunID(stack, runID string) error {
	return s.update(stack, func(m *Manifest) bool {
		if m.RunID == runID {
			return false
		}
		m.RunID = runID
		return true
	})
}

// MarkUploaded records a successful PUT.
func (s *Store) MarkUploaded(stack string, sheet, side int) error {
	return s.update(stack, func(m *Manifest) bool {
		sd := findSide(m, sheet, side)
		if sd == nil || sd.State != Pending {
			return false
		}
		sd.State = Uploaded
		return true
	})
}

// MarkConfirmed records that Sally holds the side, then deletes the local
// copy, unless "keep a copy for 7 days" is on.
func (s *Store) MarkConfirmed(stack string, sheet, side int) error {
	keep := s.Keep()
	now := s.Now().UTC()
	var remove string
	err := s.update(stack, func(m *Manifest) bool {
		sd := findSide(m, sheet, side)
		if sd == nil || sd.State == Confirmed {
			return false
		}
		sd.State = Confirmed
		sd.ConfirmedAt = &now
		if !keep {
			sd.Deleted = true
			remove = sd.File
		}
		return true
	})
	if err != nil {
		return err
	}
	// The manifest says "confirmed" before the file goes, so a crash in
	// between leaves an orphan the janitor ignores, never a pending side
	// with no file.
	if remove != "" {
		_ = os.Remove(filepath.Join(s.stackDir(stack), remove))
	}
	return nil
}

// MarkRefused stops sending a stack Sally will never take as it is. Nothing
// is deleted: sides Sally has not confirmed stay on disk.
func (s *Store) MarkRefused(stack, reason string) error {
	now := s.Now().UTC()
	if reason == "" {
		reason = "no reason given"
	}
	return s.update(stack, func(m *Manifest) bool {
		if m.Refused != "" {
			return false
		}
		m.Refused, m.RefusedAt = reason, &now
		return true
	})
}

// NoteBadHash counts one more 422 for a side and returns the count.
func (s *Store) NoteBadHash(stack string, sheet, side int) (int, error) {
	n := 0
	err := s.update(stack, func(m *Manifest) bool {
		sd := findSide(m, sheet, side)
		if sd == nil {
			return false
		}
		sd.BadHash++
		n = sd.BadHash
		return true
	})
	return n, err
}

// MarkDone records that Sally acknowledged /done.
func (s *Store) MarkDone(stack string) error {
	return s.update(stack, func(m *Manifest) bool {
		if m.Done {
			return false
		}
		m.Done = true
		return true
	})
}

// Clean deletes kept copies older than 7 days (or at once when keeping is
// off) and removes stacks that are done and empty.
func (s *Store) Clean() {
	keep := s.Keep()
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, m := range s.stacks {
		changed := false
		for i := range m.Sides {
			sd := &m.Sides[i]
			if sd.State != Confirmed || sd.Deleted {
				continue
			}
			if !keep || (sd.ConfirmedAt != nil && now.Sub(*sd.ConfirmedAt) >= KeepFor) {
				_ = os.Remove(filepath.Join(s.stackDir(id), sd.File))
				sd.Deleted = true
				changed = true
			}
		}
		if m.Done && allDeleted(m) {
			if err := os.RemoveAll(s.stackDir(id)); err == nil {
				delete(s.stacks, id)
			}
			continue
		}
		if changed {
			_ = s.writeManifest(m)
		}
	}
	// Leftover temp files from a crash mid-write.
	matches, _ := filepath.Glob(filepath.Join(s.dir, "*", ".tmp-*"))
	for _, p := range matches {
		if st, err := os.Stat(p); err == nil && now.Sub(st.ModTime()) > time.Hour {
			_ = os.Remove(p)
		}
	}
}

func allDeleted(m *Manifest) bool {
	for _, sd := range m.Sides {
		if !sd.Deleted {
			return false
		}
	}
	return true
}

// ── Counts for the status page and the heartbeat ───────────────────────────

// Counts is the outbox in numbers. Never content.
type Counts struct {
	StacksWaiting int
	SidesWaiting  int
	BytesWaiting  int64
	// Of the stacks still sending: sides in total and sides Sally holds.
	SendingTotal int
	SendingSent  int
	// Today: stacks scanned today (local time) still in the outbox, and
	// their sheets.
	TodayStacks int
	TodaySheets int
	// Held: stacks scanned for another company or device. They stay on
	// this PC and are not sent.
	Held int
	// Refused stacks, newest first: Sally will not take them, and their
	// pages are kept on this PC.
	Refused []LastStack
	Last    *LastStack
	// Recent stacks, newest first (for "Stacks today").
	Recent []LastStack
	// FolderFilesWaiting: watched-folder files on this PC not yet with
	// Sally (also counted in the totals above). Folder stacks are not in
	// Today*, Recent or Last, which describe scanned stacks.
	FolderFilesWaiting int
}

// LastStack summarises one stack.
type LastStack struct {
	Stack   string
	Sheets  int
	Sides   int
	At      time.Time
	State   string // SAFE | SENDING | SENT
	Problem string
	// Refused is why Sally refused the stack, if it did.
	Refused string
}

// Counts sums the outbox.
func (s *Store) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c Counts
	ty, tm, td := s.Now().Local().Date()
	all := make([]*Manifest, 0, len(s.stacks))
	for _, m := range s.stacks {
		if !m.Complete {
			continue
		}
		folder := m.Kind == KindFolder
		if !folder {
			all = append(all, m)
		}
		if y, mo, d := m.Created.Local().Date(); !folder && y == ty && mo == tm && d == td {
			c.TodayStacks++
			c.TodaySheets += m.Sheets
		}
		if m.Done {
			continue
		}
		if m.Refused != "" {
			c.Refused = append(c.Refused, summarise(m))
			continue
		}
		if m.CompanyID != "" && (m.CompanyID != s.company || m.DeviceID != s.device) {
			c.Held++
			continue
		}
		c.StacksWaiting++
		c.SendingTotal += len(m.Sides)
		for _, sd := range m.Sides {
			if sd.State == Confirmed {
				c.SendingSent++
				continue
			}
			c.SidesWaiting++
			c.BytesWaiting += sd.Size
			if folder {
				c.FolderFilesWaiting++
			}
		}
	}
	sortStacks(all)
	sort.Slice(c.Refused, func(i, j int) bool { return c.Refused[i].At.After(c.Refused[j].At) })
	for i := len(all) - 1; i >= 0 && len(c.Recent) < 5; i-- {
		c.Recent = append(c.Recent, summarise(all[i]))
	}
	if len(c.Recent) > 0 {
		l := c.Recent[0]
		c.Last = &l
	}
	return c
}

func summarise(m *Manifest) LastStack {
	state := "SAFE"
	confirmed := 0
	for _, sd := range m.Sides {
		if sd.State == Confirmed {
			confirmed++
		}
	}
	switch {
	case m.Done:
		state = "SENT"
	case confirmed > 0:
		state = "SENDING"
	}
	return LastStack{Stack: m.Stack, Sheets: m.Sheets, Sides: len(m.Sides), At: m.Created, State: state, Problem: m.Problem, Refused: m.Refused}
}

// Describe is a short line about a stack for logs (counts only).
func (l LastStack) Describe() string {
	return strings.TrimSpace(fmt.Sprintf("%s · %d %s · %s", l.Stack, l.Sheets, plural(l.Sheets, "sheet", "sheets"), strings.ToLower(l.State)))
}
