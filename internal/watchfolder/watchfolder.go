// Package watchfolder is Sally Desktop's watched folder: a folder on the PC
// (often the one a scanner's own software saves into) whose files are sent
// to Sally by themselves.
//
// It polls; there is no fsnotify (zero dependencies), and polling is also
// what works on network drives. A file is taken once its size AND its
// modification time have stayed the same for the settle period, so a file
// still being written is never sent half done. Only PDFs and pictures
// (pdf, jpg, jpeg, png, tif, tiff) are taken; everything else, temporary
// and partial files (~$*, *.tmp, *.part, .*) and empty files are left
// alone.
//
// A file directly in the folder is one run. A sub-folder dropped in is one
// run for all of its files (a "folder drop"), taken once every file in it
// has settled. The "Sent to Sally" folder itself is never looked into.
//
// Taking a run is three steps, in this order:
//
//  1. its files are copied into the outbox (the same outbox, upload client
//     and device token as scanning, so they are "safe on this PC" the same
//     way: sealed, fsynced, hashed, sent and confirmed in the background);
//  2. the journal records the outbox stack and each file's path, size and
//     modification time (written atomically, like the outbox's manifests);
//  3. the files are moved into "<folder>/Sent to Sally/<date>/" (a folder
//     drop into a sub-folder of its own name there). A name already there
//     gets " (2)", " (3)"…: nothing is ever overwritten.
//
// After a crash between 2 and 3 the journal finishes the moves on start. A
// crash between 1 and 2 leaves the files in the folder with their copy in
// the outbox: a file whose bytes (SHA-256) an outbox folder stack already
// holds is moved, not sent again. A move that fails (on Windows, a file the
// scanner's software still holds open) is tried again on the next poll.
package watchfolder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/outbox"
	"github.com/sallyerp/sally-print-agent/internal/secure"
)

// SentFolder is the folder, inside the watched folder, that sent files are
// moved into.
const SentFolder = "Sent to Sally"

// Defaults.
const (
	DefaultPollEvery = 2 * time.Second
	DefaultSettle    = 5 * time.Second
	// maxDepth is how deep a folder drop is read.
	maxDepth = 8
)

// Store is the part of the outbox the watcher uses.
type Store interface {
	NewFolderStack(fileName, folderName string, files []outbox.FolderFile) (string, error)
	FolderStackHolding(sha string) string
}

// Options configure a Watcher.
type Options struct {
	// Folder returns the folder to watch ("" when none is chosen).
	Folder func() string
	// Journal is the path of the journal file.
	Journal string
	Store   Store
	// Settle is how long a file's size and time must stay the same.
	Settle time.Duration
	// Now is the clock (tests replace it).
	Now  func() time.Time
	Logf func(format string, args ...any)
	// OnTaken is called after a run is safe in the outbox (wake the
	// uploader and the heartbeat).
	OnTaken func()
}

// Status is the watcher in numbers and words, for the status page and the
// heartbeat. Never content.
type Status struct {
	Folder string
	// Waiting: files in the folder (or in folder drops) that will be sent
	// once they settle.
	Waiting int
	// SentToday: files moved to Sent to Sally today (local time).
	SentToday int
	LastError string
	ErrorAt   time.Time
}

// Watcher watches one folder.
type Watcher struct {
	opt Options

	// pollMu is held for a whole pass (which may read large files); the
	// fields under it are the pass's own.
	pollMu sync.Mutex
	j      journal
	seen   map[string]*observed // by absolute path (a file, or a drop)
	folder string               // the folder seen on the last poll
	// skip: files that will not be sent as they are (not a PDF or picture
	// inside, too large), by path, with the signature they had then.
	skip map[string]string

	// mu guards what Status reads, so the status page never waits for a
	// pass.
	mu        sync.Mutex
	waiting   int
	day       string
	sentToday int
	lastErr   string
	errAt     time.Time
}

type observed struct {
	sig   string
	since time.Time
}

// journal is the watcher's state on disk.
type journal struct {
	// Day (YYYY-MM-DD, local) and SentToday count today's moved files.
	Day       string `json:"day,omitempty"`
	SentToday int    `json:"sentToday"`
	// Pending moves: runs copied into the outbox, not yet (all) moved.
	Pending []move `json:"pending"`
}

type move struct {
	Stack string `json:"stack"`
	// Root is the watched folder; Drop the dropped sub-folder ("" for a
	// single file).
	Root string `json:"root"`
	Drop string `json:"drop,omitempty"`
	// Dest is the folder the files go into.
	Dest  string `json:"dest"`
	Items []item `json:"items"`
}

type item struct {
	// Src is the file's path; Rel its path inside the drop (or its name).
	Src   string    `json:"src"`
	Rel   string    `json:"rel"`
	Size  int64     `json:"size"`
	MTime time.Time `json:"mtime"`
	Done  bool      `json:"done,omitempty"`
}

// New loads the journal (a missing one is empty).
func New(opt Options) (*Watcher, error) {
	if opt.Settle <= 0 {
		opt.Settle = DefaultSettle
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Folder == nil {
		opt.Folder = func() string { return "" }
	}
	w := &Watcher{opt: opt, seen: map[string]*observed{}, skip: map[string]string{}}
	raw, err := os.ReadFile(opt.Journal)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &w.j); err != nil {
			// A damaged journal must not stop the watcher; the hash check
			// still keeps a file in the outbox from being sent twice.
			opt.Logf("watched folder: the journal could not be read (%v); starting afresh", err)
			w.j = journal{}
		}
	}
	w.day, w.sentToday = w.j.Day, w.j.SentToday
	return w, nil
}

// Run polls every `every` until ctx ends.
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = DefaultPollEvery
	}
	for {
		w.Poll()
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Status returns the current numbers.
func (w *Watcher) Status() Status {
	folder := w.opt.Folder()
	today := w.opt.Now().Local().Format("2006-01-02")
	w.mu.Lock()
	defer w.mu.Unlock()
	st := Status{Folder: folder, Waiting: w.waiting, LastError: w.lastErr, ErrorAt: w.errAt}
	if w.day == today {
		st.SentToday = w.sentToday
	}
	return st
}

func (w *Watcher) setErr(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	now := w.opt.Now()
	w.mu.Lock()
	w.lastErr, w.errAt = msg, now
	w.mu.Unlock()
	w.opt.Logf("watched folder: %s", msg)
}

func (w *Watcher) clearErr() {
	w.mu.Lock()
	w.lastErr, w.errAt = "", time.Time{}
	w.mu.Unlock()
}

// publish makes the pass's numbers visible to Status.
func (w *Watcher) publish(waiting int) {
	w.mu.Lock()
	w.waiting, w.day, w.sentToday = waiting, w.j.Day, w.j.SentToday
	w.mu.Unlock()
}

func (w *Watcher) rollDay() {
	day := w.opt.Now().Local().Format("2006-01-02")
	if w.j.Day != day {
		w.j.Day, w.j.SentToday = day, 0
	}
}

func (w *Watcher) saveJournal() error {
	b, err := json.MarshalIndent(w.j, "", "  ")
	if err != nil {
		return err
	}
	return secure.WriteFileAtomic(w.opt.Journal, append(b, '\n'))
}

// Poll does one pass: finish moves still pending, look at the folder, and
// take every run that has settled.
func (w *Watcher) Poll() {
	w.pollMu.Lock()
	defer w.pollMu.Unlock()
	waiting := 0
	defer func() { w.publish(waiting) }()
	w.rollDay()
	w.finishMoves()

	folder := w.opt.Folder()
	if folder != w.folder {
		// A new folder (or none): forget what was seen in the old one.
		w.folder = folder
		w.seen = map[string]*observed{}
		w.skip = map[string]string{}
		w.clearErr()
	}
	if folder == "" {
		return
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		w.setErr("the folder %s cannot be read: %v", folder, err)
		return
	}
	pending := w.pendingSources()
	now := w.opt.Now()
	alive := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(folder, name)
		if strings.EqualFold(name, SentFolder) || ignoredName(name) {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		switch {
		case info.IsDir():
			if pendingUnder(pending, path) {
				continue
			}
			files, sig, err := w.readDrop(path)
			if err != nil {
				w.setErr("the folder %s cannot be read: %v", name, err)
				continue
			}
			if len(files) == 0 {
				continue
			}
			alive[path] = true
			waiting += len(files)
			if !w.settled(path, sig, now) {
				continue
			}
			if len(files) > outbox.MaxFolderFiles {
				if w.skip[path] != sig {
					w.skip[path] = sig
					w.setErr("the folder %s has %d files; Sally takes at most %d at once. Split it into smaller folders.", name, len(files), outbox.MaxFolderFiles)
				}
				continue
			}
			if w.take(folder, path, files) {
				waiting -= len(files)
				delete(w.seen, path)
			}
		case info.Mode().IsRegular():
			if pending[path] {
				continue
			}
			f, ok := w.candidate(path, name, "", info)
			if !ok {
				continue
			}
			alive[path] = true
			waiting++
			if !w.settled(path, sigOf(info), now) {
				continue
			}
			if w.take(folder, "", []candidateFile{f}) {
				waiting--
				delete(w.seen, path)
			}
		}
	}
	for p := range w.seen {
		if !alive[p] {
			delete(w.seen, p)
		}
	}
}

// settled records what is seen at path and reports whether it has stayed
// the same for the settle period.
func (w *Watcher) settled(path, sig string, now time.Time) bool {
	o, ok := w.seen[path]
	if !ok || o.sig != sig {
		w.seen[path] = &observed{sig: sig, since: now}
		return false
	}
	return now.Sub(o.since) >= w.opt.Settle
}

func sigOf(info os.FileInfo) string {
	return fmt.Sprintf("%d|%d", info.Size(), info.ModTime().UnixNano())
}

// ignoredName: temporary, partial and hidden files.
func ignoredName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "~$") ||
		strings.HasSuffix(lower, ".tmp") || strings.HasSuffix(lower, ".part") ||
		strings.HasSuffix(lower, ".crdownload")
}

// typeByExt is what the watcher takes, by extension.
var typeByExt = map[string]string{
	".pdf": "application/pdf", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".png": "image/png", ".tif": "image/tiff", ".tiff": "image/tiff",
}

// Takes reports whether a file of this name would be sent.
func Takes(name string) bool {
	if ignoredName(name) {
		return false
	}
	_, ok := typeByExt[strings.ToLower(filepath.Ext(name))]
	return ok
}

// sniff names the file's type from its first bytes, or "" when they are
// not a PDF, JPEG, PNG or TIFF.
func sniff(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "application/pdf"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return "image/jpeg"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return "image/png"
	case bytes.HasPrefix(b, []byte{'I', 'I', 0x2A, 0x00}), bytes.HasPrefix(b, []byte{'M', 'M', 0x00, 0x2A}):
		return "image/tiff"
	}
	return ""
}

// candidateFile is a file that will be sent once its run settles.
type candidateFile struct {
	path, name, folderPath string
	size                   int64
	mtime                  time.Time
}

// candidate decides whether a file would be sent: a PDF or picture by its
// name, not temporary, not empty, not over the size cap.
func (w *Watcher) candidate(path, name, folderPath string, info os.FileInfo) (candidateFile, bool) {
	if !Takes(name) || info.Size() == 0 {
		return candidateFile{}, false
	}
	if sig, ok := w.skip[path]; ok {
		if sig == sigOf(info) {
			return candidateFile{}, false
		}
		delete(w.skip, path) // changed: look again
	}
	if info.Size() > outbox.MaxFolderFileBytes {
		w.skip[path] = sigOf(info)
		w.setErr("%s is larger than %d MB; it stays in the folder", name, outbox.MaxFolderFileBytes>>20)
		return candidateFile{}, false
	}
	return candidateFile{path: path, name: name, folderPath: folderPath, size: info.Size(), mtime: info.ModTime()}, true
}

// readDrop lists a dropped folder's files to send, and a signature of
// EVERY file in it (temporary ones too: a copy still running changes it).
func (w *Watcher) readDrop(dir string) ([]candidateFile, string, error) {
	var files []candidateFile
	var sig []string
	var walk func(d, rel string, depth int) error
	walk = func(d, rel string, depth int) error {
		entries, err := os.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			p := filepath.Join(d, name)
			info, err := os.Lstat(p)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			r := name
			if rel != "" {
				r = rel + "/" + name
			}
			if info.IsDir() {
				if strings.HasPrefix(name, ".") || depth >= maxDepth {
					continue
				}
				if err := walk(p, r, depth+1); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				continue
			}
			sig = append(sig, r+"|"+sigOf(info))
			if f, ok := w.candidate(p, name, rel, info); ok {
				files = append(files, f)
			}
		}
		return nil
	}
	if err := walk(dir, "", 0); err != nil {
		return nil, "", err
	}
	sort.Strings(sig)
	sort.Slice(files, func(i, j int) bool {
		if files[i].folderPath != files[j].folderPath {
			return files[i].folderPath < files[j].folderPath
		}
		return files[i].name < files[j].name
	})
	return files, strings.Join(sig, "\n"), nil
}

// take sends one settled run: copy into the outbox (or find it there
// already), journal, move. It reports whether the run left the folder's
// waiting list (taken, or found already taken).
func (w *Watcher) take(root, drop string, files []candidateFile) bool {
	label := filepath.Base(drop)
	if drop == "" {
		label = files[0].name
	}
	read := make([]outbox.FolderFile, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			// Often the scanner's software still holds it: next poll.
			w.opt.Logf("watched folder: %s cannot be read yet: %v", f.name, err)
			return false
		}
		info, err := os.Stat(f.path)
		if err != nil || info.Size() != f.size || !info.ModTime().Equal(f.mtime) || int64(len(data)) != f.size {
			// It changed while being read: wait for it to settle again.
			delete(w.seen, f.path)
			if drop != "" {
				delete(w.seen, drop)
			}
			return false
		}
		ct := sniff(data)
		if ct == "" {
			w.skip[f.path] = sigOf(info)
			w.setErr("%s is not a PDF or a picture inside; it stays in the folder", f.name)
			continue
		}
		read = append(read, outbox.FolderFile{Name: f.name, FolderPath: f.folderPath, ContentType: ct, Data: data})
	}
	if len(read) == 0 {
		return false
	}

	// Already in the outbox (the agent stopped after copying, before it
	// could journal the move)? Then move, do not send again.
	stack := ""
	for _, f := range read {
		id := w.opt.Store.FolderStackHolding(f.SHA256())
		if id == "" {
			stack = ""
			break
		}
		if stack == "" {
			stack = id
		}
	}
	found := stack != ""
	if !found {
		fileName, folderName := "", ""
		if drop == "" {
			fileName = read[0].Name
		} else {
			folderName = label
		}
		id, err := w.opt.Store.NewFolderStack(fileName, folderName, read)
		if err != nil {
			w.setErr("%s could not be kept safe on this PC: %v", label, err)
			return false
		}
		stack = id
		w.opt.Logf("watched folder: %s is safe on this PC as stack %s (%d %s)", label, stack, len(read), plural(len(read), "file", "files"))
	} else {
		w.opt.Logf("watched folder: %s is already in the outbox (stack %s); moving it, not sending it again", label, stack)
	}

	mv := move{Stack: stack, Root: root, Drop: drop}
	dest, err := w.destFor(root, drop)
	if err != nil {
		w.setErr("could not make the %s folder: %v", SentFolder, err)
		// The copy is safe; the hash check moves the files on a later poll.
		return true
	}
	mv.Dest = dest
	sent := map[string]bool{}
	for _, f := range read {
		sent[joinRel(f.FolderPath, f.Name)] = true
	}
	for _, f := range files {
		rel := joinRel(f.folderPath, f.name)
		if !sent[rel] {
			continue // not a PDF or picture inside: it stays
		}
		mv.Items = append(mv.Items, item{Src: f.path, Rel: rel, Size: f.size, MTime: f.mtime})
	}
	w.j.Pending = append(w.j.Pending, mv)
	if err := w.saveJournal(); err != nil {
		w.j.Pending = w.j.Pending[:len(w.j.Pending)-1]
		w.setErr("could not write the journal: %v", err)
		return true
	}
	if !found && w.opt.OnTaken != nil {
		w.opt.OnTaken()
	}
	w.finishMoves()
	return true
}

func joinRel(folderPath, name string) string {
	if folderPath == "" {
		return name
	}
	return folderPath + "/" + name
}

// destFor makes "<root>/Sent to Sally/<date>" and, for a folder drop, a
// sub-folder of the drop's name there (" (2)"… when that name is taken).
func (w *Watcher) destFor(root, drop string) (string, error) {
	day := filepath.Join(root, SentFolder, w.opt.Now().Local().Format("2006-01-02"))
	if err := os.MkdirAll(day, 0o755); err != nil {
		return "", err
	}
	if drop == "" {
		return day, nil
	}
	base := filepath.Base(drop)
	for n := 1; n < 1000; n++ {
		p := filepath.Join(day, numbered(base, n, false))
		err := os.Mkdir(p, 0o755)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("too many folders named %s", base)
}

// numbered is name for n == 1, else "name (n)" (before the extension for
// a file).
func numbered(name string, n int, file bool) string {
	if n <= 1 {
		return name
	}
	ext := ""
	if file {
		ext = filepath.Ext(name)
	}
	return fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), n, ext)
}

// pendingSources are the files a journaled move still has to move.
func (w *Watcher) pendingSources() map[string]bool {
	out := map[string]bool{}
	for _, m := range w.j.Pending {
		if m.Drop != "" {
			out[m.Drop] = true
		}
		for _, it := range m.Items {
			if !it.Done {
				out[it.Src] = true
			}
		}
	}
	return out
}

func pendingUnder(pending map[string]bool, dir string) bool {
	if pending[dir] {
		return true
	}
	prefix := dir + string(filepath.Separator)
	for p := range pending {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// finishMoves moves every journaled file still in place. A file whose size
// or time changed since it was copied is not the file that was sent: it is
// left for the watcher to take as new. A move that fails stays pending.
func (w *Watcher) finishMoves() {
	if len(w.j.Pending) == 0 {
		return
	}
	changed := false
	kept := w.j.Pending[:0]
	for _, m := range w.j.Pending {
		left := 0
		for i := range m.Items {
			it := &m.Items[i]
			if it.Done {
				continue
			}
			info, err := os.Stat(it.Src)
			if errors.Is(err, os.ErrNotExist) {
				it.Done, changed = true, true
				continue
			}
			if err != nil || info.Size() != it.Size || !info.ModTime().Equal(it.MTime) {
				it.Done, changed = true, true
				continue
			}
			if err := moveInto(it.Src, filepath.Join(m.Dest, filepath.FromSlash(it.Rel))); err != nil {
				left++
				w.setErr("%s could not be moved to %s yet (it may be open in another program); trying again", filepath.Base(it.Src), SentFolder)
				continue
			}
			it.Done, changed = true, true
			w.j.SentToday++
		}
		if left > 0 {
			kept = append(kept, m)
			continue
		}
		if m.Drop != "" {
			removeEmptyDirs(m.Drop)
		}
	}
	w.j.Pending = kept
	if changed {
		if err := w.saveJournal(); err != nil {
			w.opt.Logf("watched folder: saving the journal failed: %v", err)
		}
	}
}

// rename is os.Rename (tests make it fail, as Windows does for a file
// another program holds open).
var rename = os.Rename

// moveInto renames src to dst, or to "dst (2)", "dst (3)"… when a file of
// that name is already there. It never overwrites.
func moveInto(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	name := filepath.Base(dst)
	for n := 1; n < 10000; n++ {
		p := filepath.Join(filepath.Dir(dst), numbered(name, n, true))
		if _, err := os.Lstat(p); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return rename(src, p)
	}
	return fmt.Errorf("too many files named %s", name)
}

// removeEmptyDirs removes dir and its sub-folders that are now empty;
// anything left in them (files that are not sent) keeps them.
func removeEmptyDirs(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			removeEmptyDirs(filepath.Join(dir, e.Name()))
		}
	}
	_ = os.Remove(dir) // fails, harmlessly, unless empty
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
