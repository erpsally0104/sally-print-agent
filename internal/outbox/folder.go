package outbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/secure"
)

// KindFolder marks a stack of files taken from the watched folder.
const KindFolder = "FOLDER"

// The contract's caps for a watched-folder stack.
const (
	MaxFolderFiles     = 500
	MaxFolderFileBytes = 100 << 20
)

// folderSuffix ends every folder stack's id, so a folder stack whose copy
// never finished (no manifest) is known for what it is and removed.
const folderSuffix = "-f"

func isFolderStackID(id string) bool { return strings.HasSuffix(id, folderSuffix) }

// ErrFileChanged: a file changed (size or time) while it was copied into
// the outbox; nothing was kept, and it is taken again once it settles.
var ErrFileChanged = errors.New("outbox: the file changed while it was copied")

// FolderFile is one file to put into a folder stack.
type FolderFile struct {
	// Name is the file's own name; FolderPath is the sub-folder it sits
	// in inside a folder drop ("" at the top of the drop or for a single
	// file), with "/" between folders.
	Name        string
	FolderPath  string
	ContentType string
	// Path is the file on disk, read when it is copied (one file at a
	// time, so a large drop never sits in memory at once). Size and MTime,
	// when set, are what it must still be: otherwise ErrFileChanged.
	Path  string
	Size  int64
	MTime time.Time
	// Data is the file's bytes when there is no Path (tests).
	Data []byte
}

// SHA256 is the hash of Data, as the outbox records it.
func (f FolderFile) SHA256() string {
	sum := sha256.Sum256(f.Data)
	return hex.EncodeToString(sum[:])
}

// read returns the file's bytes and SHA-256, streaming it from Path
// through the hash (at most MaxFolderFileBytes are read).
func (f FolderFile) read() ([]byte, string, error) {
	if f.Path == "" {
		if len(f.Data) > MaxFolderFileBytes {
			return nil, "", fmt.Errorf("outbox: %s is larger than %d MB", f.Name, MaxFolderFileBytes>>20)
		}
		return f.Data, f.SHA256(), nil
	}
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, "", err
	}
	defer fh.Close()
	var buf bytes.Buffer
	if f.Size > 0 && f.Size <= MaxFolderFileBytes {
		buf.Grow(int(f.Size))
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(&buf, h), io.LimitReader(fh, MaxFolderFileBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("outbox: reading %s: %w", f.Name, err)
	}
	if n > MaxFolderFileBytes {
		return nil, "", fmt.Errorf("outbox: %s is larger than %d MB", f.Name, MaxFolderFileBytes>>20)
	}
	if f.Size > 0 && n != f.Size {
		return nil, "", ErrFileChanged
	}
	if !f.MTime.IsZero() {
		info, err := fh.Stat()
		if err != nil || info.Size() != n || !info.ModTime().Equal(f.MTime) {
			return nil, "", ErrFileChanged
		}
	}
	return buf.Bytes(), hex.EncodeToString(h.Sum(nil)), nil
}

// NewFolderStack copies files into the outbox as one stack, sealed and
// fsynced like scanned sides, and returns its id. The manifest is written
// last and complete: a crash before it leaves no stack (Open removes the
// partial copy) and the files are still in the watched folder. Two files
// with the same bytes are kept once. fileName names a single file,
// folderName a folder drop.
func (s *Store) NewFolderStack(fileName, folderName string, files []FolderFile) (string, error) {
	if len(files) == 0 {
		return "", errors.New("outbox: a folder stack needs at least one file")
	}
	if len(files) > MaxFolderFiles {
		return "", fmt.Errorf("outbox: a folder stack holds at most %d files", MaxFolderFiles)
	}
	now := s.Now()
	id, err := s.makeFolderStackDir(now)
	if err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(s.stackDir(id))
		return "", err
	}
	s.mu.Lock()
	company, device := s.company, s.device
	s.mu.Unlock()
	if fileName != "" {
		fileName = WireName(fileName)
	}
	if folderName != "" {
		folderName = WireName(folderName)
	}
	m := &Manifest{
		Stack: id, Created: now.UTC(), Kind: KindFolder, FileName: fileName, FolderName: folderName,
		CompanyID: company, DeviceID: device, Complete: true, Sides: []Side{},
	}
	seen := map[string]bool{}
	for _, f := range files {
		// One file at a time: read (hashing as it streams), seal, write,
		// and let go of it before the next.
		data, sum, err := f.read()
		if err != nil {
			return fail(err)
		}
		if len(data) == 0 {
			return fail(fmt.Errorf("outbox: %s is empty", f.Name))
		}
		if seen[sum] {
			continue
		}
		seen[sum] = true
		idx := len(m.Sides) + 1
		name := fmt.Sprintf("file-%03d.page", idx)
		sealed, err := s.sealer.Seal(data)
		if err != nil {
			return fail(fmt.Errorf("outbox: sealing %s: %w", f.Name, err))
		}
		if err := secure.WriteFileAtomic(filepath.Join(s.stackDir(id), name), sealed); err != nil {
			return fail(fmt.Errorf("outbox: writing %s: %w", f.Name, err))
		}
		m.Sides = append(m.Sides, Side{
			Sheet: idx, Side: 0, SHA256: sum, Size: int64(len(data)), File: name, State: Pending,
			Name: WireName(f.Name), FolderPath: wirePath(f.FolderPath), ContentType: f.ContentType,
		})
	}
	if err := s.writeManifest(m); err != nil {
		return fail(fmt.Errorf("outbox: writing the manifest: %w", err))
	}
	if err := secure.SyncDir(s.dir); err != nil {
		return fail(err)
	}
	s.mu.Lock()
	s.stacks[id] = m
	s.mu.Unlock()
	return id, nil
}

// makeFolderStackDir creates a new stack directory whose id no other stack
// has (several folder stacks can start within one second).
func (s *Store) makeFolderStackDir(now time.Time) (string, error) {
	for i := 0; i < 20; i++ {
		id := newStackID(now) + folderSuffix
		err := os.Mkdir(s.stackDir(id), 0o700)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("outbox: could not name a new stack")
}

// FolderStackHolding names the folder stack made at or after since that
// already holds a file with these bytes (by SHA-256), or "". It is asked
// only about the crash window (the watcher journaled that it was copying a
// file and stopped before journaling the move), so a file dropped again
// later is always sent as a new stack: Sally marks true duplicates itself.
func (s *Store) FolderStackHolding(sha string, since time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, m := range s.stacks {
		if m.Kind != KindFolder || m.Created.Before(since) {
			continue
		}
		for _, sd := range m.Sides {
			if sd.SHA256 == sha {
				return id
			}
		}
	}
	return ""
}

// Stack returns a copy of one stack's manifest, or nil.
func (s *Store) Stack(id string) *Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.stacks[id]; ok {
		return m.clone()
	}
	return nil
}

// maxWireName is the longest name Sally takes (characters).
const maxWireName = 200

// WireName is a name as Sally takes it: no control characters or slashes,
// trimmed, at most 200 characters (cut before the extension, which stays).
func WireName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "file"
	}
	rs := []rune(name)
	if len(rs) <= maxWireName {
		return name
	}
	ext := []rune(filepath.Ext(name))
	if len(ext) > 10 {
		ext = nil
	}
	return strings.TrimSpace(string(rs[:maxWireName-len(ext)])) + string(ext)
}

// wirePath is a folder drop's sub-folder as Sally takes it: each part a
// WireName, the whole at most 200 characters (the deepest parts kept).
func wirePath(p string) string {
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = WireName(parts[i])
		if r := []rune(parts[i]); len(r) > 40 {
			parts[i] = strings.TrimSpace(string(r[:40]))
		}
	}
	for len(parts) > 1 && len([]rune(strings.Join(parts, "/"))) > maxWireName {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}
