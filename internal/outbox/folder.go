package outbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// FolderFile is one file to put into a folder stack.
type FolderFile struct {
	// Name is the file's own name; FolderPath is the sub-folder it sits
	// in inside a folder drop ("" at the top of the drop or for a single
	// file), with "/" between folders.
	Name        string
	FolderPath  string
	ContentType string
	Data        []byte
}

// SHA256 is the file's hash, as the outbox records it.
func (f FolderFile) SHA256() string {
	sum := sha256.Sum256(f.Data)
	return hex.EncodeToString(sum[:])
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
	m := &Manifest{
		Stack: id, Created: now.UTC(), Kind: KindFolder, FileName: fileName, FolderName: folderName,
		CompanyID: company, DeviceID: device, Complete: true, Sides: []Side{},
	}
	seen := map[string]bool{}
	for _, f := range files {
		if len(f.Data) == 0 {
			return fail(fmt.Errorf("outbox: %s is empty", f.Name))
		}
		if len(f.Data) > MaxFolderFileBytes {
			return fail(fmt.Errorf("outbox: %s is larger than %d MB", f.Name, MaxFolderFileBytes>>20))
		}
		sum := f.SHA256()
		if seen[sum] {
			continue
		}
		seen[sum] = true
		idx := len(m.Sides) + 1
		name := fmt.Sprintf("file-%03d.page", idx)
		sealed, err := s.sealer.Seal(f.Data)
		if err != nil {
			return fail(fmt.Errorf("outbox: sealing %s: %w", f.Name, err))
		}
		if err := secure.WriteFileAtomic(filepath.Join(s.stackDir(id), name), sealed); err != nil {
			return fail(fmt.Errorf("outbox: writing %s: %w", f.Name, err))
		}
		m.Sides = append(m.Sides, Side{
			Sheet: idx, Side: 0, SHA256: sum, Size: int64(len(f.Data)), File: name, State: Pending,
			Name: f.Name, FolderPath: f.FolderPath, ContentType: f.ContentType,
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

// FolderStackHolding names the folder stack that already holds a file with
// these bytes (by SHA-256), or "". A file found again in the watched folder
// after a crash, before it was moved, is matched here and moved, not sent
// twice.
func (s *Store) FolderStackHolding(sha string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, m := range s.stacks {
		if m.Kind != KindFolder {
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
