package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Printer is one queue the user can print to.
type Printer struct {
	Name      string `json:"name"`
	IsDefault bool   `json:"default"`
}

// errNoPdfHelper means the platform can print, but the piece that turns a PDF
// into a print job is missing. Sally treats it as "agent present, printing
// unavailable" and falls back to the browser print dialog rather than failing
// the user's print outright.
var errNoPdfHelper = errors.New("no PDF print helper available")

// isNoHelper reports whether printing failed only because the platform's PDF
// helper is missing, which Sally answers by falling back to the browser rather
// than showing the user an error.
func isNoHelper(err error) bool { return errors.Is(err, errNoPdfHelper) }

// printerCache holds the enumerated list briefly. Enumeration shells out to the
// OS and takes a few hundred milliseconds; the print dialog asks on every open,
// and printers do not appear and vanish second to second.
type printerCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	at       time.Time
	printers []Printer
}

func newPrinterCache(ttl time.Duration) *printerCache {
	return &printerCache{ttl: ttl}
}

func (c *printerCache) get(now time.Time, load func() ([]Printer, error)) ([]Printer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.printers != nil && now.Sub(c.at) < c.ttl {
		return c.printers, nil
	}
	list, err := load()
	if err != nil {
		return nil, err
	}
	c.printers, c.at = list, now
	return list, nil
}

// invalidate drops the cache — called after a print fails on a name we thought
// existed, which usually means the queue was removed.
func (c *printerCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.printers = nil
}

// resolvePrinter matches a caller-supplied name against the enumerated list.
//
// This is a security control, not a convenience: the name reaches an OS command,
// and only a string the OS itself gave us is ever allowed through. An empty name
// means "the default printer".
func resolvePrinter(name string, list []Printer) (string, error) {
	if len(list) == 0 {
		return "", errors.New("no printers are installed on this machine")
	}
	if strings.TrimSpace(name) == "" {
		for _, p := range list {
			if p.IsDefault {
				return p.Name, nil
			}
		}
		return list[0].Name, nil
	}
	for _, p := range list {
		if strings.EqualFold(strings.TrimSpace(name), p.Name) {
			return p.Name, nil // the OS's spelling, not the caller's
		}
	}
	return "", fmt.Errorf("printer %q is not installed on this machine", name)
}

// clampCopies keeps a caller from turning one click into a ream.
func clampCopies(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxCopies {
		return maxCopies
	}
	return n
}

const maxCopies = 20

// writeTempPDF spills the uploaded bytes to a private temp file, because both
// platforms' print paths take a path rather than a stream. The caller removes it.
func writeTempPDF(body []byte) (string, error) {
	f, err := os.CreateTemp("", "sally-print-*.pdf")
	if err != nil {
		return "", fmt.Errorf("creating a temporary file: %w", err)
	}
	path := f.Name()
	// 0600: the spooled document is the user's business and nobody else's.
	if err := f.Chmod(0o600); err != nil && !isWindows() {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("securing %s: %w", path, err)
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("closing %s: %w", path, err)
	}
	return path, nil
}

// looksLikePDF rejects a body that is not a PDF before it reaches the spooler.
// A printer handed arbitrary bytes can emit pages of garbage.
func looksLikePDF(body []byte) bool {
	return len(body) > 4 && string(body[:4]) == "%PDF"
}

// sanitiseJobName keeps the job title readable in the OS print queue and free of
// anything that could confuse a command line.
func sanitiseJobName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Sally document"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == ' ', r == '/':
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "Sally document"
	}
	return out
}

// firstExisting returns the first path that exists, or "".
func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// besideExecutable resolves a filename next to the running binary, which is
// where the installer puts the bundled PDF helper.
func besideExecutable(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), name)
}
