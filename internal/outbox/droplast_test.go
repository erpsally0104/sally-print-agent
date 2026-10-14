package outbox

// DropLast takes the side out of the manifest even when its file cannot be
// removed (antivirus holding it open), and says the side is gone, so the
// caller stops counting it.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDropLastCountsTheSideGoneWhenItsFileStays(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("an open file blocks its removal only on Windows")
	}
	dir := t.TempDir()
	s := openStore(t, dir)
	w, _ := s.NewStack(true)
	for i := 0; i < 3; i++ {
		w.Add(page(i))
	}
	// Something (an antivirus scan, a backup tool) holds the last file open.
	f, err := os.Open(filepath.Join(dir, w.ID(), "sheet-002-side-1.page"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = w.DropLast()
	t.Logf("DropLast: err=%v, sides in the manifest now %d", err, w.Sides())
	if err != nil && w.Sides() == 2 {
		t.Errorf("DropLast failed (%v) although the manifest already dropped the side: the caller keeps counting 3 sides for a 2-side stack", err)
	}
}
