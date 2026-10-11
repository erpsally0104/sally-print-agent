package secure

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTokenStoreRoundTrip(t *testing.T) {
	s := TokenStore{Path: filepath.Join(t.TempDir(), "sub", "token.dat")}
	if _, err := s.Get(); !errors.Is(err, ErrNoToken) {
		t.Fatalf("empty store: %v", err)
	}
	if err := s.Set("dev-token-123"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get()
	if err != nil || got != "dev-token-123" {
		t.Fatalf("got %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(s.Path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode %v, want 0600", st.Mode().Perm())
		}
	}
	if err := s.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(); !errors.Is(err, ErrNoToken) {
		t.Fatal("token still there after delete")
	}
	if err := s.Delete(); err != nil {
		t.Fatal("deleting twice must be fine")
	}
}

func TestWriteFileAtomicReplaces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	for _, v := range []string{"one", "two"} {
		if err := WriteFileAtomic(p, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	if string(b) != "two" {
		t.Fatalf("got %q", b)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}
