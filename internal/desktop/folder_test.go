package desktop

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheWatchedFolderMustBeAFullPathToARealFolder(t *testing.T) {
	a := newAgent(t, "http://127.0.0.1:1", nil)
	scans := filepath.Join(t.TempDir(), "Scans")
	if err := os.Mkdir(scans, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"Scans", filepath.Join(scans, "missing"), a.opt.Dir, filepath.Join(a.opt.Dir, "outbox"), filepath.Join(scans, "Sent to Sally")} {
		if bad == filepath.Join(scans, "Sent to Sally") {
			_ = os.Mkdir(bad, 0o755)
		}
		if err := a.SetWatchedFolder(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if err := a.SetWatchedFolder("  " + scans + string(filepath.Separator) + "  "); err != nil {
		t.Fatal(err)
	}
	if v := a.Snapshot(); v.WatchedFolder != scans {
		t.Fatalf("watched folder %q", v.WatchedFolder)
	}
	// Remembered across a restart, beside the other per-PC settings.
	b, err := New(Options{Dir: a.opt.Dir, BaseURL: "http://127.0.0.1:1", Version: "x", Scanning: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.Snapshot().WatchedFolder != scans {
		t.Fatal("the folder was not remembered")
	}
	raw, _ := os.ReadFile(filepath.Join(a.opt.Dir, "scan.json"))
	if !strings.Contains(string(raw), `"watchedFolder"`) {
		t.Fatalf("scan.json %s", raw)
	}
	if err := b.SetWatchedFolder(""); err != nil || b.Snapshot().WatchedFolder != "" {
		t.Fatalf("Clear: %v", err)
	}
}

func TestHeartbeatNamesTheWatchedFolderButNotItsPath(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	a := pairedAgent(t, srv.URL, nil)
	a.heartbeatOnce(context.Background())
	if _, ok := got["watchedFolder"]; ok {
		t.Fatal("no folder chosen: nothing to report")
	}
	scans := filepath.Join(t.TempDir(), "Scans")
	if err := os.Mkdir(scans, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scans, "a.pdf"), []byte("%PDF-1.7 a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.SetWatchedFolder(scans); err != nil {
		t.Fatal(err)
	}
	a.folder.Poll()
	a.heartbeatOnce(context.Background())
	wf, _ := got["watchedFolder"].(map[string]any)
	if wf == nil || wf["name"] != "Scans" || wf["filesWaiting"] != float64(1) || wf["sentToday"] != float64(0) {
		t.Fatalf("watchedFolder %v", got["watchedFolder"])
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), filepath.Dir(scans)) {
		t.Fatal("the heartbeat carried the folder's full path")
	}
}
