package outbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sallyerp/sally-print-agent/internal/sally"
)

// folderSally plays Sally and S3 for watched-folder stacks.
type folderSally struct {
	mu        sync.Mutex
	announced []map[string]any
	held      map[string]bool // sha256 Sally already holds
	declared  map[string]map[string]any
	inS3      map[string][]byte
	puts      map[string]string // ticket → Content-Type of the PUT
	confirmed []map[string]any
	done      int
	srv       *httptest.Server
}

func newFolderSally(t *testing.T) *folderSally {
	f := &folderSally{held: map[string]bool{}, declared: map[string]map[string]any{}, inS3: map[string][]byte{}, puts: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *folderSally) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/s3/") {
		t := strings.TrimPrefix(r.URL.Path, "/s3/")
		b, _ := io.ReadAll(r.Body)
		f.inS3[t] = b
		f.puts[t] = r.Header.Get("Content-Type")
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch {
	case r.URL.Path == "/api/agent/scan/stacks":
		f.announced = append(f.announced, in)
		var have []string
		for h := range f.held {
			have = append(have, h)
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"runId": "run-f", "received": []any{}, "receivedFiles": have})
	case strings.HasSuffix(r.URL.Path, "/upload-url"):
		files, _ := in["files"].([]any)
		var ups []map[string]any
		for _, x := range files {
			d := x.(map[string]any)
			idx := int(d["index"].(float64))
			ticket := fmt.Sprintf("t-%d", idx)
			f.declared[ticket] = d
			ups = append(ups, map[string]any{"index": idx, "ticket": ticket, "url": f.srv.URL + "/s3/" + ticket, "method": "PUT", "headers": map[string]string{"Content-Type": d["contentType"].(string)}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"uploads": ups})
	case strings.HasSuffix(r.URL.Path, "/files"):
		b := f.inS3[in["ticket"].(string)]
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != in["sha256"] {
			w.WriteHeader(422)
			return
		}
		f.confirmed = append(f.confirmed, in)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"file": map[string]any{"id": "x", "status": "UPLOADED"}})
	case strings.HasSuffix(r.URL.Path, "/done"):
		f.done++
		_ = json.NewEncoder(w).Encode(map[string]any{"runId": "run-f", "status": "PREPARING"})
	default:
		w.WriteHeader(404)
	}
}

func folderFiles() []FolderFile {
	return []FolderFile{
		{Name: "page-1.jpg", ContentType: "image/jpeg", Data: append([]byte{0xFF, 0xD8, 0xFF}, "one"...)},
		{Name: "page-2.png", FolderPath: "more", ContentType: "image/png", Data: append([]byte{0x89, 'P', 'N', 'G'}, "two"...)},
		{Name: "bill.pdf", ContentType: "application/pdf", Data: []byte("%PDF-1.7 three")},
		// The same bytes again under another name: kept once.
		{Name: "page-1 copy.jpg", ContentType: "image/jpeg", Data: append([]byte{0xFF, 0xD8, 0xFF}, "one"...)},
	}
}

func TestAFolderStackGoesUpAsFilesWithNamesAndTypes(t *testing.T) {
	f := newFolderSally(t)
	s := openStore(t, t.TempDir())
	s.Keep = func() bool { return false }
	id, err := s.NewFolderStack("", "Monday", folderFiles())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(id, folderSuffix) {
		t.Fatalf("id %s", id)
	}
	c := s.Counts()
	if c.FolderFilesWaiting != 3 || c.TodayStacks != 0 || len(c.Recent) != 0 || c.Last != nil {
		t.Fatalf("counts %+v: a folder stack is waiting, and is not a scanned stack", c)
	}

	c2 := f.client(t)
	u := &Uploader{Store: s, API: c2}
	if err := u.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.announced) != 1 {
		t.Fatalf("announced %d", len(f.announced))
	}
	a := f.announced[0]
	if a["kind"] != "FOLDER" || a["files"] != float64(3) || a["folderName"] != "Monday" || a["stack"] != id {
		t.Fatalf("announce %v", a)
	}
	if _, ok := a["sheets"]; ok {
		t.Fatal("a folder stack declares no sheets")
	}
	if len(f.confirmed) != 3 || f.done != 1 {
		t.Fatalf("confirmed %d, done %d", len(f.confirmed), f.done)
	}
	if f.puts["t-2"] != "image/png" || f.puts["t-3"] != "application/pdf" {
		t.Fatalf("PUT types %v", f.puts)
	}
	if d := f.declared["t-2"]; d["name"] != "page-2.png" || d["folderPath"] != "more" {
		t.Fatalf("declared %v", d)
	}
	if c := s.Counts(); c.StacksWaiting != 0 || c.FolderFilesWaiting != 0 {
		t.Fatalf("after: %+v", c)
	}
	if hold := s.FolderStackHolding(folderFiles()[2].SHA256()); hold != id {
		t.Fatalf("FolderStackHolding = %q", hold)
	}
}

func TestAFolderStackResumesFromTheFilesSallyHolds(t *testing.T) {
	f := newFolderSally(t)
	s := openStore(t, t.TempDir())
	files := folderFiles()[:3]
	if _, err := s.NewFolderStack("", "Monday", files); err != nil {
		t.Fatal(err)
	}
	f.held[files[0].SHA256()] = true
	u := &Uploader{Store: s, API: f.client(t)}
	if err := u.SendAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.confirmed) != 2 {
		t.Fatalf("sent %d files, want the 2 Sally lacked", len(f.confirmed))
	}
	for _, c := range f.confirmed {
		if c["name"] == "page-1.jpg" {
			t.Fatal("a file Sally holds was sent again")
		}
	}
}

func (f *folderSally) client(t *testing.T) API {
	t.Helper()
	c := sally.NewClient(f.srv.URL, "test")
	c.SetAuth("tok", "co-1")
	return c
}

func TestNamesAreKeptWithinWhatSallyTakes(t *testing.T) {
	long := strings.Repeat("x", 250) + ".pdf"
	if got := WireName(long); len([]rune(got)) != 200 || !strings.HasSuffix(got, ".pdf") {
		t.Fatalf("long name -> %q (%d)", got, len(got))
	}
	if got := WireName("  a\tb/c.jpg "); got != "a_b_c.jpg" {
		t.Fatalf("got %q", got)
	}
	deep := strings.Repeat(strings.Repeat("d", 50)+"/", 8) + "last"
	if got := wirePath(deep); len([]rune(got)) > 200 || !strings.HasSuffix(got, "/last") {
		t.Fatalf("deep path -> %q", got)
	}
}
