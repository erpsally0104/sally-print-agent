package escl

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakePort plays an IPP-over-USB handle in memory. Bytes in pending are what
// the device has already sent; reply decides what it sends after each
// request. A read with nothing pending times out, like the real handle.
type fakePort struct {
	pending  [][]byte
	reply    func(req string) [][]byte
	written  []string
	reads    int
	maxChunk int
}

func (f *fakePort) Write(p []byte) (int, error) {
	f.written = append(f.written, string(p))
	if f.reply != nil {
		f.pending = append(f.pending, f.reply(string(p))...)
	}
	return len(p), nil
}

func (f *fakePort) ReadTimeout(p []byte, _ time.Duration) (int, error) {
	f.reads++
	if len(f.pending) == 0 {
		return 0, ErrTimeout
	}
	chunk := f.pending[0]
	n := len(chunk)
	if n > len(p) {
		n = len(p)
	}
	if f.maxChunk > 0 && n > f.maxChunk {
		n = f.maxChunk
	}
	copy(p, chunk[:n])
	if n == len(chunk) {
		f.pending = f.pending[1:]
	} else {
		f.pending[0] = chunk[n:]
	}
	return n, nil
}

func (f *fakePort) Close() error { return nil }

func fastDoer(p Port) *StreamDoer {
	d := NewStreamDoer(p)
	d.DrainWait = time.Millisecond
	d.ReadWait = time.Millisecond
	return d
}

func fakeJPEG(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	b[0], b[1] = 0xFF, 0xD8
	return b
}

func chunked(body []byte, size int) string {
	var b strings.Builder
	for len(body) > 0 {
		n := size
		if n > len(body) {
			n = len(body)
		}
		fmt.Fprintf(&b, "%x\r\n%s\r\n", n, body[:n])
		body = body[n:]
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func TestStreamReadsAChunkedPage(t *testing.T) {
	page := fakeJPEG(900_000)
	port := &fakePort{maxChunk: 16 << 10}
	port.reply = func(req string) [][]byte {
		head := "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nTransfer-Encoding: chunked\r\n\r\n"
		return [][]byte{[]byte(head + chunked(page, 32<<10))}
	}
	resp, err := fastDoer(port).Do(context.Background(), &Request{Method: "GET", Path: "/eSCL/ScanJobs/1/NextDocument"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !bytes.Equal(resp.Body, page) {
		t.Fatalf("status %d, body %d bytes (want %d)", resp.StatusCode, len(resp.Body), len(page))
	}
}

func TestStreamDrainsStaleBytesBeforeTheRequest(t *testing.T) {
	// The tail of an earlier reply is still on the channel. Without the
	// drain it would be read as the answer to this request.
	stale := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nSTALE"
	port := &fakePort{pending: [][]byte{[]byte(stale), []byte("more junk")}}
	port.reply = func(req string) [][]byte {
		body := `<scan:ScannerStatus><pwg:State>Idle</pwg:State></scan:ScannerStatus>`
		return [][]byte{[]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))}
	}
	resp, err := fastDoer(port).Do(context.Background(), &Request{Method: "GET", Path: "/eSCL/ScannerStatus"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(resp.Body), "STALE") || ParseStatus(resp.Body).State != "Idle" {
		t.Fatalf("read the stale reply: %q", resp.Body)
	}
}

func TestStreamWritesEachRequestWholeWithTheUSBHost(t *testing.T) {
	port := &fakePort{}
	port.reply = func(string) [][]byte {
		return [][]byte{[]byte("HTTP/1.1 201 Created\r\nLocation: http://localhost:60000/eSCL/ScanJobs/77\r\nContent-Length: 0\r\n\r\n")}
	}
	c := NewClient(fastDoer(port), "eSCL")
	job, err := c.StartJob(context.Background(), ScanSettings("2.9", true))
	if err != nil {
		t.Fatal(err)
	}
	if job != "/eSCL/ScanJobs/77" {
		t.Fatalf("job path %q", job)
	}
	if len(port.written) != 1 {
		t.Fatalf("the request went out in %d writes, want 1", len(port.written))
	}
	w := port.written[0]
	if !strings.HasPrefix(w, "POST /eSCL/ScanJobs HTTP/1.1\r\nHost: localhost:60000\r\n") {
		t.Fatalf("request head: %q", w[:60])
	}
	if !strings.Contains(w, fmt.Sprintf("Content-Length: %d\r\n", len(ScanSettings("2.9", true)))) {
		t.Fatal("missing Content-Length")
	}
}

func TestStreamTimesOutOnASilentDevice(t *testing.T) {
	port := &fakePort{}
	_, err := fastDoer(port).Do(context.Background(), &Request{Method: "GET", Path: "/eSCL/ScannerStatus"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want a timeout", err)
	}
}

func TestStreamReadsABodyWithNoLengthUntilQuiet(t *testing.T) {
	port := &fakePort{}
	port.reply = func(string) [][]byte {
		return [][]byte{[]byte("HTTP/1.1 200 OK\r\n\r\n<a>"), []byte("b</a>")}
	}
	resp, err := fastDoer(port).Do(context.Background(), &Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "<a>b</a>" {
		t.Fatalf("body %q", resp.Body)
	}
}

func TestScanSettings(t *testing.T) {
	x := string(ScanSettings("2.9", true))
	if strings.Contains(x, "BlankPageDetection") {
		t.Fatal("BlankPageDetectionAndRemoval must never be sent: the HP N4000 answers 409")
	}
	for _, want := range []string{
		`xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm"`,
		`xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03"`,
		"<pwg:Version>2.9</pwg:Version>",
		"<scan:Intent>Document</scan:Intent>",
		"<pwg:Height>3508</pwg:Height>",
		"<pwg:Width>2480</pwg:Width>",
		"<pwg:XOffset>0</pwg:XOffset>",
		"<pwg:YOffset>0</pwg:YOffset>",
		"<pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>",
		"<pwg:InputSource>Feeder</pwg:InputSource>",
		"<scan:Duplex>true</scan:Duplex>",
		"<scan:ColorMode>RGB24</scan:ColorMode>",
		"<scan:XResolution>300</scan:XResolution>",
		"<scan:YResolution>300</scan:YResolution>",
		"<pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>",
		"<scan:DocumentFormatExt>image/jpeg</scan:DocumentFormatExt>",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %s", want)
		}
	}
	// Well-formed XML.
	if err := xml.Unmarshal([]byte(x), new(struct{})); err != nil {
		t.Fatalf("not well-formed: %v", err)
	}
	// A hostile or odd version never reaches the XML.
	if y := string(ScanSettings("</pwg:Version><evil/>", true)); !strings.Contains(y, "<pwg:Version>2.63</pwg:Version>") {
		t.Fatal("an odd version must fall back to 2.63")
	}
}

func TestParseCapabilities(t *testing.T) {
	c := ParseCapabilities([]byte(`<?xml version="1.0"?><scan:ScannerCapabilities xmlns:pwg="` + NSPWG + `" xmlns:scan="` + NSScan + `"><pwg:Version>2.9</pwg:Version><pwg:MakeAndModel>HP ScanJet Pro N4000 snw1</pwg:MakeAndModel></scan:ScannerCapabilities>`))
	if c.Version != "2.9" || c.MakeAndModel != "HP ScanJet Pro N4000 snw1" {
		t.Fatalf("%+v", c)
	}
	if ParseCapabilities([]byte(`<x/>`)).Version != "2.63" {
		t.Fatal("missing version must default to 2.63")
	}
	if c.Duplex {
		t.Fatal("capabilities without a duplex feeder must read as simplex")
	}
}

func TestParseCapabilitiesDuplex(t *testing.T) {
	head := `<scan:ScannerCapabilities xmlns:pwg="` + NSPWG + `" xmlns:scan="` + NSScan + `"><pwg:Version>2.63</pwg:Version>`
	for name, c := range map[string]struct {
		xml  string
		want bool
	}{
		"duplex input caps": {`<scan:Adf><scan:AdfSimplexInputCaps><scan:MinWidth>1</scan:MinWidth></scan:AdfSimplexInputCaps><scan:AdfDuplexInputCaps><scan:MinWidth>1</scan:MinWidth></scan:AdfDuplexInputCaps><scan:AdfOptions><scan:AdfOption>DetectPaperLoaded</scan:AdfOption></scan:AdfOptions></scan:Adf>`, true},
		"duplex option":     {`<scan:Adf><scan:AdfSimplexInputCaps/><scan:AdfOptions><scan:AdfOption>DetectPaperLoaded</scan:AdfOption><scan:AdfOption>Duplex</scan:AdfOption></scan:AdfOptions></scan:Adf>`, true},
		"simplex feeder":    {`<scan:Adf><scan:AdfSimplexInputCaps><scan:MinWidth>1</scan:MinWidth></scan:AdfSimplexInputCaps><scan:AdfOptions><scan:AdfOption>DetectPaperLoaded</scan:AdfOption></scan:AdfOptions></scan:Adf>`, false},
		"no feeder":         {`<scan:Platen><scan:PlatenInputCaps/></scan:Platen>`, false},
	} {
		if got := ParseCapabilities([]byte(head + c.xml + `</scan:ScannerCapabilities>`)).Duplex; got != c.want {
			t.Errorf("%s: duplex %v", name, got)
		}
	}
	if !strings.Contains(string(ScanSettings("2.63", false)), "<scan:Duplex>false</scan:Duplex>") {
		t.Fatal("a simplex scanner must be asked for one side")
	}
}

func TestParseStatus(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<scan:ScannerStatus xmlns:scan="` + NSScan + `" xmlns:pwg="` + NSPWG + `">
  <pwg:Version>2.9</pwg:Version>
  <pwg:State>Idle</pwg:State>
  <scan:AdfState>ScannerAdfJam</scan:AdfState>
  <scan:Jobs><scan:JobInfo><pwg:JobState>Aborted</pwg:JobState></scan:JobInfo></scan:Jobs>
</scan:ScannerStatus>`
	st := ParseStatus([]byte(body))
	if st.State != "Idle" || st.AdfState != "ScannerAdfJam" {
		t.Fatalf("%+v", st)
	}
	if !st.Jammed() || st.Loaded() || !st.Idle() {
		t.Fatalf("predicates wrong for %+v", st)
	}
	for adf, loaded := range map[string]bool{"ScannerAdfLoaded": true, "ScannerAdfEmpty": false, "": false} {
		if (Status{State: "Idle", AdfState: adf}).Loaded() != loaded {
			t.Errorf("%q loaded should be %v", adf, loaded)
		}
	}
	if !(Status{AdfState: "ScannerAdfDoorOpen"}).DoorOpen() {
		t.Error("door open")
	}
}

func TestJobPath(t *testing.T) {
	for in, want := range map[string]string{
		"http://192.168.1.5:80/eSCL/ScanJobs/abc": "/eSCL/ScanJobs/abc",
		"https://scanner.local/eSCL/ScanJobs/9/":  "/eSCL/ScanJobs/9",
		"/eSCL/ScanJobs/12":                       "/eSCL/ScanJobs/12",
		"ScanJobs/12":                             "/eSCL/ScanJobs/12",
	} {
		got, err := JobPath(in, "/eSCL")
		if err != nil || got != want {
			t.Errorf("%q → %q, %v (want %q)", in, got, err, want)
		}
	}
	if _, err := JobPath("", "/eSCL"); err == nil {
		t.Error("an empty Location must be an error")
	}
}

func TestClientOverHTTPPullsPagesUntil404(t *testing.T) {
	pages := [][]byte{fakeJPEG(1000), fakeJPEG(2000)}
	served, notReady := 0, 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/eSCL/ScanJobs":
			w.Header().Set("Location", "http://"+r.Host+"/eSCL/ScanJobs/5")
			w.WriteHeader(201)
		case r.URL.Path == "/eSCL/ScanJobs/5/NextDocument":
			if notReady > 0 {
				notReady--
				w.WriteHeader(503)
				return
			}
			if served == len(pages) {
				w.WriteHeader(404)
				return
			}
			w.Write(pages[served])
			served++
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	d, err := NewHTTPDoer(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(d, "")
	job, err := c.StartJob(context.Background(), ScanSettings(c.Version, c.Duplex))
	if err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	for {
		p, done, err := c.NextDocument(context.Background(), job)
		if errors.Is(err, ErrNotReady) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		got = append(got, p)
	}
	if len(got) != 2 || !bytes.Equal(got[1], pages[1]) {
		t.Fatalf("got %d pages", len(got))
	}
}

func TestNextDocumentRejectsNonJPEG(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("%PDF")) }))
	defer srv.Close()
	d, _ := NewHTTPDoer(srv.URL)
	if _, _, err := NewClient(d, "").NextDocument(context.Background(), "/eSCL/ScanJobs/1"); !errors.Is(err, ErrNotJPEG) {
		t.Fatalf("got %v", err)
	}
}
