package escl

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ErrTimeout is what a Port returns when nothing arrived within the wait.
var ErrTimeout = errors.New("escl: read timed out")

// Port is a raw byte channel to a scanner: the IPP-over-USB device handle on
// Windows, or an in-memory fake in tests.
//
// Two properties of the real USB handle shape this interface:
//
//   - Write must hand every byte to the device before it returns. A small
//     buffered write is only flushed when the handle closes, which makes
//     every reply arrive one call late.
//   - Every read needs a timeout. A device that has nothing to say simply
//     never completes the read.
type Port interface {
	Write(p []byte) (int, error)
	// ReadTimeout reads what is available, waiting at most d for the first
	// byte. It returns ErrTimeout (possibly wrapped) when nothing came.
	ReadTimeout(p []byte, d time.Duration) (int, error)
	Close() error
}

// StreamDoer speaks HTTP/1.1 by hand over a Port.
type StreamDoer struct {
	Port Port
	// Host is sent as the Host header. IPP-over-USB devices expect
	// "localhost:60000".
	Host string
	// DrainWait is how long the drain waits for stale bytes before deciding
	// the channel is clean. ReadWait is the wait for each read of a reply.
	DrainWait time.Duration
	ReadWait  time.Duration
	// MaxDrain bounds the drain so a device streaming garbage cannot hold
	// the caller forever.
	MaxDrain time.Duration

	mu sync.Mutex
}

// NewStreamDoer returns a StreamDoer with the defaults that worked on a real
// HP ScanJet Pro N4000 over IPP-over-USB.
func NewStreamDoer(p Port) *StreamDoer {
	return &StreamDoer{
		Port:      p,
		Host:      "localhost:60000",
		DrainWait: 150 * time.Millisecond,
		ReadWait:  30 * time.Second,
		MaxDrain:  5 * time.Second,
	}
}

// Close closes the port.
func (d *StreamDoer) Close() error { return d.Port.Close() }

// Do drains stale bytes, writes the request in one piece and reads one reply.
// Calls are serialised: the channel carries one exchange at a time.
func (d *StreamDoer) Do(ctx context.Context, req *Request) (*Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, err := d.drain(); err != nil {
		return nil, fmt.Errorf("escl: draining the channel: %w", err)
	}
	if err := writeFull(d.Port, d.encode(req)); err != nil {
		return nil, fmt.Errorf("escl: writing the request: %w", err)
	}
	return d.read(ctx, req.Method)
}

// drain reads and throws away anything waiting on the channel: the tail of a
// reply that an earlier, failed call never finished reading. Without this a
// stale reply would be taken as the answer to the next request.
func (d *StreamDoer) drain() (int, error) {
	buf := make([]byte, 64<<10)
	total := 0
	deadline := time.Now().Add(d.MaxDrain)
	for time.Now().Before(deadline) {
		n, err := d.Port.ReadTimeout(buf, d.DrainWait)
		total += n
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
	return total, nil
}

func (d *StreamDoer) encode(req *Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", d.Host)
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if http.CanonicalHeaderKey(k) == "Content-Length" || http.CanonicalHeaderKey(k) == "Host" {
			continue
		}
		for _, v := range req.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	if len(req.Body) > 0 || req.Method == http.MethodPost || req.Method == http.MethodPut {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(req.Body))
	}
	b.WriteString("\r\n")
	b.Write(req.Body)
	return b.Bytes()
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (d *StreamDoer) read(ctx context.Context, method string) (*Response, error) {
	tr := &timeoutReader{ctx: ctx, port: d.Port, wait: d.ReadWait}
	br := bufio.NewReaderSize(tr, 64<<10)
	for {
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			return nil, fmt.Errorf("escl: reading the reply: %w", err)
		}
		// Skip interim replies (100 Continue); the real one follows.
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			resp.Body.Close()
			continue
		}
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
			// No length and not chunked: the body runs until the device
			// stops sending. On a handle that never closes, "stops" can
			// only mean a quiet spell.
			tr.eofOnTimeout = true
			tr.wait = 2 * time.Second
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("escl: reading the reply body: %w", err)
		}
		if len(body) > MaxBody {
			return nil, fmt.Errorf("escl: reply larger than %d bytes", MaxBody)
		}
		return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
	}
}

// timeoutReader turns a Port into an io.Reader whose every read has a
// deadline. A device that goes quiet mid-reply yields ErrTimeout instead of
// hanging the agent.
type timeoutReader struct {
	ctx          context.Context
	port         Port
	wait         time.Duration
	eofOnTimeout bool
}

func (r *timeoutReader) Read(p []byte) (int, error) {
	// USB can deliver zero-length packets; a few in a row are normal, an
	// endless run of them is a device saying nothing.
	for empty := 0; empty < 50; empty++ {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := r.port.ReadTimeout(p, r.wait)
		if n > 0 {
			return n, nil
		}
		if err != nil {
			if errors.Is(err, ErrTimeout) && r.eofOnTimeout {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	if r.eofOnTimeout {
		return 0, io.EOF
	}
	return 0, ErrTimeout
}
