// Package escl speaks eSCL ("AirScan"), the HTTP+XML scan protocol every
// current network and IPP-over-USB scanner understands.
//
// The protocol is the same over both paths; only the transport differs. Over
// the network it is ordinary HTTP(S). Over USB it is HTTP/1.1 written by hand
// onto a device handle (see StreamDoer and internal/usbscan). Both satisfy
// Doer, so the client above them never knows which one it is talking to.
package escl

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Request is one eSCL call. Path is absolute ("/eSCL/ScannerStatus").
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// Response is one eSCL reply with its body already read in full. eSCL bodies
// are small XML documents or one scanned page (about a megabyte), so holding
// them in memory is simpler than streaming and keeps the USB channel clean:
// the next request can only be written once this reply is off the wire.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Doer carries eSCL requests to one scanner.
type Doer interface {
	Do(ctx context.Context, req *Request) (*Response, error)
}

// MaxBody caps any one reply. A page at 300 dpi colour is about 1 MB; a
// scanner sending more than this is misbehaving.
const MaxBody = 64 << 20

// HTTPDoer talks eSCL over the network.
type HTTPDoer struct {
	base   string // scheme://host:port, no trailing slash
	client *http.Client
}

// NewHTTPDoer returns a Doer for a network scanner at base
// ("http://192.168.1.20:80" or "https://192.168.1.20:443").
//
// Scanners serve HTTPS with a self-signed certificate that no CA can vouch
// for. The certificate check is therefore switched off, but only inside this
// one client, which is only ever pointed at this one LAN scanner. It never
// affects the client that talks to Sally.
func NewHTTPDoer(base string) (*HTTPDoer, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("escl: bad scanner address %q", base)
	}
	tr := &http.Transport{
		Proxy:               nil, // a LAN scanner is never behind the office proxy
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if u.Scheme == "https" {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed LAN scanner, scoped to this client
			ServerName:         u.Hostname(),
		}
	}
	return &HTTPDoer{
		base:   u.Scheme + "://" + u.Host,
		client: &http.Client{Transport: tr, Timeout: 90 * time.Second},
	}, nil
}

// Do sends req.
func (d *HTTPDoer) Do(ctx context.Context, req *Request) (*Response, error) {
	var body io.Reader
	if req.Body != nil {
		body = strings.NewReader(string(req.Body))
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, d.base+req.Path, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	resp, err := d.client.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBody {
		return nil, fmt.Errorf("escl: reply larger than %d bytes", MaxBody)
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

// Close releases idle connections.
func (d *HTTPDoer) Close() error {
	d.client.CloseIdleConnections()
	return nil
}
