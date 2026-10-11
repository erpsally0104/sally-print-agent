package desktop

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/escl"
	"github.com/sallyerp/sally-print-agent/internal/mdns"
	"github.com/sallyerp/sally-print-agent/internal/usbscan"
)

// Scanner is one scanner the agent can talk to.
type Scanner struct {
	Kind   string // USB | NETWORK
	Name   string
	Where  string // device path or base URL, for the log
	Client *escl.Client
	Close  func()
}

// Discoverer finds a scanner. address is the one typed on the status page,
// or empty.
type Discoverer func(ctx context.Context, address string, logf func(string, ...any)) (*Scanner, error)

// Discover is the real search: USB first (the scanner on the desk), then a
// typed address, then whatever mDNS finds.
func Discover(ctx context.Context, address string, logf func(string, ...any)) (*Scanner, error) {
	if s := findUSB(ctx, logf); s != nil {
		return s, nil
	}
	if address != "" {
		s, err := openAddress(ctx, address)
		if err == nil {
			return s, nil
		}
		logf("scanner at %s did not answer: %v", address, err)
	}
	svcs, err := mdns.Browse(ctx, 2*time.Second)
	if err != nil {
		logf("mDNS search failed: %v", err)
	}
	for _, svc := range svcs {
		s, err := openBase(ctx, svc.BaseURL(), svc.Root, svc.Name)
		if err == nil {
			return s, nil
		}
		logf("network scanner %s at %s did not answer: %v", svc.Name, svc.BaseURL(), err)
	}
	return nil, nil
}

func findUSB(ctx context.Context, logf func(string, ...any)) *Scanner {
	paths, err := usbscan.Find()
	if err != nil || len(paths) == 0 {
		return nil
	}
	for _, p := range paths {
		port, err := usbscan.Open(p)
		if err != nil {
			continue
		}
		d := escl.NewStreamDoer(port)
		c := escl.NewClient(d, "eSCL")
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		caps, err := c.Capabilities(cctx)
		cancel()
		if err != nil {
			logf("USB interface %s did not answer eSCL: %v", p, err)
			port.Close()
			continue
		}
		name := caps.MakeAndModel
		if name == "" {
			name = "USB scanner"
		}
		return &Scanner{Kind: "USB", Name: name, Where: p, Client: c, Close: func() { port.Close() }}
	}
	return nil
}

// NormaliseAddress checks a typed scanner address: an IP or host name, with
// an optional port, optionally as an http(s) URL. It returns the candidate
// base URLs to try, in order.
func NormaliseAddress(in string) ([]string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, fmt.Errorf("type the scanner's IP address")
	}
	if len(in) > 200 {
		return nil, fmt.Errorf("that address is too long")
	}
	if strings.Contains(in, "://") {
		u, err := url.Parse(in)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("that is not a scanner address")
		}
		if !validHost(u.Hostname()) {
			return nil, fmt.Errorf("that is not a scanner address")
		}
		return []string{u.Scheme + "://" + u.Host}, nil
	}
	host, port := in, ""
	if h, p, err := net.SplitHostPort(in); err == nil {
		host, port = h, p
	}
	if !validHost(host) {
		return nil, fmt.Errorf("that is not an IP address or a host name")
	}
	if port != "" {
		var n int
		if _, err := fmt.Sscanf(port, "%d", &n); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("that port is not valid")
		}
		hp := net.JoinHostPort(host, port)
		if port == "443" {
			return []string{"https://" + hp}, nil
		}
		return []string{"http://" + hp, "https://" + hp}, nil
	}
	return []string{"http://" + net.JoinHostPort(host, "80"), "https://" + net.JoinHostPort(host, "443")}, nil
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func openAddress(ctx context.Context, address string) (*Scanner, error) {
	bases, err := NormaliseAddress(address)
	if err != nil {
		return nil, err
	}
	var last error
	for _, b := range bases {
		s, err := openBase(ctx, b, "eSCL", "")
		if err == nil {
			return s, nil
		}
		last = err
	}
	return nil, last
}

func openBase(ctx context.Context, base, root, name string) (*Scanner, error) {
	d, err := escl.NewHTTPDoer(base)
	if err != nil {
		return nil, err
	}
	c := escl.NewClient(d, root)
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	caps, err := c.Capabilities(cctx)
	if err != nil {
		d.Close()
		return nil, err
	}
	if caps.MakeAndModel != "" {
		name = caps.MakeAndModel
	}
	if name == "" {
		name = "Network scanner"
	}
	return &Scanner{Kind: "NETWORK", Name: name, Where: base, Client: c, Close: func() { d.Close() }}, nil
}
