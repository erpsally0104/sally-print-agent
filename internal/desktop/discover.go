package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
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
	// ID is the scanner's id (identity.go) and Via how it can be reached
	// (USB, NETWORK); Stable says the id survives replugging.
	ID     string
	Via    []string
	Stable bool
	// Feeder: its capabilities list a document feeder.
	Feeder *bool
	// learned is the sighting key → id to remember, when the id came
	// from the capabilities.
	learned map[string]string
	// What the capabilities said about identity, for OpenFound's check.
	uuid, serial, make string
}

// Discoverer finds a scanner. address is the one typed on the status page,
// or empty.
type Discoverer func(ctx context.Context, address string, logf func(string, ...any)) (*Scanner, error)

// Looker lists every scanner the PC can find (Look).
type Looker func(ctx context.Context, address string, skip Skip, known map[string]string, logf func(string, ...any)) []Found

// Opener opens one scanner from the list (OpenFound).
type Opener func(ctx context.Context, f Found, logf func(string, ...any)) (*Scanner, error)

// netBase is one network address of a scanner.
type netBase struct {
	URL  string
	Root string
	// keys and txtUUID identify the sighting it came from.
	keys    sightingKeys
	txtUUID string
}

// Found is one scanner on the PC's list: every sighting with the same id,
// merged.
type Found struct {
	ID     string
	Name   string
	Detail string
	// Feeder is nil when no capabilities could be read.
	Feeder *bool
	Stable bool
	// USB lists its IPP-over-USB device paths, Net its network addresses
	// (HTTP before HTTPS).
	USB       []string
	Net       []netBase
	Answering bool
	// FirstSeen, LastSeen and Misses are kept by the agent's inventory.
	FirstSeen time.Time
	LastSeen  time.Time
	Misses    int

	// typed: it came from the address typed on the status page; mdns: an
	// mDNS advert.
	typed bool
	mdns  bool
	// devKey orders USB entries that share a name.
	devKey string
	// namedByCaps: Name came from the capabilities, which beat mDNS.
	namedByCaps bool
	// learned is the sighting key → id to remember.
	learned map[string]string
}

// Via lists how the scanner can be reached: USB first, each once.
func (f Found) Via() []string {
	var v []string
	if len(f.USB) > 0 {
		v = append(v, "USB")
	}
	if len(f.Net) > 0 {
		v = append(v, "NETWORK")
	}
	return v
}

// Kind is USB when it can be reached by USB, otherwise NETWORK.
func (f Found) Kind() string {
	if len(f.USB) > 0 {
		return "USB"
	}
	return "NETWORK"
}

// Skip names what Look must leave alone: the open scanner's own network
// base and its USB device.
type Skip struct {
	Bases  []string
	USBKey string
	// Cache, when set, lets Look reuse recent probes (inventoryLoop).
	Cache *ProbeCache
	// Seen holds the sighting keys of scanners already on the list, which
	// go ahead of new mDNS adverts.
	Seen map[string]bool
}

// ProbeCache remembers the last probe of each sighting, so the inventory
// does not open a USB scanner every minute: a USB device is probed again
// only when it is new, relinked, or failed more than 5 minutes ago, and an
// answering network scanner every 5 minutes.
type ProbeCache struct {
	mu sync.Mutex
	m  map[string]probe
}

type probe struct {
	caps      *escl.Capabilities
	answering bool
	linked    bool
	at        time.Time
}

const reprobeAfter = 5 * time.Minute

func (c *ProbeCache) get(key string) (probe, bool) {
	if c == nil {
		return probe{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.m[key]
	return p, ok
}

func (c *ProbeCache) put(key string, p probe) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]probe{}
	}
	c.m[key] = p
}

// sighting is one scanner seen one way, before merging.
type sighting struct {
	keys      sightingKeys
	name      string // from the capabilities, mDNS ty, or ""
	label     string // the mDNS instance label
	caps      *escl.Capabilities
	txtUUID   string
	answering bool
	usb       []string
	net       []netBase
	typed     bool
	mdns      bool
	devKey    string
}

// Look lists every scanner the PC can find: USB (Windows), the typed
// address, and mDNS (at most 32 instances, those seen before first). Each
// answering sighting's capabilities are read; sightings with the same id
// become one entry. It never opens what skip names.
func Look(ctx context.Context, address string, skip Skip, known map[string]string, logf func(string, ...any)) []Found {
	now := time.Now()
	var sights []sighting

	// USB: the interfaces of one device are one sighting.
	if paths, err := usbscan.FindAll(); err == nil {
		byKey := map[string]*sighting{}
		var keys []string
		linked := map[string]bool{}
		for _, p := range paths {
			k := usbscan.DeviceKey(p.Path)
			if k == skip.USBKey && skip.USBKey != "" {
				continue
			}
			s := byKey[k]
			if s == nil {
				s = &sighting{keys: usbKeys(k), devKey: k}
				byKey[k] = s
				keys = append(keys, k)
			}
			s.usb = append(s.usb, p.Path)
			if p.Present || p.Linked {
				linked[k] = true
			}
		}
		for _, k := range keys {
			s := byKey[k]
			if !linked[k] {
				// Neither present nor linked: listed as not answering,
				// without a probe.
				sights = append(sights, *s)
				continue
			}
			if c, ok := skip.Cache.get(s.keys.key); ok && c.linked && (c.answering || now.Sub(c.at) < reprobeAfter) {
				s.caps, s.answering = c.caps, c.answering
			} else {
				s.caps = probeUSB(ctx, s.usb, logf)
				s.answering = s.caps != nil
				skip.Cache.put(s.keys.key, probe{caps: s.caps, answering: s.answering, linked: true, at: now})
			}
			sights = append(sights, *s)
		}
		// A device that went away is relinked when it comes back.
		for _, k := range keys {
			if !linked[k] {
				skip.Cache.put(byKey[k].keys.key, probe{linked: false, at: now})
			}
		}
	}

	var net []sighting
	if address != "" {
		if bases, err := NormaliseAddress(address); err == nil && !skipped(bases, skip) {
			s := sighting{keys: addrKeys(address), typed: true}
			for _, b := range bases {
				s.net = append(s.net, netBase{URL: b, Root: "eSCL", keys: s.keys})
			}
			net = append(net, s)
		}
	}
	svcs, err := mdns.Browse(ctx, 2*time.Second)
	if err != nil {
		logf("mDNS search failed: %v", err)
	}
	net = append(net, mdnsSightings(svcs, skip, known)...)

	// Probe 4 at a time, 8 s each.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i := range net {
		s := &net[i]
		if c, ok := skip.Cache.get(s.keys.key); ok && c.answering && now.Sub(c.at) < reprobeAfter {
			s.caps, s.answering = c.caps, true
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, b := range s.net {
				caps, err := probeBase(ctx, b.URL, b.Root)
				if err == nil {
					s.caps, s.answering = caps, true
					break
				}
				logf("network scanner %s at %s did not answer: %v", s.keys.last, b.URL, err)
			}
			skip.Cache.put(s.keys.key, probe{caps: s.caps, answering: s.answering, at: now})
		}()
	}
	wg.Wait()
	sights = append(sights, net...)
	return mergeSightings(sights, known)
}

// skipped reports a base that skip names.
func skipped(bases []string, skip Skip) bool {
	for _, b := range bases {
		for _, s := range skip.Bases {
			if strings.EqualFold(b, s) {
				return true
			}
		}
	}
	return false
}

// maxMDNS bounds the mDNS instances probed per pass.
const maxMDNS = 32

// mdnsSightings turns mDNS services into sightings: the _uscan and _uscans
// records of one label and host are one sighting, HTTP first. Labels seen
// before (in known) come first, so a burst of new adverts cannot push them
// out; at most 32 are kept.
func mdnsSightings(svcs []mdns.Service, skip Skip, known map[string]string) []sighting {
	byKey := map[string]*sighting{}
	var order []string
	for _, svc := range svcs {
		k := mdnsKeys(svc.Label, svc.Host)
		s := byKey[k.key]
		if s == nil {
			s = &sighting{keys: k, label: svc.Label, mdns: true}
			byKey[k.key] = s
			order = append(order, k.key)
		}
		if svc.Name != svc.Label && s.name == "" {
			s.name = svc.Name
		}
		if s.txtUUID == "" {
			s.txtUUID = svc.UUID
		}
		b := netBase{URL: svc.BaseURL(), Root: svc.Root, keys: k, txtUUID: svc.UUID}
		if svc.Secure {
			s.net = append(s.net, b)
		} else {
			s.net = append([]netBase{b}, s.net...)
		}
	}
	var seen, fresh []sighting
	for _, k := range order {
		s := byKey[k]
		var urls []string
		for _, b := range s.net {
			urls = append(urls, b.URL)
		}
		if skipped(urls, skip) {
			continue
		}
		if _, ok := known[k]; ok || skip.Seen[k] {
			seen = append(seen, *s)
		} else {
			fresh = append(fresh, *s)
		}
	}
	out := append(seen, fresh...)
	if len(out) > maxMDNS {
		out = out[:maxMDNS]
	}
	return out
}

// probeUSB opens each path of one USB device in turn and reads its
// capabilities (15 s), then closes it.
func probeUSB(ctx context.Context, paths []string, logf func(string, ...any)) *escl.Capabilities {
	for _, p := range paths {
		port, err := usbscan.Open(p)
		if err != nil {
			continue
		}
		c := escl.NewClient(escl.NewStreamDoer(port), "eSCL")
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		caps, err := c.Capabilities(cctx)
		cancel()
		port.Close()
		if err == nil {
			return caps
		}
		logf("USB interface %s did not answer eSCL: %v", p, err)
	}
	return nil
}

// probeBase reads a network scanner's capabilities (8 s).
func probeBase(ctx context.Context, base, root string) (*escl.Capabilities, error) {
	d, err := escl.NewHTTPDoer(base)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return escl.NewClient(d, root).Capabilities(cctx)
}

// mergeSightings identifies each sighting and merges those with the same
// id: USB first, Via the union, Answering if any sighting answered. Two
// USB entries with one name get the details "USB 1", "USB 2" in DeviceKey
// order.
func mergeSightings(sights []sighting, known map[string]string) []Found {
	byID := map[string]*Found{}
	var order []string
	for _, s := range sights {
		id, stable, fromCaps := identify(s.caps, s.txtUUID, s.keys, known)
		f := byID[id]
		if f == nil {
			f = &Found{ID: id, Stable: stable}
			byID[id] = f
			order = append(order, id)
		}
		if fromCaps {
			if f.learned == nil {
				f.learned = map[string]string{}
			}
			f.learned[s.keys.key] = id
		}
		name := ""
		if s.caps != nil {
			name = strings.TrimSpace(s.caps.MakeAndModel)
			v := s.caps.Feeder
			if f.Feeder == nil || v {
				f.Feeder = &v
			}
		}
		if name == "" {
			name = s.name
		}
		byCaps := s.caps != nil && strings.TrimSpace(s.caps.MakeAndModel) != ""
		if name != "" && (f.Name == "" || (byCaps && !f.namedByCaps)) {
			f.Name, f.namedByCaps = name, byCaps
		}
		if f.Detail == "" && s.label != "" {
			f.Detail = safeDetail(s.label)
		}
		f.USB = append(f.USB, s.usb...)
		f.Net = append(f.Net, s.net...)
		f.Answering = f.Answering || s.answering
		f.typed = f.typed || s.typed
		f.mdns = f.mdns || s.mdns
		if f.devKey == "" {
			f.devKey = s.devKey
		}
	}
	out := make([]Found, 0, len(order))
	for _, id := range order {
		f := byID[id]
		if f.Name == "" {
			if len(f.USB) > 0 {
				f.Name = "USB scanner"
			} else {
				f.Name = "Network scanner"
			}
		}
		f.Name = cutRunes(f.Name, 120)
		out = append(out, *f)
	}
	numberUSBTwins(out)
	return out
}

// numberUSBTwins gives USB entries that share a name the details "USB 1",
// "USB 2"… in DeviceKey order.
func numberUSBTwins(fs []Found) {
	byName := map[string][]int{}
	for i, f := range fs {
		if len(f.USB) > 0 {
			byName[f.Name] = append(byName[f.Name], i)
		}
	}
	for _, idx := range byName {
		if len(idx) < 2 {
			continue
		}
		sort.Slice(idx, func(a, b int) bool { return fs[idx[a]].devKey < fs[idx[b]].devKey })
		for n, i := range idx {
			fs[i].Detail = fmt.Sprintf("USB %d", n+1)
		}
	}
}

// Discover is the automatic pick, exactly 0.2.0's: Look, then the first
// answering USB scanner, else the typed address, else the first mDNS
// scanner by name.
func Discover(ctx context.Context, address string, logf func(string, ...any)) (*Scanner, error) {
	found := Look(ctx, address, Skip{}, nil, logf)
	for _, f := range autoOrder(found) {
		s, err := OpenFound(ctx, f, logf)
		if err == nil {
			return s, nil
		}
		logf("scanner %s did not open: %v", f.Name, err)
	}
	return nil, nil
}

// autoOrder is the automatic pick's order among answering scanners: USB,
// then the typed address, then mDNS by name.
func autoOrder(found []Found) []Found {
	var usb, typed, net []Found
	for _, f := range found {
		switch {
		case !f.Answering:
		case len(f.USB) > 0:
			usb = append(usb, f)
		case f.typed:
			typed = append(typed, f)
		default:
			net = append(net, f)
		}
	}
	sort.SliceStable(net, func(i, j int) bool { return net[i].Name < net[j].Name })
	return append(append(usb, typed...), net...)
}

// OpenFound opens one scanner from the list: its USB paths first, then its
// network addresses. A device whose id is not f.ID is refused.
func OpenFound(ctx context.Context, f Found, logf func(string, ...any)) (*Scanner, error) {
	var last error = errors.New("the scanner has no address")
	for _, p := range f.USB {
		port, err := usbscan.Open(p)
		if err != nil {
			last = err
			continue
		}
		c := escl.NewClient(escl.NewStreamDoer(port), "eSCL")
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		caps, err := c.Capabilities(cctx)
		cancel()
		if err != nil {
			logf("USB interface %s did not answer eSCL: %v", p, err)
			port.Close()
			last = err
			continue
		}
		id, stable, fromCaps := identify(caps, "", usbKeys(usbscan.DeviceKey(p)), nil)
		if id != f.ID {
			port.Close()
			last = fmt.Errorf("the scanner at %s is another scanner now", p)
			continue
		}
		s := newScanner("USB", caps, p, c, func() { port.Close() }, "USB scanner")
		s.ID, s.Stable, s.Via = id, stable, f.Via()
		if fromCaps {
			s.learned = map[string]string{usbKeys(usbscan.DeviceKey(p)).key: id}
		}
		return s, nil
	}
	for _, b := range f.Net {
		s, err := openBase(ctx, b.URL, b.Root, f.Name)
		if err != nil {
			last = err
			continue
		}
		caps := &escl.Capabilities{UUID: s.uuid, SerialNumber: s.serial, MakeAndModel: s.make}
		id, stable, fromCaps := identify(caps, b.txtUUID, b.keys, nil)
		if id != f.ID {
			s.Close()
			last = fmt.Errorf("the scanner at %s is another scanner now", b.URL)
			continue
		}
		s.ID, s.Stable, s.Via = id, stable, f.Via()
		s.learned = nil
		if fromCaps {
			s.learned = map[string]string{b.keys.key: id}
		}
		return s, nil
	}
	return nil, last
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

// openBase opens a network scanner and reads its capabilities. Its id is
// worked out as for a typed address; OpenFound sets the sighting's own.
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
	if name == "" {
		name = "Network scanner"
	}
	s := newScanner("NETWORK", caps, base, c, func() { d.Close() }, name)
	k := addrKeys(base)
	id, stable, fromCaps := identify(caps, "", k, nil)
	s.ID, s.Stable, s.Via = id, stable, []string{"NETWORK"}
	if fromCaps {
		s.learned = map[string]string{k.key: id}
	}
	return s, nil
}

// newScanner is an open scanner described by its capabilities.
func newScanner(kind string, caps *escl.Capabilities, where string, c *escl.Client, closeFn func(), fallback string) *Scanner {
	name := strings.TrimSpace(caps.MakeAndModel)
	if name == "" {
		name = fallback
	}
	feeder := caps.Feeder
	return &Scanner{
		Kind: kind, Name: cutRunes(name, 120), Where: where, Client: c, Close: closeFn,
		Feeder: &feeder, uuid: caps.UUID, serial: caps.SerialNumber, make: caps.MakeAndModel,
	}
}
