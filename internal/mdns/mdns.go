// Package mdns finds eSCL scanners on the LAN with a minimal multicast DNS
// query, written here rather than imported (the agent has no dependencies).
//
// It asks for PTR records of _uscan._tcp.local (HTTP) and _uscans._tcp.local
// (HTTPS), and reads the PTR, SRV, TXT and A records in the answers. TXT "rs"
// is the eSCL resource path, usually "eSCL"; TXT "ty" is the model name.
package mdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Service names browsed.
const (
	ServiceHTTP  = "_uscan._tcp.local."
	ServiceHTTPS = "_uscans._tcp.local."
)

// DNS record types used.
const (
	TypeA   = 1
	TypePTR = 12
	TypeTXT = 16
	TypeSRV = 33
)

// BuildQuery builds a query packet asking for qtype of each name.
func BuildQuery(id uint16, qtype uint16, names ...string) ([]byte, error) {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[4:], uint16(len(names)))
	for _, n := range names {
		var err error
		if b, err = appendName(b, n); err != nil {
			return nil, err
		}
		b = binary.BigEndian.AppendUint16(b, qtype)
		b = binary.BigEndian.AppendUint16(b, 1) // class IN
	}
	return b, nil
}

func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0), nil
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("mdns: bad label in %q", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}

// Record is one parsed resource record.
type Record struct {
	Name string
	Type uint16
	// Data by type.
	Target string   // PTR, SRV
	Port   uint16   // SRV
	TXT    []string // TXT
	IP     net.IP   // A
}

// Parse reads every answer, authority and additional record of a packet.
// Malformed packets give an error; nothing in them is trusted beyond names,
// ports and addresses.
func Parse(msg []byte) ([]Record, error) {
	if len(msg) < 12 {
		return nil, errors.New("mdns: short packet")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	rrs := int(binary.BigEndian.Uint16(msg[6:])) + int(binary.BigEndian.Uint16(msg[8:])) + int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n + 4
		if off > len(msg) {
			return nil, errors.New("mdns: truncated question")
		}
	}
	var out []Record
	for i := 0; i < rrs; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return out, err
		}
		off = n
		if off+10 > len(msg) {
			return out, errors.New("mdns: truncated record")
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return out, errors.New("mdns: truncated record data")
		}
		rd := msg[off : off+rdlen]
		r := Record{Name: name, Type: typ}
		switch typ {
		case TypePTR:
			if r.Target, _, err = readName(msg, off); err != nil {
				return out, err
			}
		case TypeSRV:
			if rdlen < 7 {
				return out, errors.New("mdns: short SRV")
			}
			r.Port = binary.BigEndian.Uint16(rd[4:])
			if r.Target, _, err = readName(msg, off+6); err != nil {
				return out, err
			}
		case TypeTXT:
			for j := 0; j < len(rd); {
				l := int(rd[j])
				j++
				if j+l > len(rd) {
					break
				}
				r.TXT = append(r.TXT, string(rd[j:j+l]))
				j += l
			}
		case TypeA:
			if rdlen == 4 {
				r.IP = net.IPv4(rd[0], rd[1], rd[2], rd[3])
			}
		}
		out = append(out, r)
		off += rdlen
	}
	return out, nil
}

// readName reads a possibly compressed name at off and returns it (with a
// trailing dot, case kept) and the offset just past it.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errors.New("mdns: name runs off the packet")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, ".") + ".", end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("mdns: bad pointer")
			}
			if end < 0 {
				end = off + 2
			}
			jumps++
			if jumps > 20 {
				return "", 0, errors.New("mdns: pointer loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errors.New("mdns: bad label")
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("mdns: label runs off the packet")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
			if len(labels) > 64 {
				return "", 0, errors.New("mdns: name too long")
			}
		}
	}
}

// Service is one scanner found.
type Service struct {
	Instance string // "HP ScanJet Pro N4000 [ABCDEF]._uscan._tcp.local."
	Name     string // model from TXT ty, or the instance label
	Host     string
	IP       net.IP
	Port     uint16
	Secure   bool   // _uscans: HTTPS
	Root     string // TXT rs, "eSCL" by default
}

// BaseURL is scheme://ip:port for the eSCL client.
func (s Service) BaseURL() string {
	scheme := "http"
	if s.Secure {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(s.IP.String(), fmt.Sprint(s.Port)))
}

// Resolve joins PTR → SRV/TXT → A records into services. Only services with
// an address and a port are returned. HTTP and HTTPS entries of the same
// instance stay separate; callers may prefer either.
func Resolve(recs []Record) []Service {
	srv := map[string]Record{}
	txt := map[string][]string{}
	addr := map[string]net.IP{}
	var ptrs []Record
	for _, r := range recs {
		switch r.Type {
		case TypePTR:
			if isService(r.Name) {
				ptrs = append(ptrs, r)
			}
		case TypeSRV:
			srv[key(r.Name)] = r
		case TypeTXT:
			txt[key(r.Name)] = r.TXT
		case TypeA:
			if r.IP != nil {
				if _, ok := addr[key(r.Name)]; !ok {
					addr[key(r.Name)] = r.IP
				}
			}
		}
	}
	seen := map[string]bool{}
	var out []Service
	for _, p := range ptrs {
		if seen[key(p.Target)] {
			continue
		}
		seen[key(p.Target)] = true
		s, ok := srv[key(p.Target)]
		if !ok {
			continue
		}
		ip := addr[key(s.Target)]
		if ip == nil {
			continue
		}
		svc := Service{
			Instance: p.Target,
			Host:     s.Target,
			IP:       ip,
			Port:     s.Port,
			Secure:   strings.EqualFold(p.Name, ServiceHTTPS),
			Root:     "eSCL",
			Name:     instanceLabel(p.Target),
		}
		for _, kv := range txt[key(p.Target)] {
			k, v, _ := strings.Cut(kv, "=")
			switch strings.ToLower(k) {
			case "rs":
				svc.Root = strings.Trim(v, "/")
			case "ty":
				if v != "" {
					svc.Name = v
				}
			}
		}
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return !out[i].Secure && out[j].Secure
	})
	return out
}

func key(name string) string { return strings.ToLower(name) }

func isService(name string) bool {
	return strings.EqualFold(name, ServiceHTTP) || strings.EqualFold(name, ServiceHTTPS)
}

func instanceLabel(instance string) string {
	for _, suffix := range []string{"." + ServiceHTTP, "." + ServiceHTTPS} {
		if len(instance) > len(suffix) && strings.EqualFold(instance[len(instance)-len(suffix):], suffix) {
			return instance[:len(instance)-len(suffix)]
		}
	}
	return instance
}

// Browse sends one query (and one follow-up for anything half-answered) and
// collects answers for wait. It uses a "legacy" one-shot query from an
// ephemeral port, which responders answer by unicast to that port, so it
// needs no access to port 5353 and coexists with Bonjour or Windows' own
// mDNS service.
func Browse(ctx context.Context, wait time.Duration) ([]Service, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	q, err := BuildQuery(0x5a11, TypePTR, ServiceHTTP, ServiceHTTPS)
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteToUDP(q, group); err != nil {
		return nil, err
	}

	var recs []Record
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	followed := false
	buf := make([]byte, 9000)
	for {
		if ctx.Err() != nil {
			return Resolve(recs), ctx.Err()
		}
		// Half way through, ask directly for what is missing.
		if !followed && time.Until(deadline) < wait/2 {
			followed = true
			if fq := followUp(recs); fq != nil {
				_, _ = conn.WriteToUDP(fq, group)
			}
		}
		step := time.Now().Add(200 * time.Millisecond)
		if step.After(deadline) {
			step = deadline
		}
		_ = conn.SetReadDeadline(step)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if !time.Now().Before(deadline) {
					return Resolve(recs), nil
				}
				continue
			}
			return Resolve(recs), err
		}
		if rs, err := Parse(buf[:n]); err == nil || len(rs) > 0 {
			recs = append(recs, rs...)
		}
	}
}

// followUp asks for SRV/TXT of instances seen without them, and A of hosts
// seen without an address.
func followUp(recs []Record) []byte {
	have := map[string]map[uint16]bool{}
	for _, r := range recs {
		if have[key(r.Name)] == nil {
			have[key(r.Name)] = map[uint16]bool{}
		}
		have[key(r.Name)][r.Type] = true
	}
	var srvNames, aNames []string
	for _, r := range recs {
		if r.Type == TypePTR && isService(r.Name) && !have[key(r.Target)][TypeSRV] {
			srvNames = append(srvNames, r.Target)
		}
		if r.Type == TypeSRV && !have[key(r.Target)][TypeA] {
			aNames = append(aNames, r.Target)
		}
	}
	if len(srvNames) == 0 && len(aNames) == 0 {
		return nil
	}
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], 0x5a12)
	count := 0
	add := func(name string, t uint16) {
		nb, err := appendName(b, name)
		if err != nil {
			return
		}
		b = binary.BigEndian.AppendUint16(nb, t)
		b = binary.BigEndian.AppendUint16(b, 1)
		count++
	}
	for _, n := range srvNames {
		add(n, TypeSRV)
		add(n, TypeTXT)
	}
	for _, n := range aNames {
		add(n, TypeA)
	}
	binary.BigEndian.PutUint16(b[4:], uint16(count))
	return b
}
