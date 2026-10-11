package mdns

import (
	"encoding/binary"
	"net"
	"testing"
)

// packet builds a canned mDNS response the way a scanner sends one: the
// instance name written once and then referenced by compression pointers.
type packet struct {
	b     []byte
	count int
	names map[string]int
}

func newPacket() *packet {
	p := &packet{b: make([]byte, 12), names: map[string]int{}}
	binary.BigEndian.PutUint16(p.b[2:], 0x8400) // response, authoritative
	return p
}

// name writes name, compressing against any suffix written before.
func (p *packet) name(n string) {
	for n != "" && n != "." {
		if off, ok := p.names[n]; ok {
			p.b = binary.BigEndian.AppendUint16(p.b, 0xC000|uint16(off))
			return
		}
		p.names[n] = len(p.b)
		label, rest := n, "."
		for i := 0; i < len(n); i++ {
			if n[i] == '.' {
				label, rest = n[:i], n[i+1:]
				break
			}
		}
		p.b = append(p.b, byte(len(label)))
		p.b = append(p.b, label...)
		n = rest
	}
	p.b = append(p.b, 0)
}

func (p *packet) rr(name string, typ uint16, data func()) {
	p.name(name)
	p.b = binary.BigEndian.AppendUint16(p.b, typ)
	p.b = binary.BigEndian.AppendUint16(p.b, 0x8001)
	p.b = binary.BigEndian.AppendUint32(p.b, 120)
	lenAt := len(p.b)
	p.b = append(p.b, 0, 0)
	data()
	binary.BigEndian.PutUint16(p.b[lenAt:], uint16(len(p.b)-lenAt-2))
	p.count++
	binary.BigEndian.PutUint16(p.b[6:], uint16(p.count))
}

func scannerReply() []byte {
	const inst = "HP ScanJet Pro N4000 [A1B2C3]._uscan._tcp.local."
	const instS = "HP ScanJet Pro N4000 [A1B2C3]._uscans._tcp.local."
	p := newPacket()
	p.rr(ServiceHTTP, TypePTR, func() { p.name(inst) })
	p.rr(ServiceHTTPS, TypePTR, func() { p.name(instS) })
	srv := func(port uint16) func() {
		return func() {
			p.b = append(p.b, 0, 0, 0, 0)
			p.b = binary.BigEndian.AppendUint16(p.b, port)
			p.name("HPA1B2C3.local.")
		}
	}
	p.rr(inst, TypeSRV, srv(80))
	p.rr(instS, TypeSRV, srv(443))
	txt := func() {
		for _, kv := range []string{"txtvers=1", "ty=HP ScanJet Pro N4000 snw1", "rs=eSCL", "pdl=image/jpeg,application/pdf"} {
			p.b = append(p.b, byte(len(kv)))
			p.b = append(p.b, kv...)
		}
	}
	p.rr(inst, TypeTXT, txt)
	p.rr(instS, TypeTXT, txt)
	p.rr("HPA1B2C3.local.", TypeA, func() { p.b = append(p.b, 192, 168, 1, 40) })
	return p.b
}

func TestParseAndResolveACannedScannerReply(t *testing.T) {
	recs, err := Parse(scannerReply())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 7 {
		t.Fatalf("%d records", len(recs))
	}
	svcs := Resolve(recs)
	if len(svcs) != 2 {
		t.Fatalf("%d services: %+v", len(svcs), svcs)
	}
	s := svcs[0]
	if s.Secure || s.Port != 80 || !s.IP.Equal(net.IPv4(192, 168, 1, 40)) || s.Root != "eSCL" || s.Name != "HP ScanJet Pro N4000 snw1" {
		t.Fatalf("%+v", s)
	}
	if s.BaseURL() != "http://192.168.1.40:80" || svcs[1].BaseURL() != "https://192.168.1.40:443" {
		t.Fatalf("%s %s", s.BaseURL(), svcs[1].BaseURL())
	}
}

func TestBuildQuery(t *testing.T) {
	q, err := BuildQuery(7, TypePTR, ServiceHTTP, ServiceHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(q[4:]) != 2 || binary.BigEndian.Uint16(q[2:]) != 0 {
		t.Fatal("header")
	}
	// The query parses as a packet with two questions and no answers.
	want := append([]byte{6}, "_uscan"...)
	if string(q[12:12+len(want)]) != string(want) {
		t.Fatalf("first label % x", q[12:20])
	}
	recs, err := Parse(q)
	if err != nil || len(recs) != 0 {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestParseRejectsHostilePackets(t *testing.T) {
	// A compression pointer that points at itself.
	loop := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12}
	if _, err := Parse(loop); err == nil {
		t.Fatal("a pointer loop must be an error")
	}
	if _, err := Parse([]byte{1, 2, 3}); err == nil {
		t.Fatal("short packet")
	}
	// Truncate a real reply anywhere: never panic.
	r := scannerReply()
	for i := 0; i < len(r); i++ {
		Parse(r[:i])
	}
}

func TestFollowUpAsksForWhatIsMissing(t *testing.T) {
	recs := []Record{{Name: ServiceHTTP, Type: TypePTR, Target: "Scanner._uscan._tcp.local."}}
	q := followUp(recs)
	if q == nil || binary.BigEndian.Uint16(q[4:]) != 2 {
		t.Fatal("want SRV and TXT questions")
	}
	if followUp(nil) != nil {
		t.Fatal("nothing to ask")
	}
}
