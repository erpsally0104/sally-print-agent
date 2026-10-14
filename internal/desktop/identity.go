package desktop

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/sallyerp/sally-print-agent/internal/escl"
)

/*
A scanner's id (erp-sally docs/signed-copies/p1-desktop-api.md, "Scanner id
and merging").

id = "sc-" + the first 20 lowercase hex characters of SHA-256 over a key.
The first key that exists wins:

	(a) "uuid:" + the top-level scan:UUID of ScannerCapabilities;
	(b) "sn:" + lowercased MakeAndModel + "/" + the top-level pwg:SerialNumber;
	(c) "uuid:" + the mDNS TXT "UUID" (the same prefix as (a), so a network
	    sighting whose capabilities cannot be read still matches);
	(d) the id this sighting last had from (a) or (b), while its capabilities
	    do not answer;
	(e) the last resort, which can change after replugging or renaming:
	    "usb:" + DeviceKey, "mdns:" + the instance label, "addr:" + the typed
	    address.

(a) to (d) are stable; (e) is not. An id is a label the device asserts, not
proof of identity: any host on the LAN can copy a UUID.
*/

var (
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Re     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	scannerIDRe = regexp.MustCompile(`^sc-[0-9a-f]{20}$`)
	ipv4Re      = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	ipv6Re      = regexp.MustCompile(`[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,}`)
)

// NormaliseUUID trims s, removes "urn:uuid:" and braces, lowercases it and
// writes 32 hex digits as 8-4-4-4-12. Anything that is not then a UUID
// gives "".
func NormaliseUUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "urn:uuid:")
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	if hex32Re.MatchString(s) {
		s = s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
	}
	if !uuidRe.MatchString(s) {
		return ""
	}
	return s
}

// ScannerID is "sc-" + the first 20 hex characters of SHA-256 over key.
func ScannerID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "sc-" + hex.EncodeToString(sum[:])[:20]
}

// ValidScannerID reports whether id has the sc- format.
func ValidScannerID(id string) bool { return scannerIDRe.MatchString(id) }

// usableSerial: printable ASCII, at most 64 characters, and not "", "0" or
// "unknown".
func usableSerial(s string) bool {
	if s == "" || len(s) > 64 || s == "0" || strings.EqualFold(s, "unknown") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// sightingKeys names one sighting of a scanner: key is what the agent
// remembers its id under (the USB DeviceKey, the mDNS label + host, or the
// typed address), last is its last-resort id key.
type sightingKeys struct {
	key  string
	last string
}

func usbKeys(devKey string) sightingKeys {
	return sightingKeys{key: "usb:" + devKey, last: "usb:" + devKey}
}

func mdnsKeys(label, host string) sightingKeys {
	l := strings.ToLower(label)
	return sightingKeys{key: "mdns:" + l + "@" + strings.ToLower(host), last: "mdns:" + l}
}

func addrKeys(address string) sightingKeys {
	a := "addr:" + strings.ToLower(strings.TrimSpace(address))
	return sightingKeys{key: a, last: a}
}

// identify gives a sighting's id and whether it is stable, in the order
// above. caps is nil when the capabilities could not be read; known maps a
// sighting key to the id it last had from (a) or (b). fromCaps reports an
// id from (a) or (b), which the caller remembers under k.key.
func identify(caps *escl.Capabilities, txtUUID string, k sightingKeys, known map[string]string) (id string, stable, fromCaps bool) {
	if caps != nil {
		if u := NormaliseUUID(caps.UUID); u != "" {
			return ScannerID("uuid:" + u), true, true
		}
		sn := strings.TrimSpace(caps.SerialNumber)
		if usableSerial(sn) {
			return ScannerID("sn:" + strings.ToLower(strings.TrimSpace(caps.MakeAndModel)) + "/" + sn), true, true
		}
	}
	if u := NormaliseUUID(txtUUID); u != "" {
		return ScannerID("uuid:" + u), true, false
	}
	if caps == nil {
		if id := known[k.key]; ValidScannerID(id) {
			return id, true, false
		}
	}
	return ScannerID(k.last), false, false
}

// cutRunes removes control characters (C0, DEL and C1) and invalid UTF-8,
// then cuts s to at most max runes and trims it.
func cutRunes(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			continue
		}
		if n == max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// looksLikeAddress reports a detail that could be an IP address, a URL or
// a device path, which is never sent.
func looksLikeAddress(s string) bool {
	l := strings.ToLower(s)
	if strings.Contains(l, "://") || strings.ContainsAny(l, `/\`) {
		return true
	}
	// An IPv4 address, or an IPv6 one: several hex groups joined by colons.
	return ipv4Re.MatchString(l) || (strings.Count(l, ":") >= 2 && ipv6Re.MatchString(l))
}

// safeDetail is a detail fit to send: control characters removed, cut to 80
// runes, and "" when it looks like an address or a path.
func safeDetail(s string) string {
	s = cutRunes(s, 80)
	if looksLikeAddress(s) {
		return ""
	}
	return s
}
