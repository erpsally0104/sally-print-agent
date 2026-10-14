// Package usbscan opens a USB scanner's IPP-over-USB channel on Windows.
//
// Facts from a real HP ScanJet Pro N4000 snw1 on Windows 11, which shape all
// of this:
//
//   - The scanner exposes IPP-over-USB interfaces (class 7/1/4, driver
//     usbprint). WIA lists no device at all.
//   - The channel is the device interface {f2f40381-f46d-4e51-bce7-62de6cf2d098}.
//     SetupAPI enumeration returned nothing on that machine, so the paths
//     also come from the registry, under
//     HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{f2f40381-…}: each
//     subkey name with its leading "##?#" replaced by `\\?\` is a path for
//     CreateFile. Interfaces whose "#\Control" subkey has Linked = 1 are live.
//   - Plain HTTP/1.1 goes over the handle with "Host: localhost:60000"
//     (see escl.StreamDoer). Writes must be complete and unbuffered, and
//     every read needs a timeout (overlapped I/O, CancelIoEx).
//
// On other systems there is no USB path; network scanners are found by mDNS.
package usbscan

import (
	"errors"
	"strings"
)

// InterfaceGUID is the IPP-over-USB device interface class.
const InterfaceGUID = "{f2f40381-f46d-4e51-bce7-62de6cf2d098}"

// ErrUnsupported is returned where there is no USB path (not Windows).
var ErrUnsupported = errors.New("usbscan: USB scanning is only available on Windows")

// pathFromKey turns a DeviceClasses subkey name into a device path.
func pathFromKey(name string) (string, bool) {
	if len(name) < 5 || name[:4] != "##?#" {
		return "", false
	}
	return `\\?\` + name[4:], true
}

// order merges candidate paths: present (SetupAPI) first, then registry
// interfaces marked Linked, then the rest, without duplicates.
func order(present, linked, other []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{present, linked, other} {
		for _, p := range list {
			k := lower(p)
			if p == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Path is one IPP-over-USB interface the PC knows about.
type Path struct {
	Path string
	// Present: SetupAPI lists it as present now.
	Present bool
	// Linked: the registry marks the interface live (Linked = 1).
	Linked bool
}

// classify merges the three lists FindAll reads into one, in order's
// order, saying for each path whether it is present and whether it is
// linked. A registry-only path that is not linked is neither.
func classify(present, linked, other []string) []Path {
	in := func(list []string, p string) bool {
		for _, q := range list {
			if lower(q) == lower(p) {
				return true
			}
		}
		return false
	}
	var out []Path
	for _, p := range order(present, linked, other) {
		out = append(out, Path{Path: p, Present: in(present, p), Linked: in(linked, p)})
	}
	return out
}

// DeviceKey names the USB device a path belongs to, so the interfaces of
// one scanner (PI_00 and PI_01, or MI_00 and MI_01) group as one:
//
//	\\?\usb#vid_03f0&pid_5c05&pi_00#6&1a2b3c4d&0&0000#{…}  →  vid_03f0&pid_5c05#6&1a2b3c4d&0
//
// The path is lowercased and split on '#'; '&pi_NN' or '&mi_NN' is dropped
// from the hardware-id part, and the last '&' field from the instance part.
func DeviceKey(path string) string {
	parts := strings.Split(lower(path), "#")
	if len(parts) < 3 {
		return lower(path)
	}
	var hw []string
	for _, f := range strings.Split(parts[1], "&") {
		if len(f) == 5 && (strings.HasPrefix(f, "pi_") || strings.HasPrefix(f, "mi_")) {
			continue
		}
		hw = append(hw, f)
	}
	inst := parts[2]
	if i := strings.LastIndex(inst, "&"); i >= 0 {
		inst = inst[:i]
	}
	return strings.Join(hw, "&") + "#" + inst
}
