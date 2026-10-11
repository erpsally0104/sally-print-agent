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

import "errors"

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
