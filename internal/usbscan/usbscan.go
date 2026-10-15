// Package usbscan finds and opens a USB scanner's IPP-over-USB channel on
// Windows.
//
// Facts from a real HP ScanJet Pro N4000 snw1 on Windows 11, which shape all
// of this:
//
//   - The scanner exposes IPP-over-USB interfaces (class 7/1/4, driver
//     usbprint), PI_00 and PI_01, on the device interface
//     {f2f40381-f46d-4e51-bce7-62de6cf2d098}.
//   - The registry keeps that interface class's entries for devices long
//     unplugged, printers among them, so the list comes from the
//     configuration manager instead: only interfaces present now, and of
//     those only the ones whose compatible ids say class 7/1/4 (or, when
//     Windows gives none, whose path has a PI_ field). Each is named after
//     its USB device, as the device reports itself.
//   - Plain HTTP/1.1 goes over the handle with "Host: localhost:60000"
//     (see escl.StreamDoer). Writes must be complete and unbuffered, and
//     every read needs a timeout (overlapped I/O, CancelIoEx).
//   - When the first read fails at once with "Access is denied", Windows
//     is holding the channel. Refused and Gone sort such errors; Attached
//     says whether the USB device is still plugged in when its IPP-over-USB
//     interfaces are gone.
//
// On other systems there is no USB path; network scanners are found by mDNS.
package usbscan

import (
	"errors"
	"io/fs"
	"sort"
	"strings"
)

// InterfaceGUID is the IPP-over-USB device interface class.
const InterfaceGUID = "{f2f40381-f46d-4e51-bce7-62de6cf2d098}"

// ErrUnsupported is returned where there is no USB path (not Windows).
var ErrUnsupported = errors.New("usbscan: USB scanning is only available on Windows")

// ippUSBCompat is the compatible id of an IPP-over-USB interface: class 7
// (printer), subclass 1, protocol 4.
const ippUSBCompat = `usb\class_07&subclass_01&prot_04`

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Path is one IPP-over-USB interface present on the PC.
type Path struct {
	Path string
	// Name is how the USB device reports itself, or "".
	Name string
}

// splitMultiSz splits NUL-separated UTF-16 strings, up to the first empty
// one (the list's end) or the end of b.
func splitMultiSz(b []uint16) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c != 0 {
			continue
		}
		if i == start {
			return out
		}
		out = append(out, utf16ToString(b[start:i]))
		start = i + 1
	}
	if start < len(b) {
		out = append(out, utf16ToString(b[start:]))
	}
	return out
}

// utf16ToString decodes UTF-16, surrogate pairs included; a lone surrogate
// becomes U+FFFD.
func utf16ToString(b []uint16) string {
	var r []rune
	for i := 0; i < len(b); i++ {
		c := rune(b[i])
		switch {
		case c >= 0xD800 && c < 0xDC00 && i+1 < len(b) && b[i+1] >= 0xDC00 && b[i+1] < 0xE000:
			r = append(r, 0x10000+(c-0xD800)<<10+(rune(b[i+1])-0xDC00))
			i++
		case c >= 0xD800 && c < 0xE000:
			r = append(r, 0xFFFD)
		default:
			r = append(r, c)
		}
	}
	return string(r)
}

// isIPPUSB reports an IPP-over-USB interface: one of its compatible ids is
// class 7/1/4. Without compatible ids, its path's hardware-id part (the
// second '#' field) must have a PI_NN field.
func isIPPUSB(compat []string, path string) bool {
	if len(compat) > 0 {
		for _, c := range compat {
			if lower(strings.TrimSpace(c)) == ippUSBCompat {
				return true
			}
		}
		return false
	}
	parts := strings.Split(lower(path), "#")
	if len(parts) < 2 {
		return false
	}
	for _, f := range strings.Split(parts[1], "&") {
		if len(f) == 5 && strings.HasPrefix(f, "pi_") && isHex(f[3]) && isHex(f[4]) {
			return true
		}
	}
	return false
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// pickIPPUSB keeps the paths that are IPP-over-USB interfaces (a describe
// error counts as no compatible ids), with their names trimmed, sorted by
// lowercased path.
func pickIPPUSB(paths []string, describe func(string) (inst string, compat []string, name string, err error)) []Path {
	var out []Path
	for _, p := range paths {
		_, compat, name, err := describe(p)
		if err != nil {
			compat, name = nil, ""
		}
		if !isIPPUSB(compat, p) {
			continue
		}
		out = append(out, Path{Path: p, Name: strings.TrimSpace(name)})
	}
	sort.SliceStable(out, func(i, j int) bool { return lower(out[i].Path) < lower(out[j].Path) })
	return out
}

// Refused reports an error that says Windows will not let the agent use
// the channel: access denied, or (on Windows) a sharing violation or a busy
// device.
func Refused(err error) bool {
	return err != nil && (errors.Is(err, fs.ErrPermission) || refusedErrno(err))
}

// Gone reports an error that says the interface is not there: not found,
// or (on Windows) the device does not exist, is not connected or was
// removed.
func Gone(err error) bool {
	return err != nil && (errors.Is(err, fs.ErrNotExist) || goneErrno(err))
}

// isChild reports an instance id or path of one function of a composite
// device: it has a &PI_ or &MI_ field.
func isChild(s string) bool {
	l := lower(s)
	return strings.Contains(l, "&pi_") || strings.Contains(l, "&mi_")
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
