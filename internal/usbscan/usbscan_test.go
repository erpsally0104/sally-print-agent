package usbscan

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"testing"
	"unicode/utf16"
)

const (
	n4000PI0 = `\\?\USB#VID_03F0&PID_5C05&PI_00#6&2df78daf&0&c000#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
	n4000PI1 = `\\?\USB#VID_03F0&PID_5C05&PI_01#6&2df78daf&0&c001#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
)

func TestDeviceKeyGroupsTheInterfacesOfOneScanner(t *testing.T) {
	if DeviceKey(n4000PI0) != "vid_03f0&pid_5c05#6&2df78daf&0" || DeviceKey(n4000PI1) != DeviceKey(n4000PI0) {
		t.Fatalf("%q %q", DeviceKey(n4000PI0), DeviceKey(n4000PI1))
	}
	pi0 := `\\?\USB#VID_03F0&PID_5C05&PI_00#6&1a2b3c4d&0&0000#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
	pi1 := `\\?\usb#vid_03f0&pid_5c05&pi_01#6&1A2B3C4D&0&0001#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
	if DeviceKey(pi0) != "vid_03f0&pid_5c05#6&1a2b3c4d&0" || DeviceKey(pi0) != DeviceKey(pi1) {
		t.Fatalf("%q %q", DeviceKey(pi0), DeviceKey(pi1))
	}
	mi := `\\?\USB#VID_03F0&PID_5C05&MI_00#6&1a2b3c4d&0&0000#{x}`
	if DeviceKey(mi) != DeviceKey(pi0) {
		t.Fatalf("MI_ and PI_ of one device: %q", DeviceKey(mi))
	}
	other := `\\?\USB#VID_03F0&PID_5C05&PI_00#6&99999999&0&0000#{x}`
	model := `\\?\USB#VID_03F0&PID_5C06&PI_00#6&1a2b3c4d&0&0000#{x}`
	if DeviceKey(other) == DeviceKey(pi0) || DeviceKey(model) == DeviceKey(pi0) {
		t.Fatal("another instance or another vid/pid must get another key")
	}
}

func TestIsIPPUSB(t *testing.T) {
	ipp := []string{`USB\COMPAT_VID_03f0&Class_07&SubClass_01&Prot_04`, `USB\Class_07&SubClass_01&Prot_04`, `USB\Class_07&SubClass_01`, `USB\Class_07`}
	if !isIPPUSB(ipp, `\\?\USB#VID_03F0&PID_0001&MI_00#x#{g}`) {
		t.Fatal("class 7/1/4 is IPP-over-USB, whatever the path")
	}
	if !isIPPUSB([]string{`usb\class_07&subclass_01&prot_04`}, "") {
		t.Fatal("any case")
	}
	// The registry ghost: a 7/1/2 printer, with a PI_ path.
	printer := []string{`USB\COMPAT_VID_03f0&Class_07&SubClass_01&Prot_02`, `USB\Class_07&SubClass_01&Prot_02`, `USB\Class_07&SubClass_01`, `USB\Class_07`}
	if isIPPUSB(printer, n4000PI0) {
		t.Fatal("a 7/1/2 printer is not IPP-over-USB")
	}
	if !isIPPUSB(nil, n4000PI1) {
		t.Fatal("no compatible ids: a PI_ path is IPP-over-USB")
	}
	if isIPPUSB(nil, `\\?\USB#VID_03F0&PID_5C05&MI_00#6&2df78daf&0&0000#{g}`) {
		t.Fatal("no compatible ids: an MI_ path is not")
	}
	if isIPPUSB(nil, `\\?\USB#VID_03F0&PID_5C05#x&pi_00#{g}`) {
		t.Fatal("only the hardware-id part counts")
	}
}

func multiSz(ss ...string) []uint16 {
	var b []uint16
	for _, s := range ss {
		b = append(b, utf16.Encode([]rune(s))...)
		b = append(b, 0)
	}
	return append(b, 0)
}

func TestSplitMultiSz(t *testing.T) {
	for _, c := range []struct {
		in   []uint16
		want []string
	}{
		{multiSz(`USB\A`, `USB\B`), []string{`USB\A`, `USB\B`}},
		{append(multiSz("one"), 'x', 0, 0), []string{"one"}},
		{[]uint16{0}, nil},
		{nil, nil},
		{utf16.Encode([]rune("no end")), []string{"no end"}},
		{multiSz("Scanner 😀"), []string{"Scanner 😀"}},
	} {
		if got := splitMultiSz(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPickIPPUSBKeepsPresentIPPInterfacesNamedAndSorted(t *testing.T) {
	ipp := []string{`USB\Class_07&SubClass_01&Prot_04`}
	printer := `\\?\USB#VID_03F0&PID_0A2A&MI_00#7&2b9c3a5e&0&0000#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`
	describe := func(p string) (string, []string, string, error) {
		switch p {
		case n4000PI0, n4000PI1:
			return "USB\\x", ipp, "  HP ScanJet Pro N4000 snw1 \t", nil
		case printer:
			return "USB\\y", []string{`USB\Class_07&SubClass_01&Prot_02`}, "HP LaserJet M1136 MFP", nil
		}
		return "", nil, "", errors.New("no such interface")
	}
	got := pickIPPUSB([]string{n4000PI1, printer, n4000PI0}, describe)
	want := []Path{{n4000PI0, "HP ScanJet Pro N4000 snw1"}, {n4000PI1, "HP ScanJet Pro N4000 snw1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}

	failing := func(string) (string, []string, string, error) {
		return "", ipp, "named anyway", errors.New("CONFIGRET 0x13")
	}
	got = pickIPPUSB([]string{printer, n4000PI1}, failing)
	if !reflect.DeepEqual(got, []Path{{n4000PI1, ""}}) {
		t.Fatalf("a describe error must fall back to the path: %+v", got)
	}
}

func TestRefusedAndGone(t *testing.T) {
	denied := fmt.Errorf("usbscan: read: %w", fs.ErrPermission)
	missing := fmt.Errorf("usbscan: opening the scanner: %w", fs.ErrNotExist)
	other := errors.New("escl: read timed out")
	if !Refused(denied) || Refused(missing) || Refused(other) || Refused(nil) {
		t.Fatal("Refused")
	}
	if !Gone(missing) || Gone(denied) || Gone(other) || Gone(nil) {
		t.Fatal("Gone")
	}
}

func TestAnOrphansRootParentIsNotItsUSBDevice(t *testing.T) {
	if parentIsUSB(`HTREE\ROOT\0`) {
		t.Fatal("the device-tree root is not a USB device")
	}
	if parentIsUSB("") {
		t.Fatal("no parent id is not a USB device")
	}
	for _, id := range []string{`usb\vid_03f0&pid_5c05\cn12ab34cd`, `USB\VID_03F0&PID_5C05\CN12AB34CD`} {
		if !parentIsUSB(id) {
			t.Fatalf("%q is a USB device", id)
		}
	}
}
