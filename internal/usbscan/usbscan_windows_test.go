//go:build windows

package usbscan

import (
	"strings"
	"syscall"
	"testing"
)

// hidGUID is GUID_DEVINTERFACE_HID {4d1e55b2-f16f-11cf-88cb-001111000030}:
// almost every PC has a present HID device, so the configuration manager
// calls can be checked without a scanner.
var hidGUID = guid{0x4d1e55b2, 0xf16f, 0x11cf, [8]byte{0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}}

func TestTheConfigurationManagerCallsOnAHIDDevice(t *testing.T) {
	paths, err := presentInterfaces(&hidGUID)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("no HID device present")
	}
	inst, _, name, err := describe(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %s %q", paths[0], inst, name)
	if !strings.HasPrefix(strings.ToUpper(inst), `HID\`) {
		t.Fatalf("instance id %q", inst)
	}
	if !Attached(paths[0]) {
		t.Fatal("a present HID device must be attached")
	}
}

func TestWindowsErrnos(t *testing.T) {
	if !Refused(syscall.Errno(5)) || !Refused(syscall.Errno(32)) || !Refused(syscall.Errno(170)) {
		t.Fatal("refused")
	}
	for _, e := range []syscall.Errno{2, 3, 55, 433, 1167, 1617} {
		if !Gone(e) {
			t.Fatalf("gone %d", e)
		}
	}
}
