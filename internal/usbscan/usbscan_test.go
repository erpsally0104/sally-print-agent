package usbscan

import (
	"reflect"
	"testing"
)

func TestPathFromKey(t *testing.T) {
	p, ok := pathFromKey(`##?#USB#VID_03F0&PID_0A2A&MI_00#7&2b9c3a5e&0&0000#{f2f40381-f46d-4e51-bce7-62de6cf2d098}`)
	if !ok || p != `\\?\USB#VID_03F0&PID_0A2A&MI_00#7&2b9c3a5e&0&0000#{f2f40381-f46d-4e51-bce7-62de6cf2d098}` {
		t.Fatalf("%q %v", p, ok)
	}
	if _, ok := pathFromKey("#"); ok {
		t.Fatal("not a device key")
	}
}

func TestOrderPrefersPresentThenLinked(t *testing.T) {
	got := order([]string{`\\?\A`}, []string{`\\?\b`, `\\?\a`}, []string{`\\?\C`, `\\?\B`})
	want := []string{`\\?\A`, `\\?\b`, `\\?\C`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestDeviceKeyGroupsTheInterfacesOfOneScanner(t *testing.T) {
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

func TestClassifyMarksAnUnlinkedRegistryPathAsNeither(t *testing.T) {
	got := classify([]string{`\\?\A`}, []string{`\\?\a`, `\\?\B`}, []string{`\\?\C`})
	want := []Path{{`\\?\A`, true, true}, {`\\?\B`, false, true}, {`\\?\C`, false, false}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}
