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
