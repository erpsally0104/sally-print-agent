package sound

import (
	"encoding/binary"
	"testing"
)

func TestWAVsAreWellFormed(t *testing.T) {
	for _, s := range []Sound{Tick, Chime, Problem} {
		b := WAV(s)
		if string(b[0:4]) != "RIFF" || string(b[8:12]) != "WAVE" || string(b[36:40]) != "data" {
			t.Fatalf("sound %d: bad header", s)
		}
		if int(binary.LittleEndian.Uint32(b[4:])) != len(b)-8 || int(binary.LittleEndian.Uint32(b[40:])) != len(b)-44 {
			t.Fatalf("sound %d: sizes wrong", s)
		}
		if len(b) > 64<<10 {
			t.Fatalf("sound %d is %d bytes", s, len(b))
		}
	}
}

func TestSwitchingOff(t *testing.T) {
	SetEnabled(false)
	defer SetEnabled(true)
	if Enabled() {
		t.Fatal("still on")
	}
	Play(Chime) // must be a no-op, and never panic
}
