//go:build windows

package sound

import (
	"syscall"
	"unsafe"
)

var (
	winmm           = syscall.NewLazyDLL("winmm.dll")
	procPlaySoundW  = winmm.NewProc("PlaySoundW")
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBeep = user32.NewProc("MessageBeep")
)

const (
	sndAsync     = 0x0001
	sndNoDefault = 0x0002
	sndMemory    = 0x0004

	mbOK       = 0x00000000
	mbIconHand = 0x00000010
)

// play hands the in-memory WAV to PlaySoundW. With SND_ASYNC the buffer must
// outlive the call; the WAVs are package-level and never freed.
func play(s Sound) {
	b := wavs[s]
	if procPlaySoundW.Find() == nil {
		r, _, _ := procPlaySoundW.Call(uintptr(unsafe.Pointer(&b[0])), 0, sndMemory|sndAsync|sndNoDefault)
		if r != 0 {
			return
		}
	}
	beep := uintptr(mbOK)
	if s == Problem {
		beep = mbIconHand
	}
	procMessageBeep.Call(beep)
}
