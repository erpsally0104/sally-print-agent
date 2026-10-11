// Package sound plays the three sounds of Sally Desktop: a tick when a scan
// starts, a rising chime when a stack is safe on the PC, and a low falling
// tone when something needs a person.
//
// The sounds are generated here as small WAV files at startup (no assets to
// ship) and played through winmm's PlaySoundW on Windows, with no cgo. On
// other systems Play does nothing.
package sound

import (
	"encoding/binary"
	"math"
	"sync/atomic"
)

// Sound names one of the three sounds.
type Sound int

const (
	Tick Sound = iota
	Chime
	Problem
)

const sampleRate = 22050

// note is one tone of a sound.
type note struct {
	freq, ms float64
}

var wavs = [...][]byte{
	Tick:    render([]note{{1600, 35}}, 0.25),
	Chime:   render([]note{{523.25, 120}, {659.25, 120}, {783.99, 260}}, 0.3),
	Problem: render([]note{{330, 220}, {220, 380}}, 0.35),
}

// WAV returns the generated WAV bytes of s.
func WAV(s Sound) []byte { return wavs[s] }

// render makes a 16-bit mono PCM WAV of notes in sequence, each with a short
// attack and an exponential decay so nothing clicks.
func render(notes []note, volume float64) []byte {
	var pcm []byte
	for _, n := range notes {
		count := int(n.ms * sampleRate / 1000)
		attack := sampleRate / 200 // 5 ms
		for i := 0; i < count; i++ {
			env := math.Exp(-3 * float64(i) / float64(count))
			if i < attack {
				env *= float64(i) / float64(attack)
			}
			v := volume * env * math.Sin(2*math.Pi*n.freq*float64(i)/sampleRate)
			pcm = binary.LittleEndian.AppendUint16(pcm, uint16(int16(v*32767)))
		}
	}
	h := make([]byte, 0, 44+len(pcm))
	h = append(h, "RIFF"...)
	h = binary.LittleEndian.AppendUint32(h, uint32(36+len(pcm)))
	h = append(h, "WAVEfmt "...)
	h = binary.LittleEndian.AppendUint32(h, 16)
	h = binary.LittleEndian.AppendUint16(h, 1) // PCM
	h = binary.LittleEndian.AppendUint16(h, 1) // mono
	h = binary.LittleEndian.AppendUint32(h, sampleRate)
	h = binary.LittleEndian.AppendUint32(h, sampleRate*2)
	h = binary.LittleEndian.AppendUint16(h, 2)
	h = binary.LittleEndian.AppendUint16(h, 16)
	h = append(h, "data"...)
	h = binary.LittleEndian.AppendUint32(h, uint32(len(pcm)))
	return append(h, pcm...)
}

var enabled atomic.Bool

func init() { enabled.Store(true) }

// SetEnabled switches sounds on or off for this PC.
func SetEnabled(on bool) { enabled.Store(on) }

// Enabled reports whether sounds are on.
func Enabled() bool { return enabled.Load() }

// Play plays s without waiting, if sounds are on.
func Play(s Sound) {
	if !enabled.Load() || int(s) < 0 || int(s) >= len(wavs) {
		return
	}
	play(s)
}
