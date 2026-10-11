package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/secure"
)

// local is what this PC remembers about scanning, in scan.json beside the
// agent's config. Nothing secret: the device token lives in its own
// DPAPI-protected file.
type local struct {
	CompanyID   string `json:"companyId,omitempty"`
	CompanyName string `json:"companyName,omitempty"`
	DeviceID    string `json:"deviceId,omitempty"`

	// Per-PC switches on the status page. Stored as "off" so that the
	// default (absent) is on.
	SoundsOff bool `json:"soundsOff,omitempty"`
	KeepOff   bool `json:"keepCopiesOff,omitempty"`

	// ScannerAddress is a network scanner typed on the status page.
	ScannerAddress string `json:"scannerAddress,omitempty"`

	// Settings last received from Sally.
	AutoStart     *bool `json:"autoStart,omitempty"`
	StartDelaySec int   `json:"startDelaySec,omitempty"`

	// Pause survives a restart: "paused for an hour" must not end because
	// the PC rebooted.
	PausedForever bool       `json:"pausedForever,omitempty"`
	PausedUntil   *time.Time `json:"pausedUntil,omitempty"`
}

func loadLocal(path string) (local, error) {
	var l local
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		// A damaged file must not stop scanning; start from defaults.
		return local{}, nil
	}
	return l, nil
}

func saveLocal(path string, l local) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return secure.WriteFileAtomic(path, append(b, '\n'))
}

func (l *local) paused(now time.Time) (bool, *time.Time) {
	if l.PausedForever {
		return true, nil
	}
	if l.PausedUntil != nil && now.Before(*l.PausedUntil) {
		u := *l.PausedUntil
		return true, &u
	}
	return false, nil
}

// pause for minutes, or until resumed when minutes is 0.
func (l *local) pause(now time.Time, minutes int) {
	if minutes <= 0 {
		l.PausedForever, l.PausedUntil = true, nil
		return
	}
	u := now.Add(time.Duration(minutes) * time.Minute).UTC()
	l.PausedForever, l.PausedUntil = false, &u
}

func (l *local) resume() { l.PausedForever, l.PausedUntil = false, nil }

func (l *local) autoStart() bool { return l.AutoStart == nil || *l.AutoStart }

func (l *local) delay() time.Duration {
	switch l.StartDelaySec {
	case 2, 3, 5:
		return time.Duration(l.StartDelaySec) * time.Second
	}
	return 3 * time.Second
}
