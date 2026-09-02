package main

import (
	"fmt"
	"os"
	"path/filepath"
)

/*
Start at login
──────────────

The agent is useless if the user has to launch it by hand every morning: they
will forget, printing will silently fall back to the browser dialog, and the
first anyone hears of it is "why does printing keep changing".

Registration is done by the agent itself (`-install`) rather than only by an
installer, for two reasons. There is no installer yet — the release ships a zip
— so this is what makes that zip usable at all. And when the installer does
arrive it can call the same code path instead of reimplementing it per platform
in a packaging script, which is where this kind of logic usually goes to rot.

Deliberately per-user, never machine-wide:

  Windows  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  macOS    ~/Library/LaunchAgents/in.sallyerp.print-agent.plist

A Windows *Service* would be the obvious-looking choice and is the wrong one:
services run in session 0 with no user profile, where per-user printer
connections are invisible. The agent must run as the person whose printers it
is enumerating. The same reasoning rules out a machine-wide LaunchDaemon.

Neither mechanism needs administrator rights, which matters — a user who cannot
elevate can still set this up.
*/

// autostartLabel identifies the registration on both platforms. Changing it
// orphans existing registrations, so it is fixed.
const autostartLabel = "in.sallyerp.print-agent"

// AutostartState is what the status page and `-install` report.
type AutostartState struct {
	// Supported is false on platforms where we do not implement this.
	Supported bool
	Enabled   bool
	// RegisteredPath is the binary the system will launch. It can differ from
	// the running one: registration records an absolute path, so moving the
	// agent after installing leaves the old path registered and the user
	// silently loses autostart. Callers surface the mismatch rather than
	// guessing which one is intended.
	RegisteredPath string
	// Location is where the registration lives, for the status page and support.
	Location string
}

// Stale reports whether the registration points somewhere other than the
// running binary — the "I moved the folder" case.
func (a AutostartState) Stale(current string) bool {
	if !a.Enabled || a.RegisteredPath == "" || current == "" {
		return false
	}
	return !samePath(a.RegisteredPath, current)
}

// samePath compares two paths tolerantly: Windows is case-insensitive, and
// either side may carry a trailing separator or redundant elements.
func samePath(a, b string) bool {
	ca, err1 := filepath.Abs(filepath.Clean(a))
	cb, err2 := filepath.Abs(filepath.Clean(b))
	if err1 != nil || err2 != nil {
		return a == b
	}
	if isWindows() {
		return equalFold(ca, cb)
	}
	return ca == cb
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// currentExecutable resolves the running binary to an absolute, symlink-free
// path. Registration must record a real location: a relative path or a symlink
// in a temp directory would be registered and then fail to launch at login.
func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating this executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Abs(exe)
}
