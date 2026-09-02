package main

import (
	"path/filepath"
	"testing"
)

/*
These cover the platform-independent half of autostart. The registering itself
is not unit-tested on purpose: it writes to the real registry or the real
LaunchAgents directory, and a test that mutates the developer's login items is
worse than no test. The manual cycle — install, status, move, uninstall — is in
the README.

What is worth pinning is the comparison, because the failure it guards against
is silent: the agent registers an absolute path, so a user who moves the folder
still has autostart "enabled" pointing at a binary that is no longer there, and
finds out at the next restart when printing has quietly stopped working.
*/

func TestSamePath(t *testing.T) {
	base := filepath.Join("a", "b", "agent.exe")

	t.Run("a path equals itself", func(t *testing.T) {
		if !samePath(base, base) {
			t.Fatal("identical paths should match")
		}
	})

	t.Run("redundant elements do not make it a different path", func(t *testing.T) {
		messy := filepath.Join("a", "x", "..", "b", "agent.exe")
		if !samePath(base, messy) {
			t.Fatalf("%q and %q are the same file", base, messy)
		}
	})

	t.Run("a genuinely different path does not match", func(t *testing.T) {
		other := filepath.Join("a", "b", "other.exe")
		if samePath(base, other) {
			t.Fatal("different files must not match")
		}
	})

	t.Run("case follows the platform", func(t *testing.T) {
		upper := filepath.Join("A", "B", "AGENT.EXE")
		got := samePath(base, upper)
		// Windows paths are case-insensitive; treating them as distinct would
		// report a spurious "you moved the agent" on every status check.
		if got != isWindows() {
			t.Fatalf("samePath(%q, %q) = %v on %v", base, upper, got, "this platform")
		}
	})
}

func TestAutostartStale(t *testing.T) {
	exe := filepath.Join("opt", "sally", "agent")

	t.Run("not stale when the registered path is the running one", func(t *testing.T) {
		a := AutostartState{Enabled: true, RegisteredPath: exe}
		if a.Stale(exe) {
			t.Fatal("same path should not read as stale")
		}
	})

	t.Run("stale when the agent has been moved", func(t *testing.T) {
		a := AutostartState{Enabled: true, RegisteredPath: filepath.Join("downloads", "agent")}
		if !a.Stale(exe) {
			t.Fatal("a moved binary should read as stale")
		}
	})

	t.Run("never stale when autostart is off", func(t *testing.T) {
		// Nothing is registered, so there is nothing to be out of date.
		a := AutostartState{Enabled: false, RegisteredPath: filepath.Join("downloads", "agent")}
		if a.Stale(exe) {
			t.Fatal("a disabled registration cannot be stale")
		}
	})

	t.Run("never stale when either path is unknown", func(t *testing.T) {
		if (AutostartState{Enabled: true}).Stale(exe) {
			t.Fatal("no registered path means nothing to compare")
		}
		if (AutostartState{Enabled: true, RegisteredPath: exe}).Stale("") {
			t.Fatal("no current path means nothing to compare")
		}
	})
}

func TestCurrentExecutableIsAbsolute(t *testing.T) {
	// A relative path would be registered and then fail to launch at login,
	// because the login shell's working directory is not ours.
	exe, err := currentExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(exe) {
		t.Fatalf("currentExecutable() = %q, want an absolute path", exe)
	}
}
