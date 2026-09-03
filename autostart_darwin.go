//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

/*
macOS autostart: a per-user LaunchAgent.

  ~/Library/LaunchAgents/in.sallyerp.print-agent.plist

launchd gives us something Windows does not: KeepAlive, so a crashed agent is
restarted rather than staying dead until the next login.

Since Ventura the registration is visible in System Settings → General → Login
Items, where the user can switch it off. That is a feature, not a problem — but
it does mean "enabled" here describes what we registered, not a guarantee the
system will honour it.
*/

const launchAgentTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<!-- Background: never take focus, and be scheduled accordingly. -->
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating the home directory: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", autostartLabel+".plist"), nil
}

func autostartLocation() string {
	if p, err := launchAgentPath(); err == nil {
		return p
	}
	return "~/Library/LaunchAgents/" + autostartLabel + ".plist"
}

func autostartState() (AutostartState, error) {
	state := AutostartState{Supported: true, Location: autostartLocation()}

	path, err := launchAgentPath()
	if err != nil {
		return state, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		// No plist → not enabled. Absence is a normal state.
		return state, nil
	}
	state.Enabled = true
	state.RegisteredPath = programArgumentFrom(string(body))
	return state, nil
}

// programArgumentFrom pulls the executable path back out of the plist.
//
// A real plist parser would be the right tool for arbitrary input, but this
// file is one we wrote from a fixed template, so the first <string> after
// ProgramArguments is the path. If the shape is ever unexpected we return ""
// and the caller reports the registration without a path rather than guessing.
func programArgumentFrom(plist string) string {
	_, after, found := strings.Cut(plist, "<key>ProgramArguments</key>")
	if !found {
		return ""
	}
	_, after, found = strings.Cut(after, "<string>")
	if !found {
		return ""
	}
	value, _, found := strings.Cut(after, "</string>")
	if !found {
		return ""
	}
	return strings.TrimSpace(value)
}

func enableAutostart() error {
	exe, err := currentExecutable()
	if err != nil {
		return err
	}
	path, err := launchAgentPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	body := fmt.Sprintf(launchAgentTemplate, autostartLabel, exe)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	// Load it now so the user does not have to log out and back in. An already
	// loaded label makes bootstrap fail; boot it out first and ignore that
	// failing, since not-loaded is the common case.
	_ = runLaunchctl("bootout", guiTarget()+"/"+autostartLabel)
	if err := runLaunchctl("bootstrap", guiTarget(), path); err != nil {
		// The plist is written, so it will start at the next login regardless.
		return fmt.Errorf("registered, but launchctl could not start it now: %w", err)
	}
	return nil
}

func disableAutostart() error {
	path, err := launchAgentPath()
	if err != nil {
		return err
	}
	_ = runLaunchctl("bootout", guiTarget()+"/"+autostartLabel)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", path, err)
	}
	return nil
}

// guiTarget is the per-user launchd domain. `gui/<uid>` is the modern spelling;
// the deprecated `launchctl load -w` operated on it implicitly.
func guiTarget() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func runLaunchctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// autostartLaunchesIt reports whether enableAutostart also started the agent.
// It did: `launchctl bootstrap` starts the job immediately, so by the time
// enableAutostart returns there is already an agent serving. -install must not
// then serve as well, or the second copy takes the next port in the range and
// Sally's probe finds two agents where the user installed one.
func autostartLaunchesIt() bool { return true }
