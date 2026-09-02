//go:build !windows && !darwin

package main

import "errors"

// Autostart is not implemented off the two shipped platforms.
//
// Linux is a development target only (see printers_other.go), and a developer
// running the agent from a terminal does not want it registered with systemd
// behind their back. Reporting "unsupported" honestly beats writing a unit file
// nobody asked for.

var errAutostartUnsupported = errors.New("start at login is not supported on this platform")

func autostartLocation() string { return "" }

func autostartState() (AutostartState, error) {
	return AutostartState{Supported: false}, nil
}

func enableAutostart() error  { return errAutostartUnsupported }
func disableAutostart() error { return errAutostartUnsupported }
