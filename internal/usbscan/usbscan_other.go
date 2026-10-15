//go:build !windows

package usbscan

import "github.com/sallyerp/sally-print-agent/internal/escl"

// FindAll lists IPP-over-USB interfaces. There are none outside Windows.
func FindAll() ([]Path, error) { return nil, ErrUnsupported }

// Open opens a device path. Not available outside Windows.
func Open(string) (escl.Port, error) { return nil, ErrUnsupported }

// Attached reports a USB device still plugged in. Never outside Windows.
func Attached(string) bool { return false }

func refusedErrno(error) bool { return false }

func goneErrno(error) bool { return false }
