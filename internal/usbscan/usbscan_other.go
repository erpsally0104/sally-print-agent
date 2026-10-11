//go:build !windows

package usbscan

import "github.com/sallyerp/sally-print-agent/internal/escl"

// Find lists IPP-over-USB device paths. There are none outside Windows.
func Find() ([]string, error) { return nil, ErrUnsupported }

// Open opens a device path. Not available outside Windows.
func Open(string) (escl.Port, error) { return nil, ErrUnsupported }
