//go:build windows

package singleinstance

import (
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = kernel32.NewProc("CreateMutexW")
)

// errorAlreadyExists is GetLastError() after CreateMutex found the name taken.
const errorAlreadyExists = syscall.Errno(183)

// held is never released: the mutex lives exactly as long as the process.
var held uintptr

// A named mutex in the session's Local namespace, as the Tally connector
// uses: per user session, gone when the process exits.
func acquire(string) bool {
	name, err := syscall.UTF16PtrFromString(`Local\SallyDesktopScanner`)
	if err != nil {
		return true
	}
	h, _, lastErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return true
	}
	held = h
	return lastErr != errorAlreadyExists
}
