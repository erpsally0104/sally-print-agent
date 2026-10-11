//go:build !windows

package singleinstance

import (
	"os"
	"path/filepath"
	"syscall"
)

// held keeps the locked file open for the life of the process.
var held *os.File

func acquire(lockDir string) bool {
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return true // cannot even make the directory: do not block scanning
	}
	f, err := os.OpenFile(filepath.Join(lockDir, "scanner.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return true
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return false
	}
	held = f
	return true
}
