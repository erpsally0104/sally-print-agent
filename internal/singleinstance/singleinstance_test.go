package singleinstance

import (
	"runtime"
	"testing"
)

func TestAcquireScanner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a named mutex is per process; nothing to exercise in one process")
	}
	dir := t.TempDir()
	if !AcquireScanner(dir) {
		t.Fatal("first acquire should succeed")
	}
}
