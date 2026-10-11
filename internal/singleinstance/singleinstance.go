// Package singleinstance makes sure only one copy of the agent drives the
// scanner.
//
// Printing already copes with a second copy: it binds the next free port in
// the range and Sally finds whichever answers. Scanning cannot share like
// that. Two copies would both watch the feeder and both start a job on the
// same paper, so the scanner side of the agent runs only in the copy that
// holds this lock. A second copy still serves printing, exactly as before.
package singleinstance

// AcquireScanner takes the per-user scanner lock. lockDir is used where the
// lock is a file (macOS, Linux). It returns false when another copy holds it.
// The lock lives as long as the process.
func AcquireScanner(lockDir string) bool { return acquire(lockDir) }
