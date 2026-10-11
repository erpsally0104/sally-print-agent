//go:build !windows

package secure

const (
	encrypts  = false
	isWindows = false
)

// Outside Windows there is no per-user OS vault the agent can use without
// cgo or a dependency, so files are protected by permissions (0600 in a 0700
// directory) and stored as is.
func protect(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

func unprotect(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
