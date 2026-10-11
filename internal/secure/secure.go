// Package secure protects small secrets and scanned pages at rest.
//
// On Windows it uses DPAPI in user scope (CryptProtectData): the bytes can
// only be read back by the same Windows user on the same machine, which is
// what keeps the device token and the outbox's scanned pages unreadable to
// another account or to a copied disk image. Elsewhere it does not encrypt;
// files are written 0600 inside a 0700 directory, readable only by the user.
package secure

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Encrypts reports whether Protect really encrypts on this platform.
const Encrypts = encrypts

// Protect seals b for the current user.
func Protect(b []byte) ([]byte, error) { return protect(b) }

// Unprotect opens bytes sealed by Protect.
func Unprotect(b []byte) ([]byte, error) { return unprotect(b) }

// ErrNoToken is returned when no token is stored.
var ErrNoToken = errors.New("secure: no device token stored")

// TokenStore keeps the Sally device token in one protected file.
type TokenStore struct{ Path string }

// Get returns the token or ErrNoToken.
func (s TokenStore) Get() (string, error) {
	enc, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoToken
	}
	if err != nil {
		return "", err
	}
	plain, err := Unprotect(enc)
	if err != nil {
		return "", fmt.Errorf("secure: reading the token: %w", err)
	}
	if len(plain) == 0 {
		return "", ErrNoToken
	}
	return string(plain), nil
}

// Set stores the token.
func (s TokenStore) Set(token string) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	enc, err := Protect([]byte(token))
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.Path, enc)
}

// Delete forgets the token.
func (s TokenStore) Delete() error {
	err := os.Remove(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// WriteFileAtomic writes b to path 0600 through a temp file, fsyncs it,
// renames it over path and fsyncs the directory, so a crash leaves either the
// old file or the new one, never half of one.
func WriteFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil && !isWindows {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so a rename into it is durable. Windows has no
// directory fsync; NTFS journals the rename itself.
func SyncDir(dir string) error {
	if isWindows {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
