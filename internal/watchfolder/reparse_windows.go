//go:build windows

package watchfolder

import (
	"os"
	"syscall"
)

// ioReparseTagNameSurrogate marks a reparse point that stands for another
// place: a symbolic link, a junction (mount point) and the like.
const ioReparseTagNameSurrogate = 0x20000000

// isLink reports whether a folder is a reparse point that leads somewhere
// else (a junction, mount point or symbolic link). Go may report a junction
// as a plain or irregular folder, so the attributes and the reparse tag are
// read here. Other reparse points (OneDrive's cloud files, deduplication)
// are folders where they are and are not refused.
func isLink(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	var fd syscall.Win32finddata
	h, err := syscall.FindFirstFile(p, &fd)
	if err != nil {
		return true // cannot tell: refuse
	}
	_ = syscall.FindClose(h)
	// For a reparse point, dwReserved0 is its tag.
	return fd.Reserved0&ioReparseTagNameSurrogate != 0
}
