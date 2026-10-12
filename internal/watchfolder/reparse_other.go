//go:build !windows

package watchfolder

import "os"

// isLink: outside Windows a symbolic link is the only thing that leads
// elsewhere, and Lstat reports it as one.
func isLink(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
