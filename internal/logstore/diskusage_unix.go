//go:build !windows

package logstore

import (
	"path/filepath"
	"syscall"
)

// diskUsage returns (usedPercent, totalBytes, freeBytes) for the filesystem
// hosting path (POSIX: statfs).
func diskUsage(path string) (float64, uint64, uint64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, 0, 0, err
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(abs, &st); err != nil {
		return 0, 0, 0, err
	}
	total := uint64(st.Blocks) * uint64(st.Bsize)
	free := uint64(st.Bavail) * uint64(st.Bsize)
	if total == 0 {
		return 0, 0, 0, nil
	}
	used := total - free
	return float64(used) / float64(total) * 100, total, free, nil
}
