//go:build windows

package logstore

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// diskUsage returns (usedPercent, totalBytes, freeBytes) for the volume
// hosting path (Windows: GetDiskFreeSpaceExW).
func diskUsage(path string) (float64, uint64, uint64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, 0, 0, err
	}
	var free, total, avail uint64
	utf16Ptr, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return 0, 0, 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(utf16Ptr, &avail, &total, &free); err != nil {
		return 0, 0, 0, err
	}
	if total == 0 {
		return 0, 0, 0, nil
	}
	used := total - free
	return float64(used) / float64(total) * 100, total, free, nil
}
