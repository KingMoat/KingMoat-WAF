package coraza

import (
	"io/fs"
	"strings"
)

// slashFS normalizes path separators before they reach the underlying fs.FS.
//
// Why: coraza's seclang parser joins include paths with filepath.Join
// (internal/seclang/parser.go), which produces backslash separators on
// Windows. io/fs filesystems must only ever see forward slashes, so loading
// the embedded CRS (`Include @owasp_crs/*.conf`) fails on Windows with
// "file does not exist". Wrapping the root FS and rewriting separators fixes
// this without patching the third-party parser. On Linux this is a no-op.
type slashFS struct {
	inner fs.FS
}

func fixPath(name string) string {
	return strings.ReplaceAll(name, "\\", "/")
}

func (s slashFS) Open(name string) (fs.File, error) {
	return s.inner.Open(fixPath(name))
}

func (s slashFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(s.inner, fixPath(name))
}

func (s slashFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(s.inner, fixPath(name))
}

func (s slashFS) Glob(pattern string) ([]string, error) {
	return fs.Glob(s.inner, fixPath(pattern))
}
