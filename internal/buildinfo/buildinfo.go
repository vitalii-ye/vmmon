// Package buildinfo holds values stamped into the binary at link time.
package buildinfo

import (
	"fmt"
	"runtime"
)

// Set with -ldflags "-X github.com/vitalii-ye/vmmon/internal/buildinfo.Version=…".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a one-line build description.
func String() string {
	return fmt.Sprintf("vmmon %s (commit %s, built %s, %s, %s/%s)",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
