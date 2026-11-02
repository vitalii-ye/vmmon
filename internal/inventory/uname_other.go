//go:build !linux

package inventory

import (
	"errors"
	"runtime"
)

// uname fails off Linux, where there is no kernel package to relate it to.
func uname() (string, error) {
	return "", errors.New("not supported on " + runtime.GOOS)
}
