package setup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// HostSystem is the real System.
type HostSystem struct{}

// Geteuid implements System.
func (HostSystem) Geteuid() int { return os.Geteuid() }

// HasSystemd implements System, with the check systemd itself documents.
func (HostSystem) HasSystemd() bool {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// Systemctl implements System.
func (HostSystem) Systemctl(ctx context.Context, args ...string) error {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "systemctl", args...) //nolint:gosec // args are fixed by the callers in this package
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}
