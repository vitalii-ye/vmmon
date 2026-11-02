// Command vmmon scans a Debian or Ubuntu host for known vulnerabilities and
// alerts over Telegram when new ones appear.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/config"
)

// commands collects subcommands. Each lives in its own file and registers
// itself from init, so adding one never touches this file.
var commands []func() *cobra.Command

func register(c func() *cobra.Command) { commands = append(commands, c) }

// errSilent marks a failure the command has already reported to the user.
var errSilent = errors.New("silent")

func newRootCmd() *cobra.Command {
	var configPath string
	var verbose bool
	root := &cobra.Command{
		Use:           "vmmon",
		Short:         "Host vulnerability monitor for Debian and Ubuntu VMs",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(*cobra.Command, []string) {
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
		},
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "config file (default $VMMON_CONFIG or "+config.DefaultPath+")")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "debug logging")
	for _, c := range commands {
		root.AddCommand(c())
	}
	return root
}

// loadConfig loads the config selected by the root --config flag.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	path, err := cmd.Root().PersistentFlags().GetString("config")
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		if !errors.Is(err, errSilent) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}
