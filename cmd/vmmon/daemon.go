package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/daemon"
	"github.com/vitalii-ye/vmmon/internal/notify"
)

func init() {
	register(func() *cobra.Command {
		var root string
		cmd := &cobra.Command{
			Use:   "daemon",
			Short: "Keep the database fresh, rescan on changes and send alerts, until signalled",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := loadConfig(cmd)
				if err != nil {
					return err
				}
				deps := daemon.Deps{Root: root}
				n, err := notify.New(cfg)
				switch {
				case err == nil:
					deps.Notifier = n
				case errors.Is(err, notify.ErrNotConfigured):
					slog.Warn("no notification channel configured: findings stay un-notified until `sudo vmmon setup` runs")
				default:
					return fmt.Errorf("notification channel: %w", err)
				}
				slog.Info("daemon starting", "state_dir", cfg.StateDir, "policy", cfg.Policy.Preset, "telegram_token", cfg.Telegram.Redacted())
				return daemon.New(cfg, deps).Run(cmd.Context())
			},
		}
		cmd.Flags().StringVar(&root, "root", "", "watch the filesystem mounted at this path instead of the running host")
		_ = cmd.Flags().MarkHidden("root")
		return cmd
	})
}
