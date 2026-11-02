package main

import (
	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/setup"
)

func init() {
	register(func() *cobra.Command {
		cmd := &cobra.Command{
			Use:   "notify",
			Short: "Work with notification channels",
			Args:  cobra.NoArgs,
		}
		cmd.AddCommand(&cobra.Command{
			Use:   "test",
			Short: "Send a test message",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := loadConfig(cmd)
				if err != nil {
					return err
				}
				return setup.SendTest(cmd.Context(), cfg, cmd.OutOrStdout())
			},
		})
		return cmd
	})
}
