package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/buildinfo"
)

func init() {
	register(func() *cobra.Command {
		return &cobra.Command{
			Use:   "version",
			Short: "Print build information",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
			},
		}
	})
}
