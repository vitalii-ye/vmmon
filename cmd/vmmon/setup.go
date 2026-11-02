package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vitalii-ye/vmmon/internal/setup"
)

func init() {
	register(func() *cobra.Command {
		var opts setup.Options
		cmd := &cobra.Command{
			Use:       "setup [telegram]",
			Short:     "Pair a Telegram chat, send a test message and start the service",
			Long:      "Interactive wizard. Telegram is the only channel for now, so `setup` and `setup telegram` are the same.\n\nFor scripts: vmmon setup telegram --token-file PATH --chat-id ID --policy quiet --yes",
			ValidArgs: []string{"telegram"},
			Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
			RunE: func(cmd *cobra.Command, _ []string) error {
				path, err := cmd.Root().PersistentFlags().GetString("config")
				if err != nil {
					return err
				}
				opts.ConfigPath = path

				deps := setup.Deps{In: os.Stdin, Out: cmd.OutOrStdout(), System: setup.HostSystem{}}
				if fd := int(os.Stdin.Fd()); !opts.Yes && term.IsTerminal(fd) {
					// A Ctrl-C during the hidden prompt must not leave echo off.
					state, err := term.GetState(fd)
					if err != nil {
						return err
					}
					defer term.Restore(fd, state)
					deps.ReadSecret = func() (string, error) {
						b, err := term.ReadPassword(fd)
						fmt.Fprintln(cmd.OutOrStdout())
						return string(b), err
					}
				}
				return setup.Run(cmd.Context(), opts, deps)
			},
		}
		f := cmd.Flags()
		f.StringVar(&opts.TokenFile, "token-file", "", "read the bot token from this file")
		f.StringVar(&opts.ChatID, "chat-id", "", "chat ID to use instead of pairing")
		f.StringVar(&opts.Policy, "policy", "", "alert policy: quiet, critical or everything")
		f.BoolVar(&opts.Yes, "yes", false, "never prompt; fail if a required value is missing")
		f.BoolVar(&opts.NoStart, "no-start", false, "save settings but do not touch the service")
		return cmd
	})
}
