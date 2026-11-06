package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/inventory"
)

func init() {
	register(func() *cobra.Command {
		var asJSON bool
		var root string
		cmd := &cobra.Command{
			Use:   "inventory",
			Short: "Show installed packages with their source names, and kernel state",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				host, err := inventory.Collect(cmd.Context(), root)
				if err != nil {
					return err
				}
				if asJSON {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(host)
				}
				return printInventory(cmd.OutOrStdout(), host)
			},
		}
		cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
		cmd.Flags().StringVar(&root, "root", "", "scan the filesystem mounted at this path instead of the running host")
		return cmd
	})
}

func printInventory(out io.Writer, h *inventory.Host) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "Host:\t%s\n", h.Hostname)
	_, _ = fmt.Fprintf(w, "Release:\t%s\n", h.Release.Ecosystem)
	_, _ = fmt.Fprintf(w, "Kernel:\t%s\n", kernelSummary(h.Kernel))
	_, _ = fmt.Fprintf(w, "Packages:\t%d\n\n", len(h.Packages))
	if err := w.Flush(); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(w, "NAME\tVERSION\tARCH\tSOURCE\tSOURCE VERSION")
	for _, p := range h.Packages {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Arch, p.SourceName, p.SourceVersion)
	}
	return w.Flush()
}

func kernelSummary(k inventory.Kernel) string {
	var parts []string
	if k.Release != "" {
		parts = append(parts, k.Release)
	}
	if k.SourceName != "" {
		parts = append(parts, k.SourceName+" "+k.Version)
	}
	if len(parts) == 0 {
		parts = append(parts, "no kernel image installed")
	}
	if k.RebootRequired {
		parts = append(parts, "reboot required")
		if len(k.RebootPackages) > 0 {
			parts[len(parts)-1] += " by " + strings.Join(k.RebootPackages, ", ")
		}
	}
	return strings.Join(parts, ", ")
}
