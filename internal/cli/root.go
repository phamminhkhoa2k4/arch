// Package cli wires the archaeologist command tree.
// Authority: specs.md §11 (CLI contract), US-0.4.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is stamped at build time via -ldflags.
var Version = "v0.1.0-dev"

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "archaeologist",
		Short: "Evidence-first, read-only infrastructure archaeology for Linux hosts",
		Long: `Infrastructure Archaeologist discovers what is running on a server,
correlates it, and issues an evidence-backed verdict on whether it is safe
to delete — without ever modifying the scanned system.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	root := rootCmd()
	addCommands(root)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 2
	}
	return 0
}
