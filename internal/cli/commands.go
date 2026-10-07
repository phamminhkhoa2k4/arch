package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// stub marks commands that are only registered for now — their behavior
// lands in a later epic; each subcommand fills in its logic when built.
func stub() func(*cobra.Command, []string) {
	return func(c *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(c.OutOrStdout(),
			"%s is not implemented yet.\n", c.CommandPath())
	}
}

func addCommands(root *cobra.Command) {
	root.AddCommand(
		newScanCmd(),
		&cobra.Command{
			Use:   "observe",
			Short: "Sample network activity to measure real usage over time",
			Run:   stub(),
		},
		&cobra.Command{
			Use:   "delete-check <component>",
			Short: "Issue an evidence-backed verdict for one component",
			Args:  cobra.ExactArgs(1),
			Run:   stub(),
		},
		newExplainCmd(),
		&cobra.Command{
			Use:   "plan <component>",
			Short: "Generate a staged cleanup plan with rollback commands",
			Args:  cobra.ExactArgs(1),
			Run:   stub(),
		},
		&cobra.Command{
			Use:   "report",
			Short: "Export results as HTML, JSON, or Markdown",
			Run:   stub(),
		},
		&cobra.Command{
			Use:   "serve",
			Short: "Start the local web UI",
			Run:   stub(),
		},
		&cobra.Command{
			Use:   "doctor",
			Short: "Check access rights and report blind spots you would hit",
			Run: func(c *cobra.Command, _ []string) {
				runDoctor(c.OutOrStdout(), realChecks())
			},
		},
	)
}
