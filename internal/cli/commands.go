package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// stub marks commands whose behavior lands in a later epic — US-0.4 ships
// the skeleton only; each subcommand fills in its story's logic later.
func stub(epic string) func(*cobra.Command, []string) {
	return func(c *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(c.OutOrStdout(),
			"%s is not implemented yet (planned in %s — see product-backlog.md).\n",
			c.CommandPath(), epic)
	}
}

func addCommands(root *cobra.Command) {
	root.AddCommand(
		&cobra.Command{
			Use:   "scan",
			Short: "Scan the host and print an infrastructure summary",
			Run:   stub("Epic 1–7"),
		},
		&cobra.Command{
			Use:   "observe",
			Short: "Sample network activity to measure real usage over time",
			Run:   stub("Epic 8"),
		},
		&cobra.Command{
			Use:   "delete-check <component>",
			Short: "Issue an evidence-backed verdict for one component",
			Args:  cobra.ExactArgs(1),
			Run:   stub("Epic 9"),
		},
		&cobra.Command{
			Use:   "explain <component>",
			Short: "Show dependencies, evidence, and blind spots for a component",
			Args:  cobra.ExactArgs(1),
			Run:   stub("Epic 7"),
		},
		&cobra.Command{
			Use:   "plan <component>",
			Short: "Generate a staged cleanup plan with rollback commands",
			Args:  cobra.ExactArgs(1),
			Run:   stub("Epic 10"),
		},
		&cobra.Command{
			Use:   "report",
			Short: "Export results as HTML, JSON, or Markdown",
			Run:   stub("Epic 13"),
		},
		&cobra.Command{
			Use:   "serve",
			Short: "Start the local web UI",
			Run:   stub("Epic 12"),
		},
		&cobra.Command{
			Use:   "doctor",
			Short: "Check access rights and report blind spots you would hit",
			Run:   stub("US-1.4"),
		},
	)
}
