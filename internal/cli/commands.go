package cli

import (
	"github.com/spf13/cobra"
)

func addCommands(root *cobra.Command) {
	root.AddCommand(
		newScanCmd(),
		newObserveCmd(),
		newExplainCmd(),
		newDeleteCheckCmd(),
		newPlanCmd(),
		newReportCmd(),
		newServeCmd(),
		&cobra.Command{
			Use:   "doctor",
			Short: "Check access rights and report blind spots you would hit",
			Run: func(c *cobra.Command, _ []string) {
				runDoctor(c.OutOrStdout(), realChecks())
			},
		},
	)
}
