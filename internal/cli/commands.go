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
		newImpactCmd(),
		newComponentsCmd(),
		newPlanCmd(),
		newReportCmd(),
		newServeCmd(),
	)
	root.AddCommand(newDoctorCmd())
}

// newDoctorCmd wires the read-only access and database-safety probes.
func newDoctorCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check access rights and report blind spots you would hit",
		Run: func(c *cobra.Command, _ []string) {
			runDoctor(c.OutOrStdout(), realChecks(dbPath))
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	return cmd
}
