package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Output formats for the read commands.
const (
	formatText = "text"
	formatJSON = "json"
)

// addFormatFlag registers --format on cmd and returns a pointer the
// command closure reads at run time.
func addFormatFlag(cmd *cobra.Command) *string {
	return cmd.Flags().String("format", formatText,
		"output format: text or json")
}

// validateFormat rejects unknown values before any work runs.
func validateFormat(format string) error {
	if format != formatText && format != formatJSON {
		return fmt.Errorf("unknown --format %q (want %s or %s)", format, formatText, formatJSON)
	}
	return nil
}

// writeJSON emits v as indented JSON followed by a newline.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
