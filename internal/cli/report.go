package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"archaeologist/internal/report"
	"archaeologist/internal/store"
)

const (
	formatHTML = "html"
	formatMD   = "md"
)

// newReportCmd exports the latest scan as a self-contained HTML file,
// JSON, or Markdown. HTML is the default and requires -o; JSON and
// Markdown default to stdout.
func newReportCmd() *cobra.Command {
	var dbPath, outPath, format string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Export results as HTML, JSON, or Markdown",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd.OutOrStdout(), dbPath, outPath, format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVarP(&outPath, "out", "o", "",
		"output file (required for --format html; stdout when empty)")
	cmd.Flags().StringVar(&format, "format", formatHTML,
		"output format: html, json, or md")
	return cmd
}

// validateReportFormat accepts exactly html, json, md.
func validateReportFormat(format string) error {
	switch format {
	case formatHTML, formatJSON, formatMD:
		return nil
	}
	return fmt.Errorf("unknown --format %q (want html, json, or md)", format)
}

func runReport(ctx context.Context, w io.Writer, dbPath, outPath, format string) error {
	if err := validateReportFormat(format); err != nil {
		return err
	}
	if format == formatHTML && outPath == "" {
		return fmt.Errorf("--format html requires --out <file>")
	}

	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()

	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		return err
	}
	r, err := report.Build(ctx, st, scanID)
	if err != nil {
		return err
	}

	switch format {
	case formatJSON:
		return writeJSON(w, r)
	case formatMD:
		return report.WriteMarkdown(w, r)
	default: // html — write to -o, report the path on stdout
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create report file: %w", err)
		}
		if err := report.WriteHTML(f, r); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close report file: %w", err)
		}
		_, _ = fmt.Fprintf(w, "Báo cáo đã ghi: %s (scan #%d)\n", outPath, scanID)
		return nil
	}
}
