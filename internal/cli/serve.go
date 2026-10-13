package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"archaeologist/internal/store"
	"archaeologist/internal/webui"
)

// newServeCmd starts the local web UI over the evidence database.
// The server binds to localhost by default and performs no network
// egress.
func newServeCmd() *cobra.Command {
	var dbPath, addr string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local web UI",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cmd.OutOrStdout(), dbPath, addr)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&addr, "addr", "localhost:8080",
		"address to listen on (localhost only by default)")
	return cmd
}

func runServe(ctx context.Context, w io.Writer, dbPath, addr string) error {
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()
	srv, err := webui.New(ctx, st)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Web UI is running at http://%s (Ctrl+C to stop)\n", addr)
	return srv.ListenAndServe(ctx, addr)
}
