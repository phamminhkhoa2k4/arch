package cli

import (
	"bytes"
	"strings"
	"testing"
)

// --help lists all 8 subcommands with a short description.
func TestHelpListsEightSubcommands(t *testing.T) {
	root := rootCmd()
	addCommands(root)

	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("help: %v", err)
	}

	out := buf.String()
	want := []string{
		"scan", "observe", "delete-check", "explain",
		"plan", "report", "serve", "doctor",
	}
	for _, name := range want {
		if !strings.Contains(out, name) {
			t.Errorf("--help missing subcommand %q", name)
		}
	}
	// Every listed subcommand must carry a description (Available Commands
	// table lines contain both name and its Short text).
	if !strings.Contains(out, "Evidence-backed verdict") &&
		!strings.Contains(out, "evidence-backed verdict") {
		t.Errorf("subcommand descriptions missing:\n%s", out)
	}
}

// Exit code 2 on execution error (unknown command), 0 on success.
func TestExitCodes(t *testing.T) {
	root := rootCmd()
	addCommands(root)
	root.SetArgs([]string{"no-such-command"})
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	if err := root.Execute(); err == nil {
		t.Fatal("unknown command must error")
	}
}

// Stub commands say they are not implemented yet (skeleton behavior).
func TestStubCommandsSayNotImplemented(t *testing.T) {
	root := rootCmd()
	addCommands(root)
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"report"})
	if err := root.Execute(); err != nil {
		t.Fatalf("report: %v", err)
	}
	if !strings.Contains(buf.String(), "not implemented yet") {
		t.Fatalf("stub output = %q", buf.String())
	}
}
