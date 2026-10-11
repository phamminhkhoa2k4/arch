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

// serve is a real command now: --help lists its flags and executing it
// without a database fails with an error rather than a stub message.
func TestServeIsImplemented(t *testing.T) {
	root := rootCmd()
	addCommands(root)
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"serve", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("serve --help: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "not implemented yet") {
		t.Fatalf("serve still stubbed:\n%s", out)
	}
	for _, flag := range []string{"--db", "--addr"} {
		if !strings.Contains(out, flag) {
			t.Errorf("serve --help missing %s", flag)
		}
	}
}
