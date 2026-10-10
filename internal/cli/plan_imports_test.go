package cli

import (
	"go/parser"
	"go/token"
	"testing"
)

// Plan generation/status/confirm must never execute commands —
// they only write plan files and record confirmations.
func TestPlanFileImportsNoExec(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "plan.go", nil, 0)
	if err != nil {
		t.Fatalf("parse plan.go: %v", err)
	}
	forbidden := map[string]bool{"os/exec": true, "net/rpc": true}
	for _, imp := range f.Imports {
		path := imp.Path.Value
		if len(path) >= 2 && forbidden[path[1:len(path)-1]] {
			t.Errorf("plan.go imports forbidden package %s", path)
		}
	}
}
