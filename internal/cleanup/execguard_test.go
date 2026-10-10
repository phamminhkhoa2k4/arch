package cleanup

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The plan builder only writes files — nothing in this package
// may import process execution or network APIs.
func TestCleanupPackageImportsNoExec(t *testing.T) {
	forbidden := map[string]bool{
		"os/exec":  true,
		"net/http": true,
		"net/rpc":  true,
		"syscall":  true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		seen++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbidden[path] {
				t.Errorf("%s imports forbidden package %q", f.Name.Name, path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("parsed zero source files")
	}
}
