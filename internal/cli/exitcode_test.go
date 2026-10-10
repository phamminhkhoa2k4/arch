package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCodeOf(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, ExitOK},
		{"plain error", errors.New("boom"), ExitError},
		{"attention", attention(errors.New("orphaned")), ExitAttention},
		{"wrapped attention", fmt.Errorf("delete-check: %w",
			attention(errors.New("orphaned"))), ExitAttention},
	}
	for _, c := range cases {
		if got := exitCodeOf(c.err); got != c.want {
			t.Errorf("%s: exitCodeOf = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestExitErrorUnwrap(t *testing.T) {
	inner := errors.New("x")
	ee := attention(inner)
	if !errors.Is(ee, inner) {
		t.Error("attention error must wrap its cause")
	}
	if ee.Error() != "x" {
		t.Errorf("Error() = %q", ee.Error())
	}
}
