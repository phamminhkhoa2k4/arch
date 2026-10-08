package bench

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v4"
)

// Owner is the expected owner of a listener or route target: a kind
// plus the entity name as stored in the scan (container lab-web,
// systemd_unit nginx.service).
type Owner struct {
	Kind string `yaml:"kind"`
	Name string `yaml:"name"`
}

// GTListener pins one lab-critical listener by proto/addr/port — the
// inode in the identity key changes every scan — and its owner.
type GTListener struct {
	ID            string `yaml:"id"`
	Proto         string `yaml:"proto"`
	Addr          string `yaml:"addr"`
	Port          int    `yaml:"port"`
	ExpectedOwner Owner  `yaml:"expected_owner"`
	Reason        string `yaml:"reason"`
}

// key is the attributes-based lookup key (proto|addr|port).
func (l GTListener) key() string {
	return fmt.Sprintf("%s|%s|%d", l.Proto, l.Addr, l.Port)
}

// ExpectedRoute is one tuple a simple route chain must satisfy.
type ExpectedRoute struct {
	Proto string `yaml:"proto"`
	Port  int    `yaml:"port"`
	Owner Owner  `yaml:"owner"`
}

// GTRouteChain is one ground-truth route chain. Only simple chains
// (static proxy_pass, no variables) count towards the benchmark;
// /var/, /dead/ and /ext/ stay out of the denominator.
type GTRouteChain struct {
	ID       string          `yaml:"id"`
	Location string          `yaml:"location"`
	File     string          `yaml:"file"`
	Simple   bool            `yaml:"simple"`
	Expected []ExpectedRoute `yaml:"expected"`
	Reason   string          `yaml:"reason"`
}

// GroundTruth is the benchmark slice of the ground-truth yaml file.
type GroundTruth struct {
	Listeners   []GTListener   `yaml:"listeners"`
	RouteChains []GTRouteChain `yaml:"route_chains"`
}

// findListener returns the ground-truth entry matching proto/addr/port,
// or nil when this listener is not pinned by the lab.
func (g *GroundTruth) findListener(proto, addr, port string) *GTListener {
	for i := range g.Listeners {
		l := &g.Listeners[i]
		if l.Proto == proto && l.Addr == addr && fmt.Sprintf("%d", l.Port) == port {
			return l
		}
	}
	return nil
}

// LoadGT reads and validates the ground truth. A missing or empty
// benchmark block is a tool error: CI must never "pass" on a silently
// empty denominator.
func LoadGT(path string) (*GroundTruth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(data, &gt); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(gt.Listeners) == 0 {
		return nil, fmt.Errorf("%s: missing non-empty listeners block", path)
	}
	if len(gt.RouteChains) == 0 {
		return nil, fmt.Errorf("%s: missing non-empty route_chains block", path)
	}
	return &gt, nil
}
