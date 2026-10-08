package store

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"archaeologist/internal/collector"
)

// seedGraphEntities inserts entities with distinct keys in the scan
// bound to k; kind is derived from the key prefix (listener|x → listener).
func seedGraphEntities(t *testing.T, k *ScanSink, keys ...string) {
	t.Helper()
	for i, key := range keys {
		kind := key
		if idx := strings.Index(key, "|"); idx > 0 {
			kind = key[:idx]
		}
		if err := k.UpsertEntity(collector.Entity{
			Kind:        kind,
			Name:        key,
			IdentityKey: key,
			Fingerprint: "f",
			Attributes:  map[string]string{"n": itoa(i)},
		}); err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
	}
}

// seedGraphEdge links src→dst with one fresh evidence row on src.
func seedGraphEdge(t *testing.T, k *ScanSink, src, dst, kind string, strength collector.Strength) {
	t.Helper()
	ref := "ev-" + kind + "-" + src + "-" + dst
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: src,
		Polarity:          collector.PolarityNeutral,
		Channel:           "test",
		Strength:          strength,
		ObservedAt:        now(),
		RawRef:            "/x:1",
		Ref:               ref,
	}); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if err := k.UpsertEdge(collector.Edge{
		SrcIdentityKey: src,
		DstIdentityKey: dst,
		Kind:           kind,
		Strength:       strength,
		EvidenceRef:    ref,
	}); err != nil {
		t.Fatalf("upsert edge: %v", err)
	}
}

func entityID(t *testing.T, s *Store, scanID int64, key string) int64 {
	t.Helper()
	rows, err := s.FindEntities(context.Background(), scanID, key)
	if err != nil || len(rows) != 1 {
		t.Fatalf("resolve %s: err=%v rows=%d", key, err, len(rows))
	}
	return rows[0].ID
}

// NeighborRows splits incident edges into the four explain groups,
// keeps evidence on every row, and returns them in a stable order.
func TestNeighborRowsGroups(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	subject := "container|subj"
	seedGraphEntities(t, k,
		subject, "listener|tcp|0.0.0.0|8081|1",
		"image|nginx:1.27", "ci_job|build-7", "timer|lab-watchdog.timer")
	seedGraphEdge(t, k, "listener|tcp|0.0.0.0|8081|1", subject, "listens_on", collector.StrengthDeterministic)
	seedGraphEdge(t, k, subject, "image|nginx:1.27", "depends_on", collector.StrengthDeterministic)
	seedGraphEdge(t, k, subject, "ci_job|build-7", "deployed_by", collector.StrengthStrongHeuristic)
	seedGraphEdge(t, k, subject, "timer|lab-watchdog.timer", "scheduled_by", collector.StrengthDeterministic)

	rows, err := s.NeighborRows(ctx, k.scanID, entityID(t, s, k.scanID, subject))
	if err != nil {
		t.Fatalf("neighbor rows: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
	}

	wantOrder := []string{
		GroupIncoming, GroupOutgoing, GroupDeployedBy, GroupScheduledBy,
	}
	for i, want := range wantOrder {
		if rows[i].Group != want {
			t.Errorf("row %d group = %q, want %q", i, rows[i].Group, want)
		}
	}
	if rows[0].EdgeKind != "listens_on" || rows[0].NeighborKind != "listener" {
		t.Errorf("incoming row = %+v", rows[0])
	}
	if rows[1].EdgeKind != "depends_on" || rows[1].NeighborKey != "image|nginx:1.27" {
		t.Errorf("outgoing row = %+v", rows[1])
	}
	// The deployed_by axis keeps its strength label — never promoted.
	if rows[2].Group != GroupDeployedBy || rows[2].Strength != "strong_heuristic" {
		t.Errorf("deployed_by row = %+v", rows[2])
	}
	if rows[3].Group != GroupScheduledBy || rows[3].EdgeKind != "scheduled_by" {
		t.Errorf("scheduled_by row = %+v", rows[3])
	}
	for i, r := range rows {
		if r.Channel != "test" || r.RawRef != "/x:1" {
			t.Errorf("row %d evidence = channel %q raw %q, want test /x:1", i, r.Channel, r.RawRef)
		}
	}

	again, err := s.NeighborRows(ctx, k.scanID, entityID(t, s, k.scanID, subject))
	if err != nil {
		t.Fatalf("neighbor rows again: %v", err)
	}
	if !reflect.DeepEqual(rows, again) {
		t.Error("two identical calls returned different orders")
	}
}

// An entity with no incident edges yields an isolated result so explain
// can print the "không có phụ thuộc" line.
func TestNeighborRowsIsolated(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)

	seedGraphEntities(t, k, "script|/opt/lonely.sh")
	rows, err := s.NeighborRows(context.Background(), k.scanID,
		entityID(t, s, k.scanID, "script|/opt/lonely.sh"))
	if err != nil {
		t.Fatalf("neighbor rows: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("isolated entity: got %d rows, want 0", len(rows))
	}
}

// The recursive CTE returns full 5-hop chains and stops at maxDepth.
func TestChainFiveLevels(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	chain := []string{"a|0", "b|1", "c|2", "d|3", "e|4", "f|5"}
	seedGraphEntities(t, k, chain...)
	for i := 0; i < len(chain)-1; i++ {
		seedGraphEdge(t, k, chain[i], chain[i+1], "depends_on", collector.StrengthDeterministic)
	}

	rows, err := s.Chain(ctx, k.scanID, entityID(t, s, k.scanID, chain[0]), 5)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	var deepest *ChainRow
	for i := range rows {
		if rows[i].Depth == 5 && rows[i].Nodes[len(rows[i].Nodes)-1].Name == chain[5] {
			deepest = &rows[i]
		}
	}
	if deepest == nil {
		t.Fatalf("no depth-5 path to %s in %d rows", chain[5], len(rows))
	}
	if len(deepest.Nodes) != 6 || len(deepest.EdgeKinds) != 5 {
		t.Errorf("path shape = %d nodes / %d kinds, want 6 / 5", len(deepest.Nodes), len(deepest.EdgeKinds))
	}
	for _, st := range deepest.Strengths {
		if st != "deterministic" {
			t.Errorf("strength %q, want deterministic", st)
		}
	}

	// Depth cap: 4 hops must not reach the 6th node.
	short, err := s.Chain(ctx, k.scanID, entityID(t, s, k.scanID, chain[0]), 4)
	if err != nil {
		t.Fatalf("chain depth 4: %v", err)
	}
	for _, r := range short {
		if r.Nodes[len(r.Nodes)-1].Name == chain[5] {
			t.Errorf("depth 4 must not reach %s: %+v", chain[5], r)
		}
	}
}

// Ownership walks run against the stored direction (process sees the
// incoming manages edge as a step towards its unit).
func TestChainTraversesAgainstEdgeDirection(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	seedGraphEntities(t, k, "listener|l1", "process|77", "systemd_unit|nginx.service")
	seedGraphEdge(t, k, "listener|l1", "process|77", "listens_on", collector.StrengthDeterministic)
	seedGraphEdge(t, k, "systemd_unit|nginx.service", "process|77", "manages", collector.StrengthDeterministic)

	rows, err := s.Chain(ctx, k.scanID, entityID(t, s, k.scanID, "listener|l1"), 2)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.Depth != 2 || len(r.Nodes) != 3 {
			continue
		}
		if r.Nodes[2].Kind != "systemd_unit" {
			continue
		}
		if !reflect.DeepEqual(r.Reversed, []bool{false, true}) {
			t.Errorf("reversed flags = %v, want [false true]", r.Reversed)
		}
		found = true
	}
	if !found {
		t.Fatalf("no listener→process→unit chain in %d rows", len(rows))
	}
}

// Cycles must terminate without ever revisiting a node on one path.
func TestChainCycleTerminates(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	seedGraphEntities(t, k, "p|a", "p|b", "p|c")
	seedGraphEdge(t, k, "p|a", "p|b", "depends_on", collector.StrengthDeterministic)
	seedGraphEdge(t, k, "p|b", "p|c", "depends_on", collector.StrengthDeterministic)
	seedGraphEdge(t, k, "p|c", "p|a", "depends_on", collector.StrengthDeterministic)

	rows, err := s.Chain(ctx, k.scanID, entityID(t, s, k.scanID, "p|a"), 5)
	if err != nil {
		t.Fatalf("chain over cycle: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("cycle graph: want walks, got none")
	}
	for _, r := range rows {
		if r.Depth > 3 {
			t.Errorf("cycle walk depth %d exceeds node count 3", r.Depth)
		}
		seen := map[int64]bool{}
		for _, n := range r.Nodes {
			if seen[n.ID] {
				t.Errorf("path %+v revisits node %d", r.Nodes, n.ID)
			}
			seen[n.ID] = true
		}
	}
}

// Parallel routes to one node all come back, in the same order on
// every call — the benchmark must not depend on scan order.
func TestChainDeterministicOrder(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	seedGraphEntities(t, k, "r|start", "r|left", "r|right", "r|end")
	seedGraphEdge(t, k, "r|start", "r|left", "proxies_to", collector.StrengthDeterministic)
	seedGraphEdge(t, k, "r|start", "r|right", "proxies_to", collector.StrengthDeterministic)
	seedGraphEdge(t, k, "r|left", "r|end", "proxies_to", collector.StrengthDeterministic)
	seedGraphEdge(t, k, "r|right", "r|end", "proxies_to", collector.StrengthDeterministic)

	start := entityID(t, s, k.scanID, "r|start")
	first, err := s.Chain(ctx, k.scanID, start, 3)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	second, err := s.Chain(ctx, k.scanID, start, 3)
	if err != nil {
		t.Fatalf("chain again: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Error("two identical chain calls differ")
	}

	ends := 0
	for _, r := range first {
		if r.Depth == 2 && r.Nodes[len(r.Nodes)-1].Name == "r|end" {
			ends++
			joined := strings.Join(r.EdgeKinds, ">")
			if joined != "proxies_to>proxies_to" {
				t.Errorf("edge kinds = %q", joined)
			}
		}
	}
	if ends != 2 {
		t.Errorf("got %d walks ending at r|end, want 2 (left and right)", ends)
	}
}

// maxDepth below 1 returns no walks instead of erroring.
func TestChainNonPositiveDepth(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	rows, err := s.Chain(context.Background(), k.scanID, 1, 0)
	if err != nil {
		t.Fatalf("chain depth 0: %v", err)
	}
	if rows != nil {
		t.Fatalf("want nil, got %+v", rows)
	}
}
