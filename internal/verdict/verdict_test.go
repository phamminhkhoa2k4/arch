package verdict

import (
	"strings"
	"testing"
	"time"

	"archaeologist/internal/rules"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func defaultRules(t *testing.T) rules.Rules {
	t.Helper()
	r, _, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func baseInput(kind string) Input {
	return Input{
		EntityID:    1,
		Kind:        kind,
		Name:        "subject",
		IdentityKey: kind + "|subject",
		Attributes:  map[string]string{},
		Window: Window{
			Start:  "2026-09-01T00:00:00Z",
			End:    "2026-10-08T00:00:00Z",
			Days:   37,
			Source: "first_seen",
		},
	}
}

func ev(id int64, channel, polarity, strength string, value map[string]string) Evidence {
	if value == nil {
		value = map[string]string{}
	}
	return Evidence{
		ID: id, Polarity: polarity, Channel: channel, Strength: strength,
		ObservedAt: "2026-10-08T00:00:00Z", RawRef: channel + ":src", Value: value,
	}
}

func codes(items []Item) string {
	var out []string
	for _, it := range items {
		out = append(out, it.Code)
	}
	return strings.Join(out, ",")
}

func hasCode(items []Item, code string) bool {
	for _, it := range items {
		if it.Code == code {
			return true
		}
	}
	return false
}

// --- B1: nginx route/upstream reference chain ---

func TestB1ChainBlocksContainer(t *testing.T) {
	in := baseInput("container")
	in.Attributes["state"] = "running"
	in.Attributes["created_at"] = "2026-10-01T00:00:00Z"
	in.Evidence = []Evidence{
		ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"}),
		ev(2, "docker_created", "neutral", "deterministic", map[string]string{"created_at": "2026-10-01T00:00:00Z"}),
	}
	in.Paths = []Path{{
		NodeIDs:    []int64{1, 2, 3, 4},
		NodeKinds:  []string{"container", "listener", "nginx_upstream", "nginx_route"},
		NodeNames:  []string{"lab-web", "0.0.0.0:8081", "lab_pool", "/pool/"},
		EdgeKinds:  []string{"listens_on", "proxies_to", "proxies_to"},
		Strengths:  []string{"deterministic", "deterministic", "deterministic"},
		Reversed:   []bool{true, true, true},
		EvidenceID: 42,
		RawRef:     "nginx:/etc/nginx/conf.d/lab.conf:12",
	}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive {
		t.Errorf("state = %s, want ACTIVE", res.State)
	}
	if !hasCode(res.Blockers, "B1") {
		t.Errorf("blockers = %v, want B1", codes(res.Blockers))
	}
	if res.Blockers[0].EvidenceID != 42 || res.Blockers[0].RawRef == "" {
		t.Errorf("B1 must trace evidence: %+v", res.Blockers[0])
	}
}

func TestB1RouteNotBlockedByItsOwnDownstream(t *testing.T) {
	in := baseInput("nginx_route")
	in.Evidence = []Evidence{ev(1, "nginx", "neutral", "deterministic", nil)}
	in.Paths = []Path{{
		NodeIDs:    []int64{1, 2},
		NodeKinds:  []string{"nginx_route", "listener"},
		NodeNames:  []string{"/web/", "0.0.0.0:8081"},
		EdgeKinds:  []string{"proxies_to"},
		Strengths:  []string{"deterministic"},
		Reversed:   []bool{false}, // stored src = this route: outgoing reference
		EvidenceID: 9,
		RawRef:     "nginx:lab.conf:3",
	}}
	res := Compute(in, defaultRules(t), now)
	if hasCode(res.Blockers, "B1") {
		t.Errorf("route must not be blocked by what it points at: %v", codes(res.Blockers))
	}
	if res.State != StateUnknown {
		t.Errorf("state = %s, want UNKNOWN (coverage 1/2 = LOW)", res.State)
	}
}

func TestB1ListenerBlockedByActiveRoute(t *testing.T) {
	in := baseInput("listener")
	in.Evidence = []Evidence{ev(1, "procfs_net", "in_use", "deterministic", nil)}
	in.Paths = []Path{{
		NodeIDs:    []int64{1, 2},
		NodeKinds:  []string{"listener", "nginx_route"},
		NodeNames:  []string{"0.0.0.0:8081", "/web/"},
		EdgeKinds:  []string{"proxies_to"},
		Strengths:  []string{"deterministic"},
		Reversed:   []bool{true},
		EvidenceID: 5,
		RawRef:     "nginx:lab.conf:9",
	}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive || !hasCode(res.Blockers, "B1") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B1", res.State, codes(res.Blockers))
	}
}

// --- B2: inbound inside the observation window ---

func TestB2ObservationInWindowBlocks(t *testing.T) {
	in := baseInput("container")
	in.Attributes["state"] = "running"
	in.Attributes["created_at"] = "2026-10-01T00:00:00Z"
	in.Evidence = []Evidence{
		ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"}),
		ev(2, "docker_created", "neutral", "deterministic", map[string]string{"created_at": "2026-10-01T00:00:00Z"}),
	}
	in.Observations = []Observation{{ID: 7, LastSeenAt: "2026-10-07T10:00:00Z", Count: 12}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive || !hasCode(res.Blockers, "B2") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B2", res.State, codes(res.Blockers))
	}
}

func TestB2ObservationBeforeWindowDoesNotBlock(t *testing.T) {
	in := baseInput("container")
	in.Attributes["state"] = "running"
	in.Attributes["created_at"] = "2026-10-01T00:00:00Z"
	in.Evidence = []Evidence{
		ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"}),
		ev(2, "docker_created", "neutral", "deterministic", map[string]string{"created_at": "2026-10-01T00:00:00Z"}),
	}
	in.Observations = []Observation{{ID: 7, LastSeenAt: "2026-08-15T10:00:00Z", Count: 3}}
	res := Compute(in, defaultRules(t), now)
	if hasCode(res.Blockers, "B2") {
		t.Errorf("stale observation must not block: %s", codes(res.Blockers))
	}
	if res.State != StateOrphaned {
		t.Errorf("state = %s, want ORPHANED (2/2 HIGH, window ok)", res.State)
	}
}

func TestB2AccessLogTrafficBlocksRoute(t *testing.T) {
	in := baseInput("nginx_route")
	in.Evidence = []Evidence{
		ev(1, "nginx", "neutral", "deterministic", nil),
		ev(2, "nginx_access_log", "in_use", "deterministic",
			map[string]string{"last_request_at": "2026-10-07T09:00:00Z", "count": "5"}),
	}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive || !hasCode(res.Blockers, "B2") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B2", res.State, codes(res.Blockers))
	}
}

// --- B3: active unit depends_on ---

func TestB3ActiveUnitDependsOnBlocks(t *testing.T) {
	cases := []struct {
		name      string
		neighbor  Neighbor
		strength  string
		wantBlock bool
	}{
		{"active deterministic", Neighbor{Kind: "systemd_unit", Name: "a.service",
			Attributes: map[string]string{"active_state": "active"}}, "deterministic", true},
		{"inactive", Neighbor{Kind: "systemd_unit", Name: "b.service",
			Attributes: map[string]string{"active_state": "inactive"}}, "deterministic", false},
		{"weak never blocks", Neighbor{Kind: "systemd_unit", Name: "c.service",
			Attributes: map[string]string{"active_state": "active"}}, "weak_heuristic", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput("systemd_unit")
			in.Attributes["active_state"] = "active"
			in.Evidence = []Evidence{
				ev(1, "systemd", "in_use", "deterministic", map[string]string{"active_state": "active"}),
				ev(2, "journald", "in_use", "deterministic", nil),
			}
			in.Edges = []EdgeFact{{
				Kind: "depends_on", Strength: tc.strength, Dir: "in",
				EvidenceID: 5, RawRef: "unit-dep:a.service:12:Requires", Neighbor: tc.neighbor,
			}}
			res := Compute(in, defaultRules(t), now)
			if got := hasCode(res.Blockers, "B3"); got != tc.wantBlock {
				t.Errorf("B3 block=%v want=%v (state %s)", got, tc.wantBlock, res.State)
			}
			if tc.wantBlock && res.State != StateActive {
				t.Errorf("state = %s, want ACTIVE", res.State)
			}
		})
	}
}

// --- B4: compose depends_on ---

func TestB4DependencyTargetBlocksButDependentDoesNot(t *testing.T) {
	r := defaultRules(t)
	r.Coverage.Channels["container"] = []string{"docker"} // keep coverage trivial

	// lab-helper: container → svc ← depended by svc-web (reversed dep hop).
	depended := baseInput("container")
	depended.Attributes["state"] = "running"
	depended.Evidence = []Evidence{ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"})}
	depended.Paths = []Path{{
		NodeIDs:    []int64{1, 2, 3},
		NodeKinds:  []string{"container", "compose_service", "compose_service"},
		NodeNames:  []string{"lab-helper", "proj/helper", "proj/web"},
		EdgeKinds:  []string{"belongs_to", "depends_on"},
		Strengths:  []string{"deterministic", "deterministic"},
		Reversed:   []bool{false, true},
		EvidenceID: 11,
		RawRef:     "compose:docker-compose.yml#web.depends_on",
	}}
	res := Compute(depended, r, now)
	if res.State != StateActive || !hasCode(res.Blockers, "B4") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B4", res.State, codes(res.Blockers))
	}

	// lab-web declares the dependency itself: forward dep hop → no B4.
	dependent := baseInput("container")
	dependent.Attributes["state"] = "running"
	dependent.Evidence = []Evidence{ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"})}
	dependent.Paths = []Path{{
		NodeIDs:    []int64{1, 2, 3},
		NodeKinds:  []string{"container", "compose_service", "compose_service"},
		NodeNames:  []string{"lab-web", "proj/web", "proj/helper"},
		EdgeKinds:  []string{"belongs_to", "depends_on"},
		Strengths:  []string{"deterministic", "deterministic"},
		Reversed:   []bool{false, false},
		EvidenceID: 12,
		RawRef:     "compose:docker-compose.yml#web.depends_on",
	}}
	res = Compute(dependent, r, now)
	if hasCode(res.Blockers, "B4") {
		t.Errorf("dependent must not be blocked by its own dependency: %s", codes(res.Blockers))
	}
}

// --- B5: cron/timer references both sides ---

func TestB5CronReferenceBlocksTarget(t *testing.T) {
	in := baseInput("container")
	in.Attributes["state"] = "running"
	in.Evidence = []Evidence{ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"})}
	in.Edges = []EdgeFact{{
		Kind: "references", Strength: "deterministic", Dir: "in",
		EvidenceID: 21, RawRef: "/etc/cron.d/lab:3",
		Neighbor: Neighbor{Kind: "cron_job", Name: "backup.sh", Attributes: map[string]string{}},
	}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive || !hasCode(res.Blockers, "B5") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B5", res.State, codes(res.Blockers))
	}
}

func TestB5ValidSchedulerBlocksItself(t *testing.T) {
	in := baseInput("cron_job")
	in.Evidence = []Evidence{ev(1, "cron", "neutral", "deterministic", nil)}
	in.Edges = []EdgeFact{{
		Kind: "references", Strength: "deterministic", Dir: "out",
		EvidenceID: 31, RawRef: "/etc/crontab:17",
		Neighbor: Neighbor{Kind: "script", Name: "/opt/lab/heartbeat.sh", Attributes: map[string]string{}},
	}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive || !hasCode(res.Blockers, "B5") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B5", res.State, codes(res.Blockers))
	}
}

func TestB5OrphanCronWithoutTargetIsOrphaned(t *testing.T) {
	in := baseInput("cron_job")
	in.Evidence = []Evidence{ev(1, "cron", "neutral", "deterministic", nil)}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateOrphaned {
		t.Errorf("state = %s, want ORPHANED (1/1 coverage, no refs, window ok)", res.State)
	}
}

// --- B6: running subjects ---

func TestB6RunningSubjectsBlock(t *testing.T) {
	cases := []struct {
		name     string
		edge     EdgeFact
		wantCode bool
	}{
		{"live listener maps onto subject", EdgeFact{
			Kind: "listens_on", Strength: "deterministic", Dir: "in",
			Neighbor: Neighbor{Kind: "listener", Name: "0.0.0.0:9090", InUseChannels: []string{"procfs_net"}},
		}, true},
		{"dead listener mapping", EdgeFact{
			Kind: "listens_on", Strength: "deterministic", Dir: "in",
			Neighbor: Neighbor{Kind: "listener", Name: "0.0.0.0:9090"},
		}, false},
		{"subject holds port of running owner", EdgeFact{
			Kind: "listens_on", Strength: "deterministic", Dir: "out",
			Neighbor: Neighbor{Kind: "container", Name: "lab-web",
				Attributes: map[string]string{"state": "running"}},
		}, true},
		{"active unit executes script", EdgeFact{
			Kind: "runs_as", Strength: "deterministic", Dir: "in",
			Neighbor: Neighbor{Kind: "systemd_unit", Name: "lab-app.service",
				Attributes: map[string]string{"active_state": "active"}},
		}, true},
		{"running container manages process", EdgeFact{
			Kind: "manages", Strength: "deterministic", Dir: "in",
			Neighbor: Neighbor{Kind: "container", Name: "lab-api",
				Attributes: map[string]string{"state": "running"}},
		}, true},
		{"weak edge never blocks", EdgeFact{
			Kind: "listens_on", Strength: "weak_heuristic", Dir: "in",
			Neighbor: Neighbor{Kind: "listener", Name: "0.0.0.0:9090", InUseChannels: []string{"procfs_net"}},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput("process")
			in.Evidence = []Evidence{ev(1, "procfs", "in_use", "deterministic", nil)}
			in.Edges = []EdgeFact{tc.edge}
			res := Compute(in, defaultRules(t), now)
			if got := hasCode(res.Blockers, "B6"); got != tc.wantCode {
				t.Errorf("B6 block=%v want=%v (state %s)", got, tc.wantCode, res.State)
			}
			if tc.wantCode && res.State != StateActive {
				t.Errorf("state = %s, want ACTIVE", res.State)
			}
		})
	}
}

// --- The regression that matters most (old-api) ---

func TestOldAPIRegression(t *testing.T) {
	build := func(withObservation bool) Input {
		in := baseInput("container")
		in.Attributes["state"] = "exited"
		in.Attributes["created_at"] = "2026-04-01T00:00:00Z"
		in.Evidence = []Evidence{
			ev(1, "docker", "neutral", "deterministic", map[string]string{"state": "exited"}),
			ev(2, "docker_created", "neutral", "deterministic",
				map[string]string{"created_at": "2026-04-01T00:00:00Z", "last_deploy_at": "2026-04-01T00:00:00Z"}),
			ev(3, "mtime", "neutral", "deterministic",
				map[string]string{"age_days": "210", "mtime": "2026-03-10T00:00:00Z"}),
		}
		if withObservation {
			in.Observations = []Observation{{ID: 9, LastSeenAt: "2026-10-08T01:00:00Z", Count: 4}}
		}
		return in
	}

	// With a recent inbound connection the verdict must stay ACTIVE
	// no matter how stale everything else looks — never a percentage
	// orphan guess.
	res := Compute(build(true), defaultRules(t), now)
	if res.State != StateActive {
		t.Errorf("old-api with inbound: state = %s, want ACTIVE", res.State)
	}
	if !hasCode(res.Blockers, "B2") {
		t.Errorf("old-api with inbound: blockers = %s, want B2", codes(res.Blockers))
	}
	for _, s := range res.Signals {
		if s.Code == "" {
			t.Error("signals must carry codes")
		}
	}
	if len(res.Signals) == 0 {
		t.Error("old-api must still show its stale signals")
	}

	// Without any inbound evidence the same entity is a clean orphan
	// candidate (coverage 2/2 HIGH, window sufficient).
	res = Compute(build(false), defaultRules(t), now)
	if res.State != StateOrphaned {
		t.Errorf("old-api without inbound: state = %s, want ORPHANED", res.State)
	}
}

// --- Coverage (D2) ---

func TestCoverageNineOfTwelveIsMedium(t *testing.T) {
	r := defaultRules(t)
	channels := []string{"c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10", "c11", "c12"}
	r.Coverage.Channels = map[string][]string{"probe": channels}
	in := baseInput("probe")
	for i := 1; i <= 9; i++ {
		in.Evidence = append(in.Evidence, ev(int64(i), channels[i-1], "neutral", "deterministic", nil))
	}
	res := Compute(in, r, now)
	if res.Coverage != "MEDIUM" {
		t.Errorf("coverage = %s, want MEDIUM", res.Coverage)
	}
	if len(res.Missing) != 3 {
		t.Errorf("missing = %v, want 3 channels", res.Missing)
	}
	if res.State != StateLikelyOrphaned {
		t.Errorf("state = %s, want LIKELY_ORPHANED (MEDIUM, no blockers)", res.State)
	}
}

func TestCoverageEdgeCases(t *testing.T) {
	r := defaultRules(t)
	r.Coverage.Channels = map[string][]string{"probe": {"c1", "c2"}}

	t.Run("zero channels checked", func(t *testing.T) {
		in := baseInput("probe")
		res := Compute(in, r, now)
		if res.Coverage != "LOW" || res.State != StateUnknown {
			t.Errorf("coverage=%s state=%s, want LOW/UNKNOWN", res.Coverage, res.State)
		}
		if len(res.Missing) != 2 {
			t.Errorf("missing = %v", res.Missing)
		}
	})

	t.Run("full channels but short window", func(t *testing.T) {
		in := baseInput("probe")
		in.Evidence = []Evidence{
			ev(1, "c1", "neutral", "deterministic", nil),
			ev(2, "c2", "neutral", "deterministic", nil),
		}
		in.Window.Days = 3 // below observation_window_days=14
		res := Compute(in, r, now)
		if res.Coverage != "LOW" || res.State != StateUnknown {
			t.Errorf("coverage=%s state=%s, want LOW/UNKNOWN", res.Coverage, res.State)
		}
		joined := strings.Join(res.Reasons, " ")
		if !strings.Contains(joined, "cửa sổ quan sát 3 ngày") {
			t.Errorf("reasons must mention the short window: %v", res.Reasons)
		}
	})

	t.Run("full channels and window", func(t *testing.T) {
		in := baseInput("probe")
		in.Evidence = []Evidence{
			ev(1, "c1", "neutral", "deterministic", nil),
			ev(2, "c2", "neutral", "deterministic", nil),
		}
		res := Compute(in, r, now)
		if res.Coverage != "HIGH" || res.State != StateOrphaned {
			t.Errorf("coverage=%s state=%s, want HIGH/ORPHANED", res.Coverage, res.State)
		}
		if len(res.Reasons) < 2 {
			t.Errorf("orphan verdict must list multiple reasons: %v", res.Reasons)
		}
	})
}

func TestBlindSpotOnApplicableChannelForcesUnknown(t *testing.T) {
	in := baseInput("nginx_route")
	in.Evidence = []Evidence{ev(1, "nginx", "neutral", "deterministic", nil)}
	in.Blinds = []Blind{{ID: 3, Channel: "nginx", Reason: "proxy_pass_variable",
		Detail: map[string]string{"variable": "$lab_backend"}}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateUnknown {
		t.Errorf("state = %s, want UNKNOWN despite full-looking coverage", res.State)
	}
	if len(res.Reasons) == 0 || !strings.Contains(strings.Join(res.Reasons, " "), "vùng mù") {
		t.Errorf("reasons must mention blindness: %v", res.Reasons)
	}

	// A blocker still wins over blindness.
	in.Observations = []Observation{{ID: 9, LastSeenAt: "2026-10-07T00:00:00Z", Count: 1}}
	res = Compute(in, defaultRules(t), now)
	if res.State != StateActive {
		t.Errorf("state = %s, want ACTIVE (blocker beats blindness)", res.State)
	}
}

func TestHostWideBlindSpotDoesNotBlock(t *testing.T) {
	in := baseInput("nginx_route")
	in.Evidence = []Evidence{
		ev(1, "nginx", "neutral", "deterministic", nil),
		ev(2, "nginx_access_log", "neutral", "deterministic", nil),
	}
	// channel "log" is not part of nginx_route's matrix → ignored.
	in.Blinds = []Blind{{ID: 4, Channel: "log", Reason: "log_retention_short"}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateOrphaned {
		t.Errorf("state = %s, want ORPHANED", res.State)
	}
}

// --- Output guarantees ---

func TestNoConfidenceOrPercentInVerdictText(t *testing.T) {
	inputs := []Input{}
	a := baseInput("container")
	a.Evidence = []Evidence{ev(1, "docker", "neutral", "deterministic", map[string]string{"state": "running"})}
	b := baseInput("nginx_route")
	b.Evidence = []Evidence{ev(1, "nginx", "neutral", "deterministic", nil)}
	c := baseInput("probe")
	r := defaultRules(t)
	r.Coverage.Channels = map[string][]string{"probe": {"x"}}
	inputs = append(inputs, a, b, c)
	for i, in := range inputs {
		rr := r
		if in.Kind == "container" || in.Kind == "nginx_route" {
			rr = defaultRules(t)
		}
		res := Compute(in, rr, now)
		text := strings.Join(res.Reasons, "\n") + "\n" + res.Action
		if strings.Contains(strings.ToLower(text), "confidence") {
			t.Errorf("input %d leaks the word confidence: %q", i, text)
		}
		if strings.Contains(text, "%") {
			t.Errorf("input %d leaks a percentage: %q", i, text)
		}
	}
}

func TestSignalsNeverBlockButAppear(t *testing.T) {
	in := baseInput("container")
	in.Attributes["state"] = "exited"
	in.Attributes["created_at"] = "2026-04-01T00:00:00Z"
	in.Evidence = []Evidence{
		ev(1, "docker", "neutral", "deterministic", map[string]string{"state": "exited"}),
		ev(2, "docker_created", "neutral", "deterministic",
			map[string]string{"last_deploy_at": "2026-04-01T00:00:00Z"}),
		ev(3, "mtime", "neutral", "deterministic", map[string]string{"age_days": "200"}),
	}
	res := Compute(in, defaultRules(t), now)
	if res.State == StateActive {
		t.Errorf("signals alone must not block, state = %s", res.State)
	}
	if len(res.Signals) < 3 {
		t.Errorf("signals = %d, want mtime+deploy+state", len(res.Signals))
	}
}

func TestUnitStateSignal(t *testing.T) {
	in := baseInput("systemd_unit")
	in.Attributes["active_state"] = "inactive"
	in.Evidence = []Evidence{
		ev(1, "systemd", "neutral", "deterministic",
			map[string]string{"active_state": "inactive", "file_state": "enabled"}),
	}
	res := Compute(in, defaultRules(t), now)
	if len(res.Signals) == 0 || res.Signals[0].Code != "S3" {
		t.Errorf("signals = %+v, want S3 inactive-unit", res.Signals)
	}
	// journald is N/A for an inactive unit and listener_mapping has no
	// listen edge → applicable = [systemd] only → 1/1 HIGH, window ok,
	// no blockers → ORPHANED.
	if res.State != StateOrphaned {
		t.Errorf("state = %s, want ORPHANED", res.State)
	}
}

// --- B6 path: a subject that owns a live listener through an
// intermediate process (unit → manages → process ← listens_on ← listener).

func TestB6PathUnitOwningLiveListener(t *testing.T) {
	in := baseInput("systemd_unit")
	in.Attributes["active_state"] = "active"
	in.Evidence = []Evidence{
		ev(1, "systemd", "in_use", "deterministic", map[string]string{"active_state": "active"}),
		ev(2, "journald", "in_use", "deterministic", nil),
	}
	in.Paths = []Path{{
		NodeIDs:    []int64{1, 2, 3},
		NodeKinds:  []string{"systemd_unit", "process", "listener"},
		NodeNames:  []string{"lab-app.service", "socat", "0.0.0.0:9099"},
		EdgeKinds:  []string{"manages", "listens_on"},
		Strengths:  []string{"deterministic", "deterministic"},
		Reversed:   []bool{false, true},
		EvidenceID: 33,
		RawRef:     "unit:lab-app.service:9099",
		FarInUse:   []string{"procfs_net"},
	}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateActive || !hasCode(res.Blockers, "B6") {
		t.Errorf("state=%s blockers=%s, want ACTIVE/B6", res.State, codes(res.Blockers))
	}
	if !strings.Contains(res.Blockers[0].Text, "0.0.0.0:9099") {
		t.Errorf("blocker must name the listener: %q", res.Blockers[0].Text)
	}
}

func TestB6PathRequiresLiveSocketAndReversedHop(t *testing.T) {
	base := Path{
		NodeIDs:    []int64{1, 2, 3},
		NodeKinds:  []string{"systemd_unit", "process", "listener"},
		NodeNames:  []string{"u.service", "p", "0.0.0.0:1"},
		EdgeKinds:  []string{"manages", "listens_on"},
		Strengths:  []string{"deterministic", "deterministic"},
		Reversed:   []bool{false, true},
		EvidenceID: 7,
		RawRef:     "unit:u:1",
		FarInUse:   []string{"procfs_net"},
	}
	cases := []struct {
		name string
		mut  func(p *Path)
		want bool
	}{
		{"healthy", func(p *Path) {}, true},
		{"dead listener", func(p *Path) { p.FarInUse = nil }, false},
		{"forward last hop", func(p *Path) { p.Reversed[1] = false }, false},
		{"weak hop", func(p *Path) { p.Strengths[1] = "weak_heuristic" }, false},
		{"foreign edge kind", func(p *Path) { p.EdgeKinds[1] = "depends_on" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.Reversed = append([]bool{}, base.Reversed...)
			p.Strengths = append([]string{}, base.Strengths...)
			p.EdgeKinds = append([]string{}, base.EdgeKinds...)
			tc.mut(&p)
			in := baseInput("systemd_unit")
			in.Evidence = []Evidence{ev(1, "systemd", "in_use", "deterministic",
				map[string]string{"active_state": "active"})}
			in.Paths = []Path{p}
			res := Compute(in, defaultRules(t), now)
			if got := hasCode(res.Blockers, "B6"); got != tc.want {
				t.Errorf("B6=%v want=%v (state %s)", got, tc.want, res.State)
			}
		})
	}
}

// A container managing its own child process must NOT block it — an
// unused running container stays orphan-eligible (lab-worker case).
func TestContainerOwnChildDoesNotBlock(t *testing.T) {
	in := baseInput("container")
	in.Attributes["state"] = "running"
	in.Attributes["created_at"] = "2026-10-01T00:00:00Z"
	in.Evidence = []Evidence{
		ev(1, "docker", "in_use", "deterministic", map[string]string{"state": "running"}),
		ev(2, "docker_created", "neutral", "deterministic",
			map[string]string{"created_at": "2026-10-01T00:00:00Z"}),
	}
	in.Edges = []EdgeFact{{
		Kind: "manages", Strength: "deterministic", Dir: "out",
		EvidenceID: 5, RawRef: "docker:exec:worker",
		Neighbor: Neighbor{Kind: "process", Name: "sleep",
			InUseChannels: []string{"procfs"}},
	}}
	in.Paths = []Path{{
		NodeIDs:    []int64{1, 2},
		NodeKinds:  []string{"container", "process"},
		NodeNames:  []string{"lab-worker", "sleep"},
		EdgeKinds:  []string{"manages"},
		Strengths:  []string{"deterministic"},
		Reversed:   []bool{false},
		EvidenceID: 5,
		RawRef:     "docker:exec:worker",
	}}
	res := Compute(in, defaultRules(t), now)
	if res.State != StateOrphaned {
		t.Errorf("state = %s, want ORPHANED (own child is not external use)", res.State)
	}
}

// Parallel graph paths to the same finding collapse to one line.
func TestBlockersDedup(t *testing.T) {
	mk := func(id int64) Path {
		return Path{
			NodeIDs:    []int64{1, 2, 3},
			NodeKinds:  []string{"container", "listener", "nginx_route"},
			NodeNames:  []string{"lab-web", "0.0.0.0:8081", "/web/"},
			EdgeKinds:  []string{"listens_on", "proxies_to"},
			Strengths:  []string{"deterministic", "deterministic"},
			Reversed:   []bool{true, true},
			EvidenceID: id,
			RawRef:     "nginx:lab.conf:16",
		}
	}
	in := baseInput("container")
	in.Evidence = []Evidence{ev(1, "docker", "in_use", "deterministic", nil)}
	in.Paths = []Path{mk(42), mk(42), mk(42)}
	res := Compute(in, defaultRules(t), now)
	if n := len(res.Blockers); n != 1 {
		t.Errorf("blockers = %d, want 1 after dedup: %s", n, codes(res.Blockers))
	}
}
