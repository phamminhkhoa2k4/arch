package verdict

import (
	"fmt"
	"time"

	"archaeologist/internal/rules"
)

// blockers returns every hard blocker (B1–B6) on the entity. Order is
// deterministic: B1 nginx, B2 inbound, B3 unit deps, B4 compose deps,
// B5 cron/timer refs, B6 active subjects; within a kind, discovery
// order (paths in chain order, edges by id).
func blockers(in Input, r rules.Rules) []Item {
	var out []Item
	out = append(out, blockerB1(in)...)
	out = append(out, blockerB2(in, r)...)
	out = append(out, blockerB3(in)...)
	out = append(out, blockerB4(in)...)
	out = append(out, blockerB5(in)...)
	out = append(out, blockerB6(in)...)
	out = append(out, blockerB6Paths(in)...)
	return dedupItems(out)
}

// dedupItems drops repeated code+text pairs (parallel graph paths to
// the same finding) while preserving first-seen order.
func dedupItems(items []Item) []Item {
	seen := make(map[string]bool, len(items))
	out := make([]Item, 0, len(items))
	for _, it := range items {
		key := it.Code + "\x00" + it.Text
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
	}
	return out
}

// B1: an active nginx route/upstream references the entity through a
// proxies_to/listens_on chain (route → upstream → listener → owner).
// The final hop must be reversed — the walk ends at the stored *src*
// of the reference, so a route is never blocked by what it points to.
func blockerB1(in Input) []Item {
	var out []Item
	for _, p := range in.Paths {
		if len(p.EdgeKinds) == 0 || len(p.EdgeKinds) > 4 {
			continue
		}
		proxyChain := true
		for _, k := range p.EdgeKinds {
			if k != "proxies_to" && k != "listens_on" {
				proxyChain = false
				break
			}
		}
		if !proxyChain || pathHasWeak(p) || !p.Reversed[len(p.Reversed)-1] {
			continue
		}
		far := len(p.NodeKinds) - 1
		if p.NodeIDs[far] == in.EntityID {
			continue
		}
		if p.NodeKinds[far] != "nginx_route" && p.NodeKinds[far] != "nginx_upstream" {
			continue
		}
		out = append(out, Item{
			Code:       "B1",
			Text:       fmt.Sprintf("nginx route/upstream %q is proxying to this entity", p.NodeNames[far]),
			EvidenceID: p.EvidenceID,
			RawRef:     p.RawRef,
		})
	}
	return out
}

// B2: an inbound connection inside the observation window — an
// observation bucket on or after window start, or nginx access-log
// traffic inside the activity freshness band (window end minus
// no_activity_days: the log branch must not stay hot for the whole
// window when the log itself shows how stale it is).
func blockerB2(in Input, r rules.Rules) []Item {
	var out []Item
	start := in.Window.Start
	for _, o := range in.Observations {
		if !afterOrEqual(o.LastSeenAt, start) {
			continue
		}
		out = append(out, Item{
			Code:       "B2",
			Text:       fmt.Sprintf("inbound connection inside the observation window (%s, %d packets)", o.LastSeenAt, o.Count),
			EvidenceID: o.ID,
			RawRef:     "observations#" + fmt.Sprint(o.ID),
		})
	}
	cutoff := accesslogCutoff(in.Window, r.Thresholds.NoActivityDays)
	if cutoff == "" {
		return out // no usable window end: nothing to bound freshness against
	}
	for _, e := range in.Evidence {
		if e.Channel != "nginx_access_log" || e.Polarity != "in_use" ||
			e.Strength == "weak_heuristic" {
			continue
		}
		if !afterOrEqual(e.Value["last_request_at"], cutoff) {
			continue
		}
		out = append(out, Item{
			Code:       "B2",
			Text:       fmt.Sprintf("nginx traffic inside the observation window (last seen %s)", e.Value["last_request_at"]),
			EvidenceID: e.ID,
			RawRef:     e.RawRef,
		})
	}
	return out
}

// B3: an active systemd unit depends on the entity.
func blockerB3(in Input) []Item {
	var out []Item
	for _, e := range in.Edges {
		if e.Dir != "in" || e.Kind != "depends_on" || e.Neighbor.Kind != "systemd_unit" {
			continue
		}
		if e.Strength == "weak_heuristic" {
			continue
		}
		if e.Neighbor.Attributes["active_state"] != "active" {
			continue
		}
		out = append(out, Item{
			Code:       "B3",
			Text:       fmt.Sprintf("unit %q (active) depends_on this entity", e.Neighbor.Name),
			EvidenceID: e.EvidenceID,
			RawRef:     e.RawRef,
		})
	}
	return out
}

// B4: a running compose service depends on this one. Membership hops
// (belongs_to) must walk container→service; the dependency hops must
// all point back at the subject (someone depends on it), so a service
// is never blocked by the dependencies it declares itself.
func blockerB4(in Input) []Item {
	var out []Item
	for _, p := range in.Paths {
		if !b4Shape(p) {
			continue
		}
		far := len(p.NodeKinds) - 1
		out = append(out, Item{
			Code:       "B4",
			Text:       fmt.Sprintf("compose service %q (running) depends_on this entity", p.NodeNames[far]),
			EvidenceID: p.EvidenceID,
			RawRef:     p.RawRef,
		})
	}
	return out
}

func b4Shape(p Path) bool {
	if len(p.EdgeKinds) == 0 || len(p.EdgeKinds) > 4 {
		return false
	}
	sawDep, sawBelong := false, false
	for i, k := range p.EdgeKinds {
		switch k {
		case "belongs_to":
			if p.Reversed[i] {
				return false // must walk container → service
			}
			sawBelong = true
		case "depends_on":
			if !p.Reversed[i] {
				return false // the subject must be the depended-on side
			}
			sawDep = true
		default:
			return false
		}
	}
	if !sawDep || pathHasWeak(p) {
		return false
	}
	far := len(p.NodeKinds) - 1
	if p.NodeKinds[far] != "compose_service" {
		return false
	}
	// For a container subject the membership hop is required so the
	// walk leaves the container before the dependency is examined.
	if p.NodeKinds[0] == "container" && !sawBelong {
		return false
	}
	return true
}

// B5 covers both sides of a schedule: a valid cron/timer referencing
// the entity, and a valid scheduler whose own target still exists.
func blockerB5(in Input) []Item {
	var out []Item
	isScheduler := in.Kind == "cron_job" || in.Kind == "timer"
	for _, e := range in.Edges {
		if e.Strength == "weak_heuristic" {
			continue // weak heuristics are never blockers
		}
		switch {
		case e.Dir == "in" && e.Kind == "references" && e.Neighbor.Kind == "cron_job":
			out = append(out, Item{
				Code:       "B5",
				Text:       fmt.Sprintf("cron %q still references this entity", e.Neighbor.Name),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		case e.Dir == "out" && e.Kind == "scheduled_by" && e.Neighbor.Kind == "timer":
			out = append(out, Item{
				Code:       "B5",
				Text:       fmt.Sprintf("timer %q still references this entity", e.Neighbor.Name),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		case isScheduler && e.Kind == "references" && e.Dir == "out":
			out = append(out, Item{
				Code:       "B5",
				Text:       fmt.Sprintf("scheduler still references %q (%s)", e.Neighbor.Name, e.Neighbor.Kind),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		case isScheduler && e.Kind == "scheduled_by" && e.Dir == "in":
			out = append(out, Item{
				Code:       "B5",
				Text:       fmt.Sprintf("timer still schedules %q", e.Neighbor.Name),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		}
	}
	return out
}

// B6: the entity is the target of a currently-running subject — a
// live listener mapping onto it, an active unit executing it, or a
// running owner managing it.
func blockerB6(in Input) []Item {
	var out []Item
	for _, e := range in.Edges {
		if e.Strength == "weak_heuristic" {
			continue // weak heuristics are never blockers
		}
		switch {
		case e.Dir == "in" && e.Kind == "listens_on" && contains(e.Neighbor.InUseChannels, "procfs_net"):
			out = append(out, Item{
				Code:       "B6",
				Text:       fmt.Sprintf("listener %q is open (live socket) pointing at this entity", e.Neighbor.Name),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		case e.Dir == "out" && e.Kind == "listens_on" && neighborRunning(e.Neighbor):
			out = append(out, Item{
				Code:       "B6",
				Text:       fmt.Sprintf("owner %q (%s) is running and holds this listener", e.Neighbor.Name, e.Neighbor.Kind),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		case e.Dir == "in" && e.Kind == "runs_as" && e.Neighbor.Attributes["active_state"] == "active":
			out = append(out, Item{
				Code:       "B6",
				Text:       fmt.Sprintf("active unit %q is executing this entity", e.Neighbor.Name),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		case e.Dir == "in" && e.Kind == "manages" && neighborRunning(e.Neighbor):
			out = append(out, Item{
				Code:       "B6",
				Text:       fmt.Sprintf("owner %q (%s) is running and manages this entity", e.Neighbor.Name, e.Neighbor.Kind),
				EvidenceID: e.EvidenceID,
				RawRef:     e.RawRef,
			})
		}
	}
	return out
}

// blockerB6Paths covers subjects that own a live listening socket
// through an intermediate (a unit managing the process that holds the
// port): a short listens_on/manages walk ending at a listener with
// live socket evidence. The final hop must be reversed — the mapping
// originates at the listener. A container's own child processes never
// block it, so an unused running container stays orphan-eligible.
func blockerB6Paths(in Input) []Item {
	var out []Item
	for _, p := range in.Paths {
		if len(p.EdgeKinds) == 0 || len(p.EdgeKinds) > 3 || pathHasWeak(p) {
			continue
		}
		if !p.Reversed[len(p.Reversed)-1] {
			continue
		}
		ok := true
		for _, k := range p.EdgeKinds {
			if k != "listens_on" && k != "manages" {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		far := len(p.NodeKinds) - 1
		if p.NodeKinds[far] != "listener" || !contains(p.FarInUse, "procfs_net") {
			continue
		}
		text := fmt.Sprintf("listener %q is open (live socket) pointing at this entity", p.NodeNames[far])
		if len(p.EdgeKinds) > 1 {
			text = fmt.Sprintf("listener %q is open (live socket) — mapped through %q to this entity",
				p.NodeNames[far], p.NodeNames[far-1])
		}
		out = append(out, Item{
			Code:       "B6",
			Text:       text,
			EvidenceID: p.EvidenceID,
			RawRef:     p.RawRef,
		})
	}
	return out
}

// neighborRunning reports whether the neighbor is a live subject.
func neighborRunning(n Neighbor) bool {
	switch n.Kind {
	case "systemd_unit":
		return n.Attributes["active_state"] == "active"
	case "container":
		return n.Attributes["state"] == "running"
	case "process":
		return contains(n.InUseChannels, "procfs")
	default:
		return false
	}
}

// pathHasWeak reports whether any hop of the path is a weak
// heuristic (or strengths are missing, which fails closed); such
// paths never block.
func pathHasWeak(p Path) bool {
	if len(p.Strengths) != len(p.EdgeKinds) {
		return true
	}
	for _, st := range p.Strengths {
		if st == "weak_heuristic" {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// accesslogCutoff is the newest last_request_at that still counts as
// activity: no_activity_days before the window end. Empty when the
// window has no parsable end (freshness cannot be bounded).
func accesslogCutoff(w Window, noActivityDays int) string {
	if w.End == "" || noActivityDays < 0 {
		return ""
	}
	end, err := parseTime(w.End)
	if err != nil {
		return ""
	}
	return end.AddDate(0, 0, -noActivityDays).Format(time.RFC3339)
}

// afterOrEqual compares RFC3339 timestamps; an unparsable or empty
// bound counts as satisfied (fail towards "blocked", never towards a
// false orphan). Format may carry a timezone-less fallback.
func afterOrEqual(ts, bound string) bool {
	if bound == "" || ts == "" {
		return true
	}
	a, ea := parseTime(ts)
	b, eb := parseTime(bound)
	if ea != nil || eb != nil {
		return true
	}
	return !a.Before(b)
}

func parseTime(s string) (timeT, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return timeT{}, fmt.Errorf("unparsable time %q", s)
}

// timeT aliases time.Time to keep parseTime compact.
type timeT = time.Time
