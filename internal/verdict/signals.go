package verdict

import (
	"fmt"
	"strconv"
	"time"

	"archaeologist/internal/rules"
)

// signals derives the "⚠ non-delete signals" list from neutral
// evidence and attributes. Signals never override a blocker (INV-2);
// they only push an unblocked entity toward orphan states.
func signals(in Input, r rules.Rules, now time.Time) []Item {
	var out []Item
	seen := map[string]bool{}
	add := func(code string, item Item) {
		if seen[code] {
			return
		}
		seen[code] = true
		out = append(out, item)
	}

	for _, e := range in.Evidence {
		switch e.Channel {
		case "mtime":
			age, err := strconv.Atoi(e.Value["age_days"])
			if err == nil && age > r.Thresholds.NoActivityDays {
				add("S_mtime", Item{
					Code:       "S1",
					Text:       fmt.Sprintf("file unchanged for %d days (no_activity_days=%d)", age, r.Thresholds.NoActivityDays),
					EvidenceID: e.ID,
					RawRef:     e.RawRef,
				})
			}
		case "docker_created":
			ts := e.Value["last_deploy_at"]
			if ts == "" {
				ts = e.Value["created_at"]
			}
			if days, ok := daysSince(ts, now); ok && days > r.Thresholds.NoDeployDays {
				add("S_deploy", Item{
					Code:       "S2",
					Text:       fmt.Sprintf("no new deploy for %d days (no_deploy_days=%d)", days, r.Thresholds.NoDeployDays),
					EvidenceID: e.ID,
					RawRef:     e.RawRef,
				})
			}
		case "systemd":
			if st := e.Value["active_state"]; st != "" && st != "active" {
				add("S_unit_state", Item{
					Code:       "S3",
					Text:       fmt.Sprintf("unit is not active (active_state=%s)", st),
					EvidenceID: e.ID,
					RawRef:     e.RawRef,
				})
			}
		case "docker":
			if st := e.Value["state"]; st != "" && st != "running" {
				add("S_container_state", Item{
					Code:       "S4",
					Text:       fmt.Sprintf("container is not running (state=%s)", st),
					EvidenceID: e.ID,
					RawRef:     e.RawRef,
				})
			}
		}
	}
	return out
}

// daysSince converts an RFC3339 timestamp to whole days before now.
func daysSince(ts string, now time.Time) (int, bool) {
	if ts == "" {
		return 0, false
	}
	t, err := parseTime(ts)
	if err != nil {
		return 0, false
	}
	d := int(now.Sub(t).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return d, true
}
