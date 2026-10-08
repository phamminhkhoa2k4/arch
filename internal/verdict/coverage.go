package verdict

import "archaeologist/internal/rules"

// coverage computes Evidence Coverage (D2): which configured channels
// apply to this entity, which were checked, which are missing, and
// whether an applicable-channel blind spot forbids orphan verdicts.
//
// checked = an evidence row OR a blind spot for that channel exists,
// plus documented preconditions where absence itself proves the
// channel ran (a running container with an empty docker log, a
// resolved listener mapping).
func coverage(in Input, r rules.Rules) (applicable, checked, missing []string, blindBlocked bool) {
	chans, ok := r.Coverage.Channels[in.Kind]
	if !ok {
		return nil, nil, nil, false
	}
	for _, ch := range chans {
		if notApplicable(in, ch) {
			continue
		}
		applicable = append(applicable, ch)
		switch {
		case hasBlind(in, ch):
			checked = append(checked, ch)
			blindBlocked = true // applicable-channel blindness forbids orphan verdicts
		case hasEvidence(in, ch):
			checked = append(checked, ch)
		case preconditionChecked(in, ch):
			checked = append(checked, ch)
		default:
			missing = append(missing, ch)
		}
	}
	return applicable, checked, missing, blindBlocked
}

// notApplicable implements the per-channel preconditions: a channel
// that cannot produce a fact about this entity is neither checked nor
// missing.
func notApplicable(in Input, ch string) bool {
	switch ch {
	case "journald":
		// Journal lines only exist for units that are (or were) active.
		return in.Kind == "systemd_unit" && in.Attributes["active_state"] != "active"
	case "docker_log":
		// Only a running container can emit log lines.
		return in.Kind == "container" && in.Attributes["state"] != "running"
	case "docker_created":
		return in.Attributes["created_at"] == "" && in.Attributes["last_deploy_at"] == ""
	case "listener_mapping":
		// Mapping matters only where there is something to map.
		return !hasListenEdge(in) && in.Kind != "listener"
	}
	return false
}

// preconditionChecked covers "the collector ran and the result was
// empty": an empty log for a running container and a resolved listener
// mapping (proved by procfs_net evidence on a listener) are both
// successful checks, not gaps.
func preconditionChecked(in Input, ch string) bool {
	switch ch {
	case "docker_log":
		return in.Kind == "container" && in.Attributes["state"] == "running"
	case "listener_mapping":
		// The correlated listens_on edge IS the resolved mapping for
		// a subject that owns a port; listeners additionally prove it
		// with live socket evidence.
		return hasListenEdge(in) || (in.Kind == "listener" && hasEvidence(in, "procfs_net"))
	}
	return false
}

func hasEvidence(in Input, ch string) bool {
	for _, e := range in.Evidence {
		if e.Channel == ch {
			return true
		}
	}
	return false
}

func hasBlind(in Input, ch string) bool {
	for _, b := range in.Blinds {
		if b.Channel == ch {
			return true
		}
	}
	return false
}

func hasListenEdge(in Input) bool {
	for _, e := range in.Edges {
		if e.Kind == "listens_on" {
			return true
		}
	}
	return false
}
