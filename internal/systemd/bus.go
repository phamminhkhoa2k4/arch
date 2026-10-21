package systemd

import "sort"

// UnitStatus is the merged view of one systemd unit from list-units
// (runtime state) and list-unit-files (file state).
type UnitStatus struct {
	Name                 string
	Description          string
	LoadState            string
	ActiveState          string
	SubState             string
	UnitFileState        string // enabled/disabled/static/transient/masked, "" unknown
	FragmentPath         string
	ActiveEnterTimestamp uint64 // µs since epoch, 0 when unknown/not active
	Loaded               bool   // present in list-units (runtime state known)
}

// Bus lists units. Implementations: the real D-Bus bus and fakes in
// tests. A non-nil error means systemd itself is unreachable — the
// collector turns it into a blind spot.
type Bus interface {
	Units() ([]UnitStatus, error)
}

// SplitBus optionally exposes the two listings separately. Journal
// reads only need loaded units, so callers can overlap them with the
// slower ListUnitFiles call and still merge to the same view.
type SplitBus interface {
	LoadedUnits() ([]UnitStatus, error)
	UnitFiles() (map[string]UnitStatus, error)
}

// MergeUnits combines runtime state with unit-file state, sorted by
// name. Loaded rows win; file rows fill FragmentPath and UnitFileState
// so a unit that is loaded but not installed this boot keeps both.
func MergeUnits(loaded []UnitStatus, files map[string]UnitStatus) []UnitStatus {
	byName := map[string]UnitStatus{}
	for name, st := range files {
		byName[name] = st
	}
	for _, st := range loaded {
		prev := byName[st.Name]
		st.UnitFileState = firstNonEmpty(st.UnitFileState, prev.UnitFileState)
		if prev.FragmentPath != "" && st.FragmentPath == "" {
			st.FragmentPath = prev.FragmentPath
		}
		st.Loaded = true
		byName[st.Name] = st
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]UnitStatus, 0, len(names))
	for _, n := range names {
		out = append(out, byName[n])
	}
	return out
}
