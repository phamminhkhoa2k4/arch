package systemd

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
