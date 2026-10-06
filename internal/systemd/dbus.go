package systemd

import (
	"fmt"
	"sort"

	"github.com/godbus/dbus/v5"
)

// DBusBus reads units from the system manager over D-Bus — never via
// shelling out to systemctl.
type DBusBus struct{}

// NewDBusBus returns a bus that connects lazily on the first Units call,
// so a host without systemd surfaces as an error there (→ blind spot)
// instead of at scan wiring time.
func NewDBusBus() *DBusBus { return &DBusBus{} }

const (
	systemdDest    = "org.freedesktop.systemd1"
	systemdPath    = dbus.ObjectPath("/org/freedesktop/systemd1")
	managerIface   = "org.freedesktop.systemd1.Manager"
	unitPropsIface = "org.freedesktop.systemd1.Unit"
)

// ListUnits row layout, verified against a live manager:
// [0] name, [1] description, [2] load, [3] active, [4] sub,
// [5] following, [6] object path, [7] job id, [8] job type, [9] job path.
const (
	rowName = iota
	rowDescription
	rowLoad
	rowActive
	rowSub
)

func (b *DBusBus) Units() ([]UnitStatus, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect system bus: %w", err)
	}
	mgr := conn.Object(systemdDest, systemdPath)

	loaded, err := listUnits(mgr)
	if err != nil {
		return nil, err
	}
	files, err := listUnitFiles(mgr)
	if err != nil {
		return nil, err
	}

	byName := map[string]UnitStatus{}
	loadedNames := map[string]bool{}
	for _, st := range loaded {
		loadedNames[st.Name] = true
	}
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

	// Enrich loaded units with properties (timestamp, fragment, file
	// state). File-only units have no manager object to ask.
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]UnitStatus, 0, len(names))
	for _, n := range names {
		st := byName[n]
		if loadedNames[n] && (st.FragmentPath == "" || st.ActiveEnterTimestamp == 0) {
			if err := b.enrich(conn, &st); err != nil {
				// Best effort: state facts already came from
				// ListUnits; missing optional fields stay absent.
				_ = err
			}
		}
		out = append(out, st)
	}
	return out, nil
}

func listUnits(mgr dbus.BusObject) ([]UnitStatus, error) {
	call := mgr.Call(managerIface+".ListUnits", 0)
	if call.Err != nil {
		return nil, fmt.Errorf("ListUnits: %w", call.Err)
	}
	rows, ok := call.Body[0].([][]interface{})
	if !ok {
		return nil, fmt.Errorf("ListUnits: unexpected reply type %T", call.Body[0])
	}
	out := make([]UnitStatus, 0, len(rows))
	for _, r := range rows {
		if len(r) <= rowSub {
			continue
		}
		name, _ := r[rowName].(string)
		if name == "" {
			continue
		}
		st := UnitStatus{Name: name}
		st.Description, _ = r[rowDescription].(string)
		st.LoadState, _ = r[rowLoad].(string)
		st.ActiveState, _ = r[rowActive].(string)
		st.SubState, _ = r[rowSub].(string)
		out = append(out, st)
	}
	return out, nil
}

func listUnitFiles(mgr dbus.BusObject) (map[string]UnitStatus, error) {
	call := mgr.Call(managerIface+".ListUnitFiles", 0)
	if call.Err != nil {
		return nil, fmt.Errorf("ListUnitFiles: %w", call.Err)
	}
	rows, ok := call.Body[0].([][]interface{})
	if !ok {
		return nil, fmt.Errorf("ListUnitFiles: unexpected reply type %T", call.Body[0])
	}
	out := map[string]UnitStatus{}
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		p, ok := r[0].(string)
		if !ok {
			continue
		}
		state, _ := r[1].(string)
		name := unitNameFromPath(p)
		if name == "" {
			continue
		}
		out[name] = UnitStatus{
			Name:          name,
			FragmentPath:  p,
			UnitFileState: state,
		}
	}
	return out, nil
}

// enrich reads org.freedesktop.systemd1.Unit properties for one unit.
// Only loaded units have a manager object; file-only units are skipped
// by the caller.
func (b *DBusBus) enrich(conn *dbus.Conn, st *UnitStatus) error {
	if st.Name == "" {
		return nil
	}
	if st.FragmentPath != "" && st.ActiveEnterTimestamp != 0 {
		return nil
	}
	obj := conn.Object(systemdDest, unitPath(st.Name))
	call := obj.Call("org.freedesktop.DBus.Properties.GetAll", 0, unitPropsIface)
	if call.Err != nil {
		return call.Err
	}
	props, ok := call.Body[0].(map[string]dbus.Variant)
	if !ok {
		return fmt.Errorf("GetAll: unexpected type %T", call.Body[0])
	}
	if v, ex := props["FragmentPath"]; ex {
		if s, ok := v.Value().(string); ok {
			st.FragmentPath = s
		}
	}
	if v, ex := props["UnitFileState"]; ex {
		if s, ok := v.Value().(string); ok && st.UnitFileState == "" {
			st.UnitFileState = s
		}
	}
	if v, ex := props["ActiveEnterTimestamp"]; ex {
		if n, ok := v.Value().(uint64); ok {
			st.ActiveEnterTimestamp = n
		}
	}
	return nil
}

// unitPath escapes a unit name into its object path
// (systemd rule: alnum kept, everything else `_` + lowercase hex).
func unitPath(name string) dbus.ObjectPath {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(name)*2+40)
	out = append(out, "/org/freedesktop/systemd1/unit/"...)
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if alnum {
			out = append(out, c)
		} else {
			out = append(out, '_', hex[c>>4], hex[c&0xf])
		}
	}
	return dbus.ObjectPath(out)
}

// unitNameFromPath extracts the unit name from a fragment path
// ("/lib/systemd/system/nginx.service" → "nginx.service").
func unitNameFromPath(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
